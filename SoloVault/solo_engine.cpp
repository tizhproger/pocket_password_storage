#include "solo_engine.h"
#include <cstdio>
#include <cstring>
#include <new>
namespace solo {
Engine::Engine(SnapshotStore &s, Random r)
    : store_(s), random_(r), document_(new(std::nothrow) Document) {}
Engine::~Engine() { lock(); }
void Engine::clearPending() {
  erase(pending_.restoreKey.data(), 32);
  erase(&pending_.record, sizeof(pending_.record));
  erase(pending_.revision.data(), 32);
  if (pending_.restored)
    erase(pending_.restored.get(), sizeof(Document));
  pending_.restored.reset();
  pending_.blob.clear();
  pending_.active = pending_.verified = false;
  pending_.until = 0;
}
void Engine::lock() {
  clearPending();
  window_.close();
  unlocked_ = false;
  activity_ = opened_ = 0;
  erase(root_.data(), 32);
  erase(&identity_, sizeof(identity_));
  if (document_)
    erase(document_.get(), sizeof(Document));
}
bool Engine::initialize(const Key &key, const Identity &identity,
                        uint64_t now) {
  if (!document_ || store_.state() != DiskState::Empty)
    return false;
  erase(document_.get(), sizeof(Document));
  if (store_.save(*document_, identity, key, random_) != Result::Ok)
    return false;
  root_ = key;
  identity_ = identity;
  unlocked_ = true;
  activity_ = opened_ = now;
  return true;
}
bool Engine::unlock(const Key &key, uint64_t now) {
  lock();
  if (!document_)
    return false;
  Bytes blob;
  if (store_.read(blob) != Result::Ok ||
      !decryptSnapshot(blob, key, *document_))
    return false;
  root_ = key;
  identity_ = store_.active().identity;
  unlocked_ = true;
  activity_ = opened_ = now;
  return true;
}
bool Engine::openWindow(Access a, uint64_t now) {
  if (pending())
    return false;
  if (a == Access::Manage &&
      (!unlocked_ || store_.state() != DiskState::Sealed))
    return false;
  if (a == Access::Restore && store_.state() != DiskState::Empty)
    return false;
  if (a == Access::Backup && store_.state() != DiskState::Sealed &&
      store_.state() != DiskState::Recovery)
    return false;
  window_.open(a, now);
  return true;
}
int Engine::index(const Id &id) const {
  if (!unlocked_ || !document_)
    return -1;
  for (size_t i = 0; i < document_->count; i++)
    if (document_->items[i].id == id)
      return int(i);
  return -1;
}
Reply Engine::baseReply(const Request &r, Result result) const {
  Reply out;
  out.op = r.op;
  out.id = r.id;
  out.result = result;
  return out;
}
Result Engine::stagePut(const Request &request) {
  if (request.size < 50)
    return Result::Invalid;
  const uint8_t *p = request.data;
  size_t at = 42;
  memcpy(pending_.revision.data(), p, 32);
  memcpy(pending_.record.id.data(), p + 32, 8);
  pending_.policy = p[40];
  pending_.generatedLength = p[41];
  if (pending_.policy > 2 ||
      (pending_.policy == 1 ? (p[41] < 12 || p[41] > 64) : p[41] != 0))
    return Result::Invalid;
  char *fields[] = {pending_.record.title, pending_.record.user,
                    pending_.record.password, pending_.record.note};
  const size_t caps[] = {48, 64, 96, 160};
  for (unsigned j = 0; j < 4; j++) {
    if (at + 2 > request.size)
      return Result::Invalid;
    size_t n = get16(p + at);
    at += 2;
    if (n > caps[j] || at + n > request.size || memchr(p + at, 0, n))
      return Result::Invalid;
    memcpy(fields[j], p + at, n);
    fields[j][n] = 0;
    at += n;
  }
  auto &r = pending_.record;
  if (at != request.size || !validText(r.title, 48, true) ||
      !validText(r.user, 64) || !validText(r.note, 160, false, true) ||
      !validText(r.password, 96, pending_.policy == 0) ||
      ((pending_.policy != 0) && r.password[0]))
    return Result::Invalid;
  Id zero{};
  int old = index(r.id);
  if (r.id == zero) {
    if (pending_.policy == 2 || document_->count == MAX_RECORDS)
      return Result::Invalid;
  } else if (old < 0)
    return Result::Conflict;
  if (pending_.revision != store_.revision())
    return Result::Conflict;
  return Result::Pending;
}
Reply Engine::request(const Request &r, uint64_t now) {
  if (pending())
    return baseReply(r, Result::Busy);
  if (!window_.allows(r.op, unlocked_ && !expired(now), now))
    return baseReply(r, Result::Locked);
  if (r.op == Op::Status) {
    if (r.size)
      return baseReply(r, Result::Invalid);
    Reply out = baseReply(r, Result::Ok);
    out.data = {0,
                1,
                0,
                uint8_t(store_.state()),
                uint8_t(unlocked_ && !expired(now)),
                uint8_t(access(now)),
                uint8_t(store_.cleanupWarning)};
    return out;
  }
  if (r.op == Op::Backup) {
    if (r.size)
      return baseReply(r, Result::Invalid);
    Reply out = baseReply(r, Result::Ok);
    out.result = store_.read(out.data);
    if (access(now) == Access::Backup)
      window_.close();
    return out;
  }
  if (r.op == Op::List) {
    if (r.size)
      return baseReply(r, Result::Invalid);
    Reply out = baseReply(r, Result::Ok);
    out.data.assign(store_.revision().begin(), store_.revision().end());
    size_t at = out.data.size();
    out.data.resize(at + 2);
    put16(out.data.data() + at, document_->count);
    for (size_t i = 0; i < document_->count; i++) {
      const auto &record = document_->items[i];
      size_t n = strlen(record.title);
      out.data.insert(out.data.end(), record.id.begin(), record.id.end());
      out.data.push_back(n);
      out.data.insert(out.data.end(), record.title, record.title + n);
    }
    return out;
  }
  if (store_.state() != DiskState::Sealed &&
      !(r.op == Op::Restore && store_.state() == DiskState::Empty))
    return baseReply(r, Result::Corrupt);
  clearPending();
  Result result = Result::Invalid;
  if (r.op == Op::Put)
    result = stagePut(r);
  else if (r.op == Op::Delete && r.size == 40) {
    memcpy(pending_.revision.data(), r.data, 32);
    memcpy(pending_.record.id.data(), r.data + 32, 8);
    int old = index(pending_.record.id);
    if (pending_.revision != store_.revision() || old < 0)
      result = Result::Conflict;
    else {
      memcpy(pending_.record.title, document_->items[old].title,
             sizeof(pending_.record.title));
      result = Result::Pending;
    }
  } else if (r.op == Op::Restore && r.size <= BLOB_MAX) {
    pending_.blob.assign(r.data, r.data + r.size);
    if (inspectSnapshot(pending_.blob, pending_.snapshot)) {
      if (unlocked_) {
        if (identity_.id == pending_.snapshot.identity.id &&
            identity_.salt == pending_.snapshot.identity.salt) {
          pending_.restored.reset(new (std::nothrow) Document);
          if (pending_.restored &&
              decryptSnapshot(pending_.blob, root_, *pending_.restored)) {
            pending_.restoreKey = root_;
            pending_.verified = true;
            result = Result::Pending;
          }
        }
      } else if (store_.state() == DiskState::Empty)
        result = Result::NeedKey;
      pending_.revision = store_.revision();
    }
  }
  if (result != Result::Pending && result != Result::NeedKey) {
    clearPending();
    return baseReply(r, result);
  }
  pending_.op = r.op;
  pending_.requestId = r.id;
  pending_.until = now + (result == Result::NeedKey ? 300000 : 60000);
  pending_.active = true;
  return baseReply(r, result);
}
bool Engine::verifyRestore(const Key &key) {
  if (!pending() || pending_.op != Op::Restore || pending_.verified ||
      store_.state() != DiskState::Empty)
    return false;
  pending_.restored.reset(new (std::nothrow) Document);
  if (!pending_.restored ||
      !decryptSnapshot(pending_.blob, key, *pending_.restored)) {
    if (pending_.restored)
      erase(pending_.restored.get(), sizeof(Document));
    pending_.restored.reset();
    return false;
  }
  pending_.restoreKey = key;
  pending_.verified = true;
  return true;
}
Result Engine::commitDocument(const Document &candidate) {
  if (!unlocked_ || !document_)
    return Result::Locked;
  Result r = store_.save(candidate, identity_, root_, random_);
  if (r == Result::Ok)
    *document_ = candidate;
  return r;
}
Reply Engine::approve(bool accepted, uint64_t now) {
  Request r{pending_.op, pending_.requestId, nullptr, 0};
  Reply reply = baseReply(r, Result::Denied);
  if (!pending())
    return reply;
  if (pendingExpired(now)) {
    reply.result = Result::Expired;
    clearPending();
    return reply;
  }
  if (!accepted) {
    clearPending();
    return reply;
  }
  localActivity(now);
  if (pending_.revision != store_.revision()) {
    reply.result = Result::Conflict;
    clearPending();
    return reply;
  }
  if (pending_.op == Op::Restore) {
    if (!pending_.verified || !pending_.restored)
      reply.result = Result::Locked;
    else {
      reply.result = store_.save(*pending_.restored, pending_.snapshot.identity,
                                 pending_.restoreKey, random_);
      if (reply.result == Result::Ok) {
        if (!document_)
          reply.result = Result::Storage;
        else {
          *document_ = *pending_.restored;
          root_ = pending_.restoreKey;
          identity_ = pending_.snapshot.identity;
          unlocked_ = true;
          activity_ = opened_ = now;
        }
      }
    }
  } else {
    std::unique_ptr<Document> candidate(new (std::nothrow) Document);
    if (!candidate) {
      reply.result = Result::Storage;
      clearPending();
      return reply;
    }
    *candidate = *document_;
    int old = index(pending_.record.id);
    if (pending_.op == Op::Delete) {
      if (old < 0)
        reply.result = Result::Conflict;
      else {
        for (size_t i = old; i + 1 < candidate->count; i++)
          candidate->items[i] = candidate->items[i + 1];
        erase(&candidate->items[--candidate->count], sizeof(Record));
        reply.result = commitDocument(*candidate);
      }
    } else if (pending_.op == Op::Put) {
      Record &value = pending_.record;
      Id zero{};
      bool good = true;
      if (value.id == zero) {
        for (unsigned attempt = 0; attempt < 16; attempt++) {
          good = random_(value.id.data(), 8);
          if (!good || (value.id != zero && index(value.id) < 0))
            break;
        }
        if (value.id == zero || index(value.id) >= 0)
          good = false;
        old = candidate->count;
      }
      if (pending_.policy == 1)
        good = good && randomPassword(random_, value.password,
                                      pending_.generatedLength);
      else if (pending_.policy == 2) {
        if (old < 0 || size_t(old) >= document_->count)
          good = false;
        else
          memcpy(value.password, document_->items[old].password,
                 sizeof(value.password));
      }
      if (good && old >= 0 && size_t(old) <= candidate->count &&
          size_t(old) < MAX_RECORDS) {
        candidate->items[old] = value;
        if (size_t(old) == candidate->count)
          ++candidate->count;
        reply.result = commitDocument(*candidate);
        if (reply.result == Result::Ok)
          reply.data.assign(value.id.begin(), value.id.end());
      } else
        reply.result = Result::Invalid;
    }
    erase(candidate.get(), sizeof(Document));
  }
  if (reply.result == Result::Ok)
    reply.data.insert(reply.data.end(), store_.revision().begin(),
                      store_.revision().end());
  clearPending();
  return reply;
}
Result Engine::localGenerate(uint64_t now) {
  if (!unlocked_ || pending() || document_->count >= MAX_RECORDS)
    return Result::Locked;
  std::unique_ptr<Document> next(new (std::nothrow) Document);
  if (!next)
    return Result::Storage;
  *next = *document_;
  auto &r = next->items[next->count];
  r = {};
  Id zero{};
  bool good = false;
  for (unsigned n = 0; n < 16; n++)
    if (random_(r.id.data(), 8) && r.id != zero && index(r.id) < 0) {
      good = true;
      break;
    }
  snprintf(r.title, sizeof(r.title), "Password %u", unsigned(next->count) + 1);
  if (!good || !randomPassword(random_, r.password, 20)) {
    erase(next.get(), sizeof(Document));
    return Result::Invalid;
  }
  ++next->count;
  localActivity(now);
  Result result = commitDocument(*next);
  erase(next.get(), sizeof(Document));
  return result;
}
Result Engine::localDelete(const Id &id, uint64_t now) {
  if (!unlocked_ || pending())
    return Result::Locked;
  int at = index(id);
  if (at < 0)
    return Result::Invalid;
  std::unique_ptr<Document> next(new (std::nothrow) Document);
  if (!next)
    return Result::Storage;
  *next = *document_;
  for (size_t i = at; i + 1 < next->count; i++)
    next->items[i] = next->items[i + 1];
  erase(&next->items[--next->count], sizeof(Record));
  localActivity(now);
  Result r = commitDocument(*next);
  erase(next.get(), sizeof(Document));
  return r;
}
Result Engine::repair(uint64_t now) {
  if (!unlocked_ || store_.state() != DiskState::Recovery)
    return Result::Invalid;
  localActivity(now);
  return store_.save(*document_, identity_, root_, random_, true);
}
Result Engine::rotate(const Key &root, const Identity &identity, uint64_t now) {
  if (!unlocked_ || pending() || store_.state() != DiskState::Sealed)
    return Result::Locked;
  localActivity(now);
  Result r = store_.save(*document_, identity, root, random_);
  if (r == Result::Ok) {
    store_.discardOlder();
    lock();
  }
  return r;
}
} // namespace solo
