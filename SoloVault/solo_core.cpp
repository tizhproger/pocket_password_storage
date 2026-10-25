#include "solo_core.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <limits>
#include <mbedtls/gcm.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/sha256.h>
#include <new>
namespace solo {
void erase(void *p, size_t n) {
  if (p && n)
    mbedtls_platform_zeroize(p, n);
}
bool constantEqual(const void *a, const void *b, size_t n) {
  const auto *x = static_cast<const uint8_t *>(a);
  const auto *y = static_cast<const uint8_t *>(b);
  uint8_t d = 0;
  for (size_t i = 0; i < n; i++)
    d |= x[i] ^ y[i];
  return d == 0;
}
bool sha256(const void *p, size_t n, uint8_t out[32]) {
  return mbedtls_sha256_ret(static_cast<const uint8_t *>(p), n, out, 0) == 0;
}
uint16_t get16(const uint8_t *p) {
  return uint16_t(p[0]) | (uint16_t(p[1]) << 8);
}
uint32_t get32(const uint8_t *p) {
  return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) |
         (uint32_t(p[3]) << 24);
}
void put16(uint8_t *p, uint16_t v) {
  p[0] = v;
  p[1] = v >> 8;
}
void put32(uint8_t *p, uint32_t v) {
  for (unsigned i = 0; i < 4; i++)
    p[i] = v >> (8 * i);
}
std::string hex(const void *p, size_t n) {
  const char *digits = "0123456789abcdef";
  const auto *b = static_cast<const uint8_t *>(p);
  std::string s(n * 2, '0');
  for (size_t i = 0; i < n; i++) {
    s[2 * i] = digits[b[i] >> 4];
    s[2 * i + 1] = digits[b[i] & 15];
  }
  return s;
}
bool unhex(const std::string &s, void *dst, size_t n) {
  if (s.size() != n * 2)
    return false;
  auto *out = static_cast<uint8_t *>(dst);
  for (size_t i = 0; i < n; i++) {
    int v = 0;
    for (int j = 0; j < 2; j++) {
      char c = s[2 * i + j];
      int d = c >= '0' && c <= '9'   ? c - '0'
              : c >= 'a' && c <= 'f' ? c - 'a' + 10
                                     : -1;
      if (d < 0)
        return false;
      v = (v << 4) | d;
    }
    out[i] = v;
  }
  return true;
}
SensitiveBuffer::SensitiveBuffer(size_t n)
    : data_(new(std::nothrow) uint8_t[n]()), size_(n) {}
SensitiveBuffer::~SensitiveBuffer() { erase(data_.get(), size_); }
bool validText(const char *s, size_t maximum, bool required, bool multiline) {
  size_t n = 0;
  while (n <= maximum && s[n])
    n++;
  if (n > maximum || (required && !n))
    return false;
  for (size_t i = 0; i < n;) {
    uint8_t c = uint8_t(s[i++]);
    uint32_t cp = 0, min = 0;
    unsigned need = 0;
    if (c < 128) {
      if (c < 32 && !(multiline && c == 10))
        return false;
      if (c == 127)
        return false;
      continue;
    }
    if (c >= 0xc2 && c <= 0xdf) {
      cp = c & 31;
      need = 1;
      min = 128;
    } else if (c >= 0xe0 && c <= 0xef) {
      cp = c & 15;
      need = 2;
      min = 2048;
    } else if (c >= 0xf0 && c <= 0xf4) {
      cp = c & 7;
      need = 3;
      min = 65536;
    } else
      return false;
    if (i + need > n)
      return false;
    while (need--) {
      uint8_t b = uint8_t(s[i++]);
      if ((b & 0xc0) != 0x80)
        return false;
      cp = (cp << 6) | (b & 63);
    }
    if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff) ||
        (cp >= 0x80 && cp <= 0x9f))
      return false;
  }
  return true;
}
Derivation::Derivation() { mbedtls_md_init(&ctx_); }
Derivation::~Derivation() { cancel(); }
void Derivation::cancel() {
  mbedtls_md_free(&ctx_);
  mbedtls_md_init(&ctx_);
  erase(u_.data(), 32);
  erase(sum_.data(), 32);
  rounds_ = done_ = 0;
  error_ = false;
}
bool Derivation::start(const char *password, size_t length, const uint8_t *salt,
                       size_t saltLength, uint32_t rounds) {
  cancel();
  if (!password || !length || length > 128 || !salt || saltLength > 64 ||
      !rounds || rounds > 1000000) {
    error_ = true;
    return false;
  }
  const uint8_t index[4] = {0, 0, 0, 1};
  int rc =
      mbedtls_md_setup(&ctx_, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  if (!rc)
    rc = mbedtls_md_hmac_starts(
        &ctx_, reinterpret_cast<const uint8_t *>(password), length);
  if (!rc)
    rc = mbedtls_md_hmac_update(&ctx_, salt, saltLength);
  if (!rc)
    rc = mbedtls_md_hmac_update(&ctx_, index, 4);
  if (!rc)
    rc = mbedtls_md_hmac_finish(&ctx_, u_.data());
  if (rc) {
    cancel();
    error_ = true;
    return false;
  }
  sum_ = u_;
  rounds_ = rounds;
  done_ = 1;
  return true;
}
void Derivation::advance(uint32_t budget) {
  while (rounds_ && done_ < rounds_ && budget-- && !error_) {
    int rc = mbedtls_md_hmac_reset(&ctx_);
    if (!rc)
      rc = mbedtls_md_hmac_update(&ctx_, u_.data(), 32);
    if (!rc)
      rc = mbedtls_md_hmac_finish(&ctx_, u_.data());
    if (rc) {
      cancel();
      error_ = true;
      return;
    }
    for (unsigned i = 0; i < 32; i++)
      sum_[i] ^= u_[i];
    ++done_;
  }
}
bool Derivation::take(Key &key) {
  if (!finished() || error_)
    return false;
  key = sum_;
  cancel();
  return true;
}
bool makeOwner(Random random, char out[OWNER_LEN + 1]) {
  std::array<uint8_t, OWNER_LEN> b{};
  if (!random(b.data(), b.size())) {
    erase(b.data(), b.size());
    erase(out, OWNER_LEN + 1);
    return false;
  }
  for (size_t i = 0; i < OWNER_LEN; i++)
    out[i] = ALPHABET[b[i] & 31];
  out[OWNER_LEN] = 0;
  erase(b.data(), b.size());
  return true;
}
bool validOwner(const char *s) {
  for (size_t i = 0; i < OWNER_LEN; i++)
    if (!s[i] || !strchr(ALPHABET, s[i]))
      return false;
  return s[OWNER_LEN] == 0;
}
bool makeIdentity(Random random, Identity &id) {
  return random(id.id.data(), 16) && random(id.salt.data(), 16);
}
bool validDocument(const Document &doc) {
  if (doc.count > MAX_RECORDS)
    return false;
  const Id zero{};
  for (size_t i = 0; i < doc.count; i++) {
    const auto &r = doc.items[i];
    if (r.id == zero || !validText(r.title, 48, true) ||
        !validText(r.user, 64) || !validText(r.password, 96, true) ||
        !validText(r.note, 160, false, true))
      return false;
    for (size_t j = 0; j < i; j++)
      if (doc.items[j].id == r.id)
        return false;
  }
  return true;
}
bool packDocument(const Document &doc, uint8_t *out, size_t cap, size_t &used) {
  used = 0;
  if (cap < 10 || !validDocument(doc))
    return false;
  memcpy(out, "SVDOC001", 8);
  put16(out + 8, doc.count);
  used = 10;
  for (size_t i = 0; i < doc.count; i++) {
    const auto &r = doc.items[i];
    if (used + 8 > cap)
      return false;
    memcpy(out + used, r.id.data(), 8);
    used += 8;
    for (const char *s : {r.title, r.user, r.password, r.note}) {
      size_t n = strlen(s);
      if (used + 2 + n > cap)
        return false;
      put16(out + used, n);
      used += 2;
      memcpy(out + used, s, n);
      used += n;
    }
  }
  return true;
}
bool unpackDocument(const uint8_t *b, size_t n, Document &doc) {
  erase(&doc, sizeof(doc));
  if (n < 10 || n > PLAIN_MAX || memcmp(b, "SVDOC001", 8))
    return false;
  doc.count = get16(b + 8);
  if (doc.count > MAX_RECORDS) {
    erase(&doc, sizeof(doc));
    return false;
  }
  size_t at = 10;
  bool ok = true;
  for (size_t i = 0; i < doc.count && ok; i++) {
    auto &r = doc.items[i];
    if (at + 8 > n) {
      ok = false;
      break;
    }
    memcpy(r.id.data(), b + at, 8);
    at += 8;
    char *fields[] = {r.title, r.user, r.password, r.note};
    const size_t caps[] = {48, 64, 96, 160};
    for (unsigned j = 0; j < 4; j++) {
      if (at + 2 > n) {
        ok = false;
        break;
      }
      size_t len = get16(b + at);
      at += 2;
      if (len > caps[j] || at + len > n || memchr(b + at, 0, len)) {
        ok = false;
        break;
      }
      memcpy(fields[j], b + at, len);
      fields[j][len] = 0;
      at += len;
    }
  }
  if (!ok || at != n || !validDocument(doc)) {
    erase(&doc, sizeof(doc));
    return false;
  }
  return true;
}
static bool payloadKey(const Key &root, const uint8_t salt[32], Key &out) {
  // RFC5869 Extract and one-block Expand. Core2.0.17 lacks linked mbedtls_hkdf.
  constexpr char info[] = "SoloVault snapshot key v1";
  Key prk{};
  uint8_t context[sizeof(info)];
  memcpy(context, info, sizeof(info) - 1);
  context[sizeof(info) - 1] = 1;
  const auto *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  int rc = mbedtls_md_hmac(md, salt, 32, root.data(), 32, prk.data());
  if (!rc)
    rc = mbedtls_md_hmac(md, prk.data(), 32, context, sizeof(context),
                         out.data());
  erase(prk.data(), 32);
  return rc == 0;
}
bool inspectSnapshot(const Bytes &b, Snapshot &s) {
  s = {};
  if (b.size() < HEADER_SIZE + 10 + TRAILER_SIZE || b.size() > BLOB_MAX ||
      memcmp(b.data(), "SOLOV1\r\n", 8) || get32(b.data() + 8) != 1 ||
      get32(b.data() + 20) != KDF_ROUNDS)
    return false;
  uint32_t length = get32(b.data() + 16), generation = get32(b.data() + 12);
  if (!generation || length < 10 || length > PLAIN_MAX ||
      b.size() != HEADER_SIZE + length + TRAILER_SIZE ||
      memcmp(b.data() + b.size() - 40, "SVCOMMIT", 8))
    return false;
  Key hash{};
  if (!sha256(b.data(), b.size() - 32, hash.data()) ||
      !constantEqual(hash.data(), b.data() + b.size() - 32, 32))
    return false;
  s.length = length;
  s.generation = generation;
  memcpy(s.identity.id.data(), b.data() + 24, 16);
  memcpy(s.identity.salt.data(), b.data() + 40, 16);
  return true;
}
bool encryptSnapshot(const Document &doc, const Identity &id, const Key &root,
                     uint32_t gen, Random random, Bytes &out) {
  SensitiveBuffer plain(PLAIN_MAX);
  size_t length = 0;
  Key key{};
  if (!gen || !plain || !packDocument(doc, plain.data(), plain.size(), length))
    return false;
  out.assign(HEADER_SIZE + length + TRAILER_SIZE, 0);
  memcpy(out.data(), "SOLOV1\r\n", 8);
  put32(out.data() + 8, 1);
  put32(out.data() + 12, gen);
  put32(out.data() + 16, length);
  put32(out.data() + 20, KDF_ROUNDS);
  memcpy(out.data() + 24, id.id.data(), 16);
  memcpy(out.data() + 40, id.salt.data(), 16);
  bool ok = random(out.data() + 56, 32) && random(out.data() + 88, 12) &&
            payloadKey(root, out.data() + 56, key);
  mbedtls_gcm_context aes;
  mbedtls_gcm_init(&aes);
  int rc = ok ? mbedtls_gcm_setkey(&aes, MBEDTLS_CIPHER_ID_AES, key.data(), 256)
              : -1;
  if (!rc)
    rc = mbedtls_gcm_crypt_and_tag(&aes, MBEDTLS_GCM_ENCRYPT, length,
                                   out.data() + 88, 12, out.data(), HEADER_SIZE,
                                   plain.data(), out.data() + HEADER_SIZE, 16,
                                   out.data() + HEADER_SIZE + length);
  mbedtls_gcm_free(&aes);
  erase(key.data(), 32);
  if (rc) {
    out.clear();
    return false;
  }
  memcpy(out.data() + out.size() - 40, "SVCOMMIT", 8);
  return sha256(out.data(), out.size() - 32, out.data() + out.size() - 32);
}
bool decryptSnapshot(const Bytes &b, const Key &root, Document &doc) {
  erase(&doc, sizeof(doc));
  Snapshot s;
  Key key{};
  if (!inspectSnapshot(b, s) || !payloadKey(root, b.data() + 56, key)) {
    erase(key.data(), key.size());
    return false;
  }
  SensitiveBuffer plain(s.length);
  if (!plain) {
    erase(key.data(), 32);
    return false;
  }
  mbedtls_gcm_context aes;
  mbedtls_gcm_init(&aes);
  int rc = mbedtls_gcm_setkey(&aes, MBEDTLS_CIPHER_ID_AES, key.data(), 256);
  if (!rc)
    rc =
        mbedtls_gcm_auth_decrypt(&aes, s.length, b.data() + 88, 12, b.data(),
                                 HEADER_SIZE, b.data() + HEADER_SIZE + s.length,
                                 16, b.data() + HEADER_SIZE, plain.data());
  mbedtls_gcm_free(&aes);
  erase(key.data(), 32);
  return !rc && unpackDocument(plain.data(), plain.size(), doc);
}
bool randomPassword(Random random, char *out, size_t n) {
  constexpr char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@";
  if (n < 12 || n > 64)
    return false;
  std::array<uint8_t, 64> bytes{};
  for (unsigned tries = 0; tries < 128; tries++) {
    if (!random(bytes.data(), n)) {
      erase(bytes.data(), 64);
      erase(out, n + 1);
      return false;
    }
    unsigned classes = 0;
    for (size_t i = 0; i < n; i++) {
      unsigned c = bytes[i] & 63;
      out[i] = alphabet[c];
      classes |= c < 26 ? 1 : c < 52 ? 2 : c < 62 ? 4 : 8;
    }
    if (classes == 15) {
      out[n] = 0;
      erase(bytes.data(), 64);
      return true;
    }
  }
  erase(bytes.data(), 64);
  erase(out, n + 1);
  return false;
}
static bool filename(const std::string &name, uint32_t &generation) {
  if (name.size() != 16 || name.compare(0, 4, "/sv_") ||
      name.compare(12, 4, ".dat"))
    return false;
  uint8_t bytes[4];
  if (!unhex(name.substr(4, 8), bytes, 4))
    return false;
  generation = (uint32_t(bytes[0]) << 24) | (uint32_t(bytes[1]) << 16) |
               (uint32_t(bytes[2]) << 8) | bytes[3];
  return generation != 0;
}
static std::string snapshotName(uint32_t gen) {
  char out[17];
  snprintf(out, sizeof(out), "/sv_%08lx.dat", static_cast<unsigned long>(gen));
  return out;
}
bool SnapshotStore::scan() {
  files_.clear();
  active_ = {};
  revision_ = {};
  maximum_ = 0;
  cleanupWarning = false;
  if (!volume_.mounted()) {
    state_ = DiskState::Unavailable;
    return false;
  }
  bool initialized = false;
  std::vector<std::string> names;
  if (!volume_.names(names) || names.size() > 128 ||
      !volume_.initialized(initialized)) {
    state_ = DiskState::Corrupt;
    return false;
  }
  bool foreign = false;
  for (const auto &name : names) {
    uint32_t generation = 0;
    if (!filename(name, generation)) {
      foreign = true;
      continue;
    }
    maximum_ = std::max(maximum_, generation);
    Bytes b;
    Snapshot s;
    bool complete = volume_.read(name, b, BLOB_MAX) && inspectSnapshot(b, s) &&
                    s.generation == generation;
    files_.push_back({generation, name, complete});
    if (complete && generation > active_.generation) {
      active_ = s;
      memcpy(revision_.data(), b.data() + b.size() - 32, 32);
    }
  }
  std::sort(files_.begin(), files_.end(),
            [](const Candidate &a, const Candidate &b) {
              return a.generation > b.generation;
            });
  if (foreign) {
    state_ = DiskState::Foreign;
    return false;
  }
  if (!active_.generation) {
    state_ =
        (!names.empty() || initialized) ? DiskState::Corrupt : DiskState::Empty;
    return state_ == DiskState::Empty;
  }
  state_ =
      maximum_ == active_.generation ? DiskState::Sealed : DiskState::Recovery;
  return true;
}
bool SnapshotStore::activeRead(Bytes &b) {
  if (state_ != DiskState::Sealed && state_ != DiskState::Recovery)
    return false;
  Snapshot s;
  if (!volume_.read(snapshotName(active_.generation), b, BLOB_MAX) ||
      !inspectSnapshot(b, s) || s.generation != active_.generation ||
      !constantEqual(revision_.data(), b.data() + b.size() - 32, 32)) {
    state_ = DiskState::Corrupt;
    return false;
  }
  return true;
}
Result SnapshotStore::read(Bytes &b) {
  return activeRead(b) ? Result::Ok : Result::Corrupt;
}
Result SnapshotStore::save(const Document &doc, const Identity &identity,
                           const Key &key, Random random, bool allowRecovery) {
  if (state_ != DiskState::Empty && state_ != DiskState::Sealed &&
      !(allowRecovery && state_ == DiskState::Recovery))
    return Result::Corrupt;
  if (maximum_ == std::numeric_limits<uint32_t>::max())
    return Result::Full;
  Bytes wanted;
  if (!encryptSnapshot(doc, identity, key, maximum_ + 1, random, wanted))
    return Result::Invalid;
  if (volume_.freeBytes() < wanted.size() + 8192)
    return Result::Full;
  std::string name = snapshotName(maximum_ + 1);
  if (!volume_.create(name, wanted.data(), wanted.size(), 40)) {
    state_ = DiskState::Corrupt;
    return Result::Storage;
  }
  Bytes actual;
  Snapshot s;
  if (!volume_.read(name, actual, BLOB_MAX) || actual != wanted ||
      !inspectSnapshot(actual, s) || !volume_.markInitialized()) {
    state_ = DiskState::Corrupt;
    return Result::Storage;
  }
  if (!scan()) {
    state_ = DiskState::Corrupt;
    return Result::Storage;
  }
  unsigned retained = 0;
  for (const auto &f : files_) {
    if (f.complete && retained < 3) {
      ++retained;
      continue;
    }
    if (!volume_.remove(f.name))
      cleanupWarning = true;
  }
  return Result::Ok;
}
bool SnapshotStore::discardOlder() {
  bool ok = true;
  for (const auto &f : files_)
    if (f.generation != active_.generation && !volume_.remove(f.name))
      ok = false;
  cleanupWarning = !ok;
  return ok;
}
} // namespace solo
