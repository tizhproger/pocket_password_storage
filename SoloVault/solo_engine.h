#pragma once
#include "solo_wire.h"
namespace solo {
class Engine {
  SnapshotStore &store_;
  Random random_;
  std::unique_ptr<Document> document_;
  Key root_{};
  Identity identity_{};
  bool unlocked_ = false;
  uint64_t activity_ = 0, opened_ = 0;
  PhysicalWindow window_;
  struct Pending {
    Op op = Op::Status;
    uint32_t requestId = 0;
    uint64_t until = 0;
    bool active = false, verified = false;
    Key revision{}, restoreKey{};
    Record record{};
    uint8_t policy = 0, generatedLength = 0;
    Bytes blob;
    Snapshot snapshot{};
    std::unique_ptr<Document> restored;
  } pending_;
  void clearPending();
  Result commitDocument(const Document &);
  int index(const Id &) const;
  Result stagePut(const Request &);
  Reply baseReply(const Request &, Result) const;

public:
  Engine(SnapshotStore &, Random);
  ~Engine();
  bool unlocked() const { return unlocked_; }
  const Document *document() const {
    return unlocked_ ? document_.get() : nullptr;
  }
  const Identity &identity() const { return identity_; }
  bool initialize(const Key &, const Identity &, uint64_t);
  bool unlock(const Key &, uint64_t);
  void lock();
  void localActivity(uint64_t now) { activity_ = now; }
  bool expired(uint64_t now) const {
    return unlocked_ && (now - activity_ >= 90000 || now - opened_ >= 900000);
  }
  bool openWindow(Access, uint64_t);
  Access access(uint64_t now) const { return window_.access(now); }
  void closeWindow() { window_.close(); }
  Reply request(const Request &, uint64_t);
  bool pending() const { return pending_.active; }
  Op pendingOp() const { return pending_.op; }
  const char *pendingTitle() const { return pending_.record.title; }
  const Snapshot &restoreInfo() const { return pending_.snapshot; }
  uint16_t restoreCount() const {
    return pending_.restored ? pending_.restored->count : 0;
  }
  bool verifyRestore(const Key &);
  Reply approve(bool, uint64_t);
  bool pendingExpired(uint64_t now) const {
    return pending_.active && (now >= pending_.until ||
                               access(now) == Access::Closed || expired(now));
  }
  Result localGenerate(uint64_t);
  Result localDelete(const Id &, uint64_t);
  Result repair(uint64_t);
  Result rotate(const Key &, const Identity &, uint64_t);
};
} // namespace solo
