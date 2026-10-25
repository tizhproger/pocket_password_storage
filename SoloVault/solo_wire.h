#pragma once
#include "solo_core.h"
namespace solo {
constexpr size_t WIRE_MAX = BLOB_MAX + 64;
enum class Op : uint8_t {
  Status = 1,
  List = 16,
  Put = 17,
  Delete = 18,
  Backup = 32,
  Restore = 33
};
struct Request {
  Op op;
  uint32_t id;
  const uint8_t *data;
  size_t size;
};
struct Reply {
  Op op = Op::Status;
  uint32_t id = 0;
  Result result = Result::Invalid;
  Bytes data;
};
uint32_t crc32(const uint8_t *, size_t);
Bytes responseFrame(const Reply &);
class FrameDecoder {
  std::array<uint8_t, WIRE_MAX + 15> bytes_{};
  size_t used_ = 0, target_ = 0;
  uint64_t started_ = 0;
  bool ready_ = false;

public:
  ~FrameDecoder() { reset(); }
  void reset();
  bool feed(uint8_t, uint64_t);
  void expire(uint64_t);
  bool ready() const { return ready_; }
  Request request() const;
};
enum class Access : uint8_t { Closed, Backup, Manage, Restore };
class PhysicalWindow {
  Access access_ = Access::Closed;
  uint64_t deadline_ = 0;

public:
  void open(Access a, uint64_t now) {
    access_ = a;
    deadline_ = now + (a == Access::Restore ? 300000 : 120000);
  }
  void close() {
    access_ = Access::Closed;
    deadline_ = 0;
  }
  Access access(uint64_t now) const {
    return now < deadline_ ? access_ : Access::Closed;
  }
  bool allows(Op, bool, uint64_t) const;
};
} // namespace solo
