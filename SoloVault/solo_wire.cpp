#include "solo_wire.h"
#include <cstring>
namespace solo {
uint32_t crc32(const uint8_t *p, size_t n) {
  uint32_t crc = 0xffffffff;
  for (size_t i = 0; i < n; i++) {
    crc ^= p[i];
    for (unsigned b = 0; b < 8; b++)
      crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return crc ^ 0xffffffff;
}
Bytes responseFrame(const Reply &r) {
  if (r.data.size() + 1 > WIRE_MAX)
    return {};
  Bytes b(16 + r.data.size());
  memcpy(b.data(), "SVC1", 4);
  b[4] = uint8_t(r.op) | 0x80;
  put32(b.data() + 5, r.id);
  put16(b.data() + 9, r.data.size() + 1);
  b[11] = uint8_t(r.result);
  if (!r.data.empty())
    memcpy(b.data() + 12, r.data.data(), r.data.size());
  put32(b.data() + b.size() - 4, crc32(b.data(), b.size() - 4));
  return b;
}
void FrameDecoder::reset() {
  erase(bytes_.data(), used_);
  used_ = target_ = 0;
  started_ = 0;
  ready_ = false;
}
void FrameDecoder::expire(uint64_t now) {
  if (used_ && !ready_ && now - started_ >= 5000)
    reset();
}
bool FrameDecoder::feed(uint8_t byte, uint64_t now) {
  expire(now);
  if (ready_)
    return true;
  if (used_ < 4) {
    constexpr char sync[] = "SVC1";
    if (byte != uint8_t(sync[used_])) {
      reset();
      if (byte != 'S')
        return false;
    }
    if (!used_)
      started_ = now;
    bytes_[used_++] = byte;
    return false;
  }
  if (used_ >= bytes_.size()) {
    reset();
    return false;
  }
  bytes_[used_++] = byte;
  if (used_ == 11) {
    size_t n = get16(bytes_.data() + 9);
    if (n > WIRE_MAX || (bytes_[4] & 0x80)) {
      reset();
      return false;
    }
    target_ = 15 + n;
  }
  if (target_ && used_ == target_) {
    if (get32(bytes_.data() + used_ - 4) != crc32(bytes_.data(), used_ - 4)) {
      reset();
      return false;
    }
    ready_ = true;
    return true;
  }
  return false;
}
Request FrameDecoder::request() const {
  return {static_cast<Op>(bytes_[4]), get32(bytes_.data() + 5),
          bytes_.data() + 11, ready_ ? size_t(get16(bytes_.data() + 9)) : 0};
}
bool PhysicalWindow::allows(Op op, bool unlocked, uint64_t now) const {
  if (op == Op::Status)
    return true;
  auto a = access(now);
  if (a == Access::Closed)
    return false;
  if (op == Op::Backup)
    return a == Access::Backup || (a == Access::Manage && unlocked);
  if (op == Op::Restore)
    return a == Access::Restore || (a == Access::Manage && unlocked);
  return a == Access::Manage && unlocked &&
         (op == Op::List || op == Op::Put || op == Op::Delete);
}
} // namespace solo
