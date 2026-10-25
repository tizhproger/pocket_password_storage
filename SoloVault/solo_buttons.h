#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
namespace solo {
class Buttons {
  struct Button {
    bool raw = false, down = false;
    uint64_t changed = 0, since = 0, repeat = 0;
    bool press = false, release = false, step = false;
  };
  std::array<Button, 5> b_{};
  bool fenced_ = true;

public:
  enum Index { Up, Down, Left, Right, Select };
  void fence() {
    fenced_ = true;
    for (auto &b : b_)
      b.press = b.release = b.step = false;
  }
  void update(const std::array<bool, 5> &raw, uint64_t now) {
    bool allUp = true;
    for (size_t i = 0; i < 5; i++) {
      auto &b = b_[i];
      b.press = b.release = b.step = false;
      if (raw[i] != b.raw) {
        b.raw = raw[i];
        b.changed = now;
      }
      if (b.raw != b.down && now - b.changed >= 30) {
        b.down = b.raw;
        if (b.down) {
          b.since = now;
          b.repeat = now + 400;
          b.press = b.step = true;
        } else
          b.release = true;
      }
      if (i != Select && b.down && now >= b.repeat) {
        b.step = true;
        b.repeat = now + 140;
      }
      if (b.raw || b.down)
        allUp = false;
    }
    if (fenced_) {
      for (auto &b : b_)
        b.press = b.release = b.step = false;
      if (allUp)
        fenced_ = false;
    }
  }
  bool down(Index i) const { return !fenced_ && b_[i].down; }
  bool pressed(Index i) const { return !fenced_ && b_[i].press; }
  bool released(Index i) const { return !fenced_ && b_[i].release; }
  bool step(Index i) const { return !fenced_ && b_[i].step; }
  uint64_t held(Index i, uint64_t now) const {
    return down(i) ? now - b_[i].since : 0;
  }
  bool activity() const {
    for (const auto &b : b_)
      if (!fenced_ && (b.press || b.step))
        return true;
    return false;
  }
};
} // namespace solo
