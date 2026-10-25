#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <mbedtls/md.h>
#include <memory>
#include <string>
#include <vector>
namespace solo {
constexpr char VERSION[] = "0.1.0";
constexpr char ALPHABET[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
constexpr size_t OWNER_LEN = 20, MAX_RECORDS = 32, PLAIN_MAX = 12304,
                 HEADER_SIZE = 100, TRAILER_SIZE = 56,
                 BLOB_MAX = PLAIN_MAX + HEADER_SIZE + TRAILER_SIZE;
constexpr uint32_t KDF_ROUNDS = 100000;
using Bytes = std::vector<uint8_t>;
using Key = std::array<uint8_t, 32>;
using Id = std::array<uint8_t, 8>;
using Random = bool (*)(uint8_t *, size_t);
void erase(void *, size_t);
bool constantEqual(const void *, const void *, size_t);
bool sha256(const void *, size_t, uint8_t[32]);
uint16_t get16(const uint8_t *);
uint32_t get32(const uint8_t *);
void put16(uint8_t *, uint16_t);
void put32(uint8_t *, uint32_t);
std::string hex(const void *, size_t);
bool unhex(const std::string &, void *, size_t);
bool validText(const char *, size_t, bool required = false,
               bool multiline = false);
struct Record {
  Id id{};
  char title[49]{}, user[65]{}, password[97]{}, note[161]{};
};
struct Document {
  uint16_t count = 0;
  std::array<Record, MAX_RECORDS> items{};
};
struct Identity {
  std::array<uint8_t, 16> id{}, salt{};
};
struct Snapshot {
  uint32_t generation = 0, length = 0;
  Identity identity{};
};
class SensitiveBuffer {
  std::unique_ptr<uint8_t[]> data_;
  size_t size_;

public:
  explicit SensitiveBuffer(size_t);
  ~SensitiveBuffer();
  uint8_t *data() { return data_.get(); }
  size_t size() const { return size_; }
  explicit operator bool() const { return bool(data_); }
  SensitiveBuffer(const SensitiveBuffer &) = delete;
  SensitiveBuffer &operator=(const SensitiveBuffer &) = delete;
};
class Derivation {
  mbedtls_md_context_t ctx_;
  Key u_{}, sum_{};
  uint32_t rounds_ = 0, done_ = 0;
  bool error_ = false;

public:
  Derivation();
  ~Derivation();
  bool start(const char *, size_t, const uint8_t *, size_t,
             uint32_t rounds = KDF_ROUNDS);
  void advance(uint32_t budget = 128);
  bool finished() const { return done_ && done_ == rounds_; }
  uint32_t progress() const { return rounds_ ? 100 * done_ / rounds_ : 0; }
  bool take(Key &);
  bool failed() const { return error_; }
  void cancel();
};
bool makeOwner(Random, char[OWNER_LEN + 1]);
bool validOwner(const char *);
bool makeIdentity(Random, Identity &);
bool validDocument(const Document &);
bool packDocument(const Document &, uint8_t *, size_t, size_t &);
bool unpackDocument(const uint8_t *, size_t, Document &);
bool inspectSnapshot(const Bytes &, Snapshot &);
bool encryptSnapshot(const Document &, const Identity &, const Key &, uint32_t,
                     Random, Bytes &);
bool decryptSnapshot(const Bytes &, const Key &, Document &);
bool randomPassword(Random, char *, size_t);
enum class DiskState : uint8_t {
  Empty,
  Sealed,
  Recovery,
  Foreign,
  Corrupt,
  Unavailable
};
enum class Result : uint8_t {
  Ok,
  Locked,
  Invalid,
  Busy,
  Conflict,
  Denied,
  Storage,
  Corrupt,
  Full,
  Pending,
  NeedKey,
  Expired
};
class Volume {
public:
  virtual ~Volume() = default;
  virtual bool mounted() const = 0;
  virtual bool names(std::vector<std::string> &) = 0;
  virtual bool read(const std::string &, Bytes &, size_t) = 0;
  // Fresh file only; final footer written after the body, then read back by
  // Store.
  virtual bool create(const std::string &, const uint8_t *, size_t,
                      size_t footer) = 0;
  virtual bool remove(const std::string &) = 0;
  virtual size_t freeBytes() const = 0;
  virtual bool initialized(bool &) = 0;
  virtual bool markInitialized() = 0;
};
class SnapshotStore {
  Volume &volume_;
  DiskState state_ = DiskState::Unavailable;
  Snapshot active_{};
  uint32_t maximum_ = 0;
  Key revision_{};
  struct Candidate {
    uint32_t generation;
    std::string name;
    bool complete;
  };
  std::vector<Candidate> files_;
  bool activeRead(Bytes &);

public:
  explicit SnapshotStore(Volume &v) : volume_(v) {}
  bool scan();
  DiskState state() const { return state_; }
  const Snapshot &active() const { return active_; }
  const Key &revision() const { return revision_; }
  Result read(Bytes &);
  Result save(const Document &, const Identity &, const Key &, Random,
              bool allowRecovery = false);
  bool discardOlder();
  bool cleanupWarning = false;
};
} // namespace solo
