#pragma once
#include "solo_core.h"
#include <Arduino.h>
#include <Preferences.h>
#include <SPIFFS.h>
#include <bootloader_random.h>
#include <esp_partition.h>
#include <esp_system.h>
#include <sdkconfig.h>
namespace solo {
// RF, ADC and I2S are never started by this application.
inline bool hardwareRandom(uint8_t *out, size_t n) {
  if (!out || !n)
    return false;
  bootloader_random_enable();
  esp_fill_random(out, n);
  bootloader_random_disable();
  return true;
}
class EspVolume final : public Volume {
  bool mounted_ = false;
  bool unsafeDump_ = true;
  Preferences control_;
  bool controlReady_ = false;

public:
  bool unsafeDumpConfiguration() const { return unsafeDump_; }
  void begin() {
    // A stock Arduino SDK may write task stacks (including keys) on panic.
    // Refuse to load/create secrets if it has a destination for core dumps.
    unsafeDump_ = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                                           ESP_PARTITION_SUBTYPE_DATA_COREDUMP,
                                           nullptr) != nullptr;
#if defined(CONFIG_ESP_COREDUMP_ENABLE_TO_UART) &&                             \
    CONFIG_ESP_COREDUMP_ENABLE_TO_UART
    unsafeDump_ = true;
#endif
    if (unsafeDump_)
      return;
    controlReady_ = control_.begin("soloctl", false);
    mounted_ = SPIFFS.begin(false);
    if (mounted_ && SPIFFS.totalBytes() < 131072)
      mounted_ = false;
  }
  bool mounted() const override { return mounted_; }
  bool names(std::vector<std::string> &out) override {
    out.clear();
    if (!mounted_)
      return false;
    File directory = SPIFFS.open("/");
    if (!directory || !directory.isDirectory())
      return false;
    for (File file = directory.openNextFile(); file;
         file = directory.openNextFile()) {
      if (out.size() >= 129) {
        file.close();
        directory.close();
        return false;
      }
      std::string name = file.name();
      if (name.empty() || name[0] != '/')
        name = "/" + name;
      out.push_back(name);
      file.close();
    }
    directory.close();
    return true;
  }
  bool read(const std::string &name, Bytes &out, size_t maximum) override {
    if (!mounted_)
      return false;
    File file = SPIFFS.open(name.c_str(), FILE_READ);
    if (!file || file.isDirectory())
      return false;
    size_t length = file.size();
    if (length > maximum) {
      file.close();
      return false;
    }
    out.assign(length, 0);
    size_t got = file.read(out.data(), length);
    file.close();
    return got == length;
  }
  bool create(const std::string &name, const uint8_t *bytes, size_t n,
              size_t footer) override {
    if (!mounted_ || n < footer || SPIFFS.exists(name.c_str()))
      return false;
    File file = SPIFFS.open(name.c_str(), FILE_WRITE);
    if (!file)
      return false;
    const size_t body = n - footer;
    bool ok = file.write(bytes, body) == body;
    file.flush();
    if (ok)
      ok = file.write(bytes + body, footer) == footer;
    file.flush();
    ok = ok && file.size() == n;
    file.close();
    return ok;
  }
  bool remove(const std::string &name) override {
    return mounted_ &&
           (!SPIFFS.exists(name.c_str()) || SPIFFS.remove(name.c_str()));
  }
  size_t freeBytes() const override {
    return mounted_ ? SPIFFS.totalBytes() - SPIFFS.usedBytes() : 0;
  }
  bool initialized(bool &value) override {
    if (!controlReady_)
      return false;
    if (!control_.isKey("initialized")) {
      value = false;
      return true;
    }
    if (control_.getType("initialized") != PT_U8)
      return false;
    value = control_.getBool("initialized", true);
    return true;
  }
  bool markInitialized() override {
    if (!controlReady_)
      return false;
    bool old = false;
    if (initialized(old) && old)
      return true;
    return control_.putBool("initialized", true) == 1 &&
           control_.getBool("initialized", false);
  }
  // Never called at boot. Two separate physical confirmations are required.
  bool factoryReset() {
    if (!controlReady_ || !markInitialized())
      return false;
    SPIFFS.end();
    mounted_ = false;
    if (!SPIFFS.format())
      return false;
    mounted_ = SPIFFS.begin(false);
    if (!mounted_ || SPIFFS.totalBytes() < 131072) {
      mounted_ = false;
      return false;
    }
    std::vector<std::string> files;
    if (!names(files) || !files.empty() || !control_.clear())
      return false;
    bool marker = true;
    return initialized(marker) && !marker;
  }
};
} // namespace solo
