#ifndef PPS_PROJECT_CONFIG_H_INCLUDED
#define PPS_PROJECT_CONFIG_H_INCLUDED

#include <Arduino.h>
#define PPS_MAX_ENTRIES 128
#define PPS_VAULT_MAX_BYTES 32768
#define PPS_STRINGIFY_INNER(x) #x
#define PPS_STRINGIFY(x) PPS_STRINGIFY_INNER(x)

// Wiring tested on my board, check yours if you use another board/kit
namespace Config {
constexpr int UP=8, DOWN=13, LEFT=5, RIGHT=9, SELECT=4;
constexpr int SCLK=2, MOSI=3, MISO=-1, RST=10, DC=6, CS=7;
constexpr int BATTERY=0, BACKLIGHT=-1;
constexpr bool BACKLIGHT_HIGH=true;
constexpr float DIVIDER=2.0f, CALIBRATION=1.0f;
constexpr size_t VAULT_MAX=PPS_VAULT_MAX_BYTES, JSON_CAPACITY=65536, REQUEST_MAX=VAULT_MAX+1024;
constexpr size_t MAX_ENTRIES=PPS_MAX_ENTRIES, MAX_EXTRAS=8;
constexpr uint32_t KDF_ROUNDS=120000;
constexpr uint64_t AUTOLOCK_MS=120000, SESSION_MS=1800000, SETUP_MS=180000;
constexpr uint64_t BOOT_LOGO_MS=1500;
constexpr const char* VERSION="2.1.4";
}

#endif
