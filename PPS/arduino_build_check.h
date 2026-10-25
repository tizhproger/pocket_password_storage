#ifndef PPS_PROJECT_ARDUINO_BUILD_CHECK_H_INCLUDED
#define PPS_PROJECT_ARDUINO_BUILD_CHECK_H_INCLUDED

#if !defined(ARDUINO_ARCH_ESP32)
#error "PPS V2 requires the esp32 board package by Espressif Systems."
#endif
#include <esp_arduino_version.h>
#if ESP_ARDUINO_VERSION_MAJOR != 3
#error "PPS supports Arduino-ESP32 3.x; review new major APIs before building."
#endif
#if __cplusplus < 201703L
#error "PPS V2 requires C++17. Keep build_opt.h beside PPS_V2.ino."
#endif
#include "pps_json_config.h"
#include "pps_dependency_check.h"

#endif
