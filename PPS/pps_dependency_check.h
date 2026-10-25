#ifndef PPS_DEPENDENCY_CHECK_H
#define PPS_DEPENDENCY_CHECK_H
#include <mbedtls/version.h>
#if MBEDTLS_VERSION_MAJOR != 3
#error "PPS requires Mbed TLS 3.x from the Arduino-ESP32 SDK; review new major APIs."
#elif MBEDTLS_VERSION_NUMBER < 0x03060300
#error "Mbed TLS before 3.6.3 is unsupported (CVE-2025-27810). Update the Espressif board package."
#elif MBEDTLS_VERSION_NUMBER < 0x03060700
#warning "Review TLS SDK: Mbed TLS <3.6.7 may need CVE-2026-50581 backport. Session tickets are disabled for CVE-2026-50586."
#endif
#endif
