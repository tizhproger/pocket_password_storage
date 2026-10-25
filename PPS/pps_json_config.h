#ifndef PPS_JSON_CONFIG_H
#define PPS_JSON_CONFIG_H
#ifndef ARDUINOJSON_POOL_CAPACITY
#define ARDUINOJSON_POOL_CAPACITY 16
#elif ARDUINOJSON_POOL_CAPACITY != 16
#error "PPS JSON memory budgets require ARDUINOJSON_POOL_CAPACITY=16."
#endif
#include <ArduinoJson.h>
#if ARDUINOJSON_VERSION_MAJOR != 7
#error "PPS requires ArduinoJson 7.x; review new major APIs before building."
#elif ARDUINOJSON_VERSION_MINOR < 4 || (ARDUINOJSON_VERSION_MINOR == 4 && ARDUINOJSON_VERSION_REVISION < 3)
#error "PPS requires ArduinoJson >=7.4.3 for the tested allocator API."
#endif
#endif
