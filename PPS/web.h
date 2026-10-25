#ifndef PPS_PROJECT_WEB_H_INCLUDED
#define PPS_PROJECT_WEB_H_INCLUDED
#include <Arduino.h>
namespace Web {bool begin();bool start();void stop();void tick();String fingerprint();}
#endif
