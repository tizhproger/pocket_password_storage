#ifndef PPS_PROJECT_PPS_NETWORK_H_INCLUDED
#define PPS_PROJECT_PPS_NETWORK_H_INCLUDED

#include "secure.h"
#include "outcome.h"
namespace Net {
enum class State {Off,Connecting,Ready,Degraded,Retry};
State state();
const char* stateName();
bool begin();
void tick();
void stop();
bool apply(const String& mode=String());
Outcome queueApply();
String ip();
String mode();
const String& ssid();
const String& apPassword();
String warning();
void settings(SecureJson&);
Outcome save(JsonVariantConst);
Outcome saveMode(const String&);
}

#endif
