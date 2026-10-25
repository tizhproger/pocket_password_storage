#ifndef PPS_PROJECT_APP_H_INCLUDED
#define PPS_PROJECT_APP_H_INCLUDED

#include "storage.h"
namespace App {
uint64_t now();
bool begin();
bool resumeReset();
bool factoryReset();
void tick();
void touch();
void lock();
bool local();
bool pin(const String&,bool recovery=false);
String login(const String&);
bool authorized(const String&);
void logout(const String&);
bool startSetup(const String& pin);
const String& setupCode();
bool setupReady();
bool setup(const String& password,const String& code);
uint32_t waitSeconds(bool byPin);
bool changePin(const String&);
Outcome changeMaster(const String&,const String&);
Outcome restorePrevious(const String&);
Outcome lastResult();
}

#endif
