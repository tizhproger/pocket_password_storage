#ifndef PPS_PROJECT_STORAGE_H_INCLUDED
#define PPS_PROJECT_STORAGE_H_INCLUDED

#include "config.h"
#include "secure.h"
#include "outcome.h"
namespace Vault {
enum class State {Empty,Legacy,Locked,Unlocked,Corrupt,FsError};
bool begin();
State state();
Outcome lastResult();
const char* stateName();
void lock();
bool unlock(const String&,bool byPin=false);
bool initialize(const String&,const String&,bool migrate);
bool read(SecureJson&);
bool save(const SecureJson&);
bool save(JsonVariantConst);
Outcome changeMaster(const String&,const String&);
Outcome restorePrevious(const String& currentMaster);
bool changePin(const String&);
bool recoverPrevious(const String&);
bool reset(bool allowFormat);
bool finishLegacyCleanup();
String revision();
bool validPin(const String&);
bool validMaster(const String&);
bool validate(JsonVariantConst);
bool importEntries(JsonVariantConst,SecureJson&,bool legacy);
}

#endif
