#include "app.h"
#include "crypto.h"
#include <Preferences.h>
#include <esp_timer.h>
namespace App {
static Preferences auth;
struct Rate {uint8_t fails=0,persisted=0;uint64_t until=0;};
static Rate webRate,pinRate;
struct Session {char token[65]{};uint64_t born=0;};
static Session sessions[4];
static bool localUnlocked=false;
static uint64_t activity=0,setupUntil=0,rebootAt=0;
static String pendingPin,code;
static Outcome last=Outcome::Ok;
Outcome lastResult(){return last;}
uint64_t now(){return uint64_t(esp_timer_get_time())/1000;}
static uint32_t penalty(uint8_t n){return n<3?1000:std::min<uint32_t>(300000,2000u<<std::min<int>(n-3,8));}
static bool attempt(Rate& r,const char* key){
  if(now()<r.until){last=Outcome::Throttled;return false;}
  r.fails=std::min<int>(12,r.fails+1);r.until=now()+penalty(r.fails);
  if(r.fails!=r.persisted){
    if(auth.putUChar(key,r.fails)!=1){last=Outcome::Storage;lock();return false;}
    r.persisted=r.fails;
  }
  last=Outcome::Credentials;return true;
}
static bool success(Rate& r,const char* key){if(r.persisted&&auth.putUChar(key,0)!=1){last=Outcome::Storage;lock();return false;}r={};last=Outcome::Ok;return true;}
bool begin(){
  lock();auth.end();webRate={};pinRate={};rebootAt=0;last=Outcome::Ok;
  if(!auth.begin("ppsauth",false))return false;
  for(const char* key:{"web","pin"})if(auth.isKey(key)&&auth.getType(key)!=PT_U8)return false;
  webRate.fails=webRate.persisted=std::min<int>(12,auth.getUChar("web",0));
  pinRate.fails=pinRate.persisted=std::min<int>(12,auth.getUChar("pin",0));
  if(webRate.fails)webRate.until=now()+penalty(webRate.fails);if(pinRate.fails)pinRate.until=now()+penalty(pinRate.fails);touch();return true;
}
void touch(){activity=now();}
void lock(){for(auto& s:sessions)wipe(&s,sizeof(s));localUnlocked=false;Vault::lock();wipe(pendingPin);wipe(code);setupUntil=0;}
bool local(){return localUnlocked&&Vault::state()==Vault::State::Unlocked;}
uint32_t waitSeconds(bool byPin){auto until=byPin?pinRate.until:webRate.until;return until>now()?(until-now()+999)/1000:0;}
bool pin(const String& credential,bool recovery){
  PpsMemory::Attempt memory;
  if(!attempt(pinRate,"pin"))return false;
  bool ok=recovery?Vault::recoverPrevious(credential):Vault::unlock(credential,true);
  if(!ok){last=memory.failed()?Outcome::NoMemory:Vault::lastResult();return false;}if(!success(pinRate,"pin"))return false;
  localUnlocked=!recovery;touch();return true;
}
String login(const String& password){
  PpsMemory::Attempt memory;
  if(password.length()>128){last=Outcome::Invalid;return String();}if(!attempt(webRate,"web"))return String();
  if(!Vault::unlock(password,false)){last=Vault::lastResult();return String();}if(!success(webRate,"web"))return String();
  String token=Crypto::token();if(token.length()!=64){last=memory.failed()?Outcome::NoMemory:Outcome::Unavailable;lock();return String();}
  size_t target=0;for(size_t i=0;i<4;i++){if(!sessions[i].token[0]){target=i;break;}if(sessions[i].born<sessions[target].born)target=i;}
  wipe(&sessions[target],sizeof(Session));memcpy(sessions[target].token,token.c_str(),64);sessions[target].born=now();touch();return token;
}
bool authorized(const String& token){if(token.length()!=64||Vault::state()!=Vault::State::Unlocked)return false;
  for(auto& s:sessions)if(s.token[0]&&now()-s.born<Config::SESSION_MS&&Crypto::equal(s.token,token.c_str(),64)){touch();return true;}return false;
}
void logout(const String& token){for(auto& s:sessions)if(token.length()==64&&Crypto::equal(s.token,token.c_str(),64))wipe(&s,sizeof(s));
  bool any=false;for(auto& s:sessions)any|=s.token[0]!=0;if(!any&&!localUnlocked)Vault::lock();
}
bool startSetup(const String& pin){if(!Vault::validPin(pin)||(Vault::state()!=Vault::State::Empty&&Vault::state()!=Vault::State::Legacy))return false;
  lock();pendingPin=pin;code=Crypto::token(4);if(pendingPin.length()!=pin.length()||code.length()!=8){last=Outcome::NoMemory;lock();return false;}setupUntil=now()+Config::SETUP_MS;return true;
}
bool setupReady(){return now()<setupUntil&&code.length()==8;}
const String& setupCode(){static const String empty;return setupReady()?code:empty;}
bool setup(const String& password,const String& supplied){
  if(now()>=setupUntil||pendingPin.length()==0||!attempt(webRate,"web"))return false;
  if(supplied.length()!=code.length()||!Crypto::equal(supplied.c_str(),code.c_str(),code.length()))return false;
  if(!Vault::initialize(password,pendingPin,Vault::state()==Vault::State::Legacy)){last=Vault::lastResult();return false;}
  bool ok=success(webRate,"web");lock();return ok;
}
bool changePin(const String& next){if(!local()){last=Outcome::Unavailable;return false;}if(!Vault::changePin(next)){last=Vault::lastResult();return false;}last=Outcome::Ok;lock();return true;}
Outcome changeMaster(const String& old,const String& next){
  if(!Vault::validMaster(next))return Outcome::Invalid;if(!attempt(webRate,"web"))return last;
  Outcome r=Vault::changeMaster(old,next);if(r!=Outcome::Ok)return r;
  bool ok=success(webRate,"web");lock();return ok?Outcome::Ok:Outcome::Storage;
}
Outcome restorePrevious(const String& password){
  if(!attempt(webRate,"web"))return last;
  Outcome r=Vault::restorePrevious(password);if(r!=Outcome::Ok)return r;
  bool ok=success(webRate,"web");lock();return ok?Outcome::Ok:Outcome::Storage;
}
static bool finishReset(){
  if(!Vault::reset(true))return false;
  auth.end();for(const char* ns:{"ppsnet","ppsauth","ppstls"}){Preferences p;if(!p.begin(ns,false)||!p.clear())return false;}
  Preferences control;if(!control.begin("ppsctl",false)||!control.remove("reset"))return false;return true;
}
bool resumeReset(){Preferences p;if(!p.begin("ppsctl",false))return false;bool pending=p.getBool("reset",false);p.end();return !pending||finishReset();}
bool factoryReset(){lock();Preferences p;if(!p.begin("ppsctl",false)||p.putBool("reset",true)!=1)return false;p.end();if(!finishReset())return false;rebootAt=now()+750;return true;}
void tick(){
  if(rebootAt&&now()>=rebootAt){ESP.restart();return;}
  if(Vault::state()==Vault::State::Corrupt||Vault::state()==Vault::State::FsError)lock();
  if(Vault::state()==Vault::State::Unlocked&&now()-activity>=Config::AUTOLOCK_MS)lock();
  bool any=false;for(auto& s:sessions){if(s.token[0]&&now()-s.born>=Config::SESSION_MS)wipe(&s,sizeof(s));any|=s.token[0]!=0;}
  if(!any&&!localUnlocked&&Vault::state()==Vault::State::Unlocked)Vault::lock();
  if(setupUntil&&now()>=setupUntil){wipe(pendingPin);wipe(code);setupUntil=0;}
}
}
