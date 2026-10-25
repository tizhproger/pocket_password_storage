#include "pps_network.h"
#include "app.h"
#include "web.h"
#include "crypto.h"
#include <WiFi.h>
#include <SPIFFS.h>
#include <Preferences.h>
#include <DNSServer.h>
#include <ESPmDNS.h>
namespace Net {
static Preferences prefs;
static SecureJson cfg(4096);
static DNSServer dns;
static String activeMode,activeSSID,activePass,configNote,runtimeNote;
static uint64_t connecting=0,applyAt=0,retryAt=0;
static bool httpsUp=false,dnsUp=false,mdnsUp=false,retryRadio=false,initialized=false;
static bool uncertain=false;
static uint8_t serviceFails=0;
static State netState=State::Off;
State state(){return netState;}
const char* stateName(){switch(netState){case State::Off:return "off";case State::Connecting:return "connecting";case State::Ready:return "ready";case State::Degraded:return "degraded";case State::Retry:return "retrying";}return "off";}
static bool textField(JsonVariantConst v,size_t lo,size_t hi){if(!v.is<const char*>())return false;auto s=v.as<JsonString>();return s.size()>=lo&&s.size()<=hi&&strlen(s.c_str())==s.size();}
static bool wifiPass(JsonVariantConst v,bool open){if(!textField(v,open?0:8,63))return false;const char* p=v.as<const char*>();if(open&&strlen(p)==0)return true;if(strlen(p)<8)return false;for(;*p;p++)if(*p<32||*p>126)return false;return true;}
static bool valid(JsonVariantConst c){Secret<8> rev;return c.is<JsonObjectConst>()&&c.size()==6&&textField(c["ssid"],0,32)&&wifiPass(c["password"],true)&&textField(c["ap_ssid"],1,32)&&wifiPass(c["ap_password"],false)&&textField(c["revision"],16,16)&&Crypto::unhex(c["revision"].as<const char*>(),rev.data,8)&&(c["wifi_mode"]=="ap"||c["wifi_mode"]=="wifi");}
static Outcome persist(const SecureJson& next){
  PpsMemory::Attempt memory;if(uncertain)return Outcome::Storage;
  if(next.overflowed())return Outcome::NoMemory;
  Bytes data;if(!valid(next.as<JsonVariantConst>())||!serializeChecked(next,data,4095))return memory.failed()?Outcome::NoMemory:Outcome::Invalid;
  Bytes prior;if(!serializeChecked(cfg,prior,4095))return memory.failed()?Outcome::NoMemory:Outcome::Storage;

  Bytes check(4096);if(!check.valid())return Outcome::NoMemory;
  prefs.putBytes("config",data.data(),data.size());size_t n=prefs.getBytesLength("config");
  bool readOK=n&&n<=check.size()&&prefs.getBytes("config",check.data(),n)==n;
  if(!readOK||n!=data.size()||!Crypto::equal(check.data(),data.data(),n)){
    if(!readOK||n!=prior.size()||!Crypto::equal(check.data(),prior.data(),n)){uncertain=true;configNote="Save state unknown; restart to reload settings.";}
    return Outcome::Storage;
  }
  if(&next!=&cfg&&(!cfg.set(next)||cfg.overflowed())){uncertain=true;cfg.clear();configNote="Settings saved; restart to reload.";return Outcome::NoMemory;}
  configNote="";return Outcome::Ok;
}
static bool defaults(){cfg.clear();cfg["ssid"]="";cfg["password"]="";cfg["ap_ssid"]="PPS-"+Crypto::token(3);cfg["ap_password"]=Crypto::token(10);cfg["wifi_mode"]="ap";cfg["revision"]=Crypto::token(8);return !cfg.overflowed()&&valid(cfg.as<JsonVariantConst>());}
static void stopLink(){
  Web::stop();dns.stop();MDNS.end();httpsUp=dnsUp=mdnsUp=false;
  Crypto::radioEntropy(false);
  WiFi.disconnect(true);WiFi.softAPdisconnect(true);WiFi.mode(WIFI_OFF);
  connecting=retryAt=0;retryRadio=false;activeMode="";activeSSID="";wipe(activePass);netState=State::Off;
}
void stop(){stopLink();applyAt=0;runtimeNote="";serviceFails=0;}
static void retry(bool radio,const char* why){
  retryRadio=radio;runtimeNote=why;netState=State::Retry;
  serviceFails=std::min<int>(serviceFails+1,6);retryAt=App::now()+std::min<uint32_t>(30000,5000u*serviceFails);
}
static bool services(){
  if(!httpsUp)httpsUp=Web::start();
  if(!httpsUp){retry(false,"HTTPS failed; retry pending");return false;}
  if(activeMode=="ap"&&!dnsUp)dnsUp=dns.start(53,"*",WiFi.softAPIP());
  if(!mdnsUp){mdnsUp=MDNS.begin("pps");if(mdnsUp&&!MDNS.addService("https","tcp",443)){MDNS.end();mdnsUp=false;}}
  serviceFails=0;retryRadio=false;
  if((activeMode=="ap"&&!dnsUp)||!mdnsUp){
    netState=State::Degraded;runtimeNote=!mdnsUp?"mDNS failed; use HTTPS IP":"DNS failed; use HTTPS IP";retryAt=App::now()+30000;
  }else{netState=State::Ready;runtimeNote="";retryAt=0;}
  return true;
}
static bool ap(){
  activeMode="ap";activeSSID=cfg["ap_ssid"].as<const char*>();wipe(activePass);activePass=cfg["ap_password"].as<const char*>();
  if(strcmp(activeSSID.c_str(),cfg["ap_ssid"].as<const char*>())||strcmp(activePass.c_str(),cfg["ap_password"].as<const char*>())){PpsMemory::failed();wipe(activePass);retry(true,"Low RAM; AP start postponed");return false;}
  bool radio=WiFi.mode(WIFI_AP);Crypto::radioEntropy(radio);
  if(!radio||!WiFi.softAP(activeSSID.c_str(),activePass.c_str())){retry(true,"AP failed; retry pending");return false;}
  return services();
}
static void fallback(){App::lock();stopLink();serviceFails=0;ap();}
bool apply(const String& selected){
  if(uncertain||!initialized||!valid(cfg.as<JsonVariantConst>()))return false;
  String next=selected.length()?selected:String(cfg["wifi_mode"].as<const char*>());
  if(next!="ap"&&next!="wifi")return false;
  App::lock();stop();
  if(next=="wifi"&&strlen(cfg["ssid"].as<const char*>())){
    activeMode="wifi";activeSSID=cfg["ssid"].as<const char*>();
    if(strcmp(activeSSID.c_str(),cfg["ssid"].as<const char*>())){PpsMemory::failed();fallback();return false;}
    if(!WiFi.mode(WIFI_STA)){fallback();return false;}
    Crypto::radioEntropy(true);
    WiFi.begin(activeSSID.c_str(),cfg["password"].as<const char*>());connecting=App::now()+10000;netState=State::Connecting;return true;
  }
  return ap();
}
bool begin(){
  PpsMemory::Attempt memory;
  stop();prefs.end();initialized=false;uncertain=false;configNote="";
  if(!prefs.begin("ppsnet",false)||!defaults())return false;
  if(prefs.isKey("config")){
    size_t n=prefs.getBytesLength("config");Bytes b(n<=4096?n:0);if(!b.valid())return false;SecureJson saved(4096);
    if(n&&n<=4096&&prefs.getBytes("config",b.data(),n)==n&&deserializeChecked(saved,b.data(),n,true)&&valid(saved.as<JsonVariantConst>())){
      if(!cfg.set(saved)||cfg.overflowed())return false;
    }else if(memory.failed())return false;else configNote="Saved settings invalid; temporary AP. Review all settings before saving.";
  }else{
    auto f=SPIFFS.open("/settings.json","r");SecureJson legacy(6144);bool imported=false;
    if(f&&f.size()>0&&f.size()<=4096){Bytes b(f.size());if(!b.valid()){f.close();return false;}bool readOK=f.read(b.data(),b.size())==b.size();
      if(readOK&&deserializeChecked(legacy,b.data(),b.size())&&legacy.is<JsonObject>()){
        imported=true;
        if(textField(legacy["ssid"],0,32)&&wifiPass(legacy["password"],true)){cfg["ssid"]=legacy["ssid"];cfg["password"]=legacy["password"];}
        if(textField(legacy["ap_ssid"],1,32))cfg["ap_ssid"]=legacy["ap_ssid"];
        if(wifiPass(legacy["ap_password"],false))cfg["ap_password"]=legacy["ap_password"];
        if(legacy["wifi_mode"]=="wifi")cfg["wifi_mode"]="wifi";
      }
    }
    if(f)f.close();
    if(memory.failed()||cfg.overflowed())return false;
    if(SPIFFS.exists("/settings.json")&&!imported)configNote="Legacy settings unreadable; temporary AP. Original file kept.";
    else if(persist(cfg)!=Outcome::Ok)return false;
  }
  initialized=true;WiFi.persistent(false);WiFi.setAutoReconnect(false);return apply();
}
void tick(){
  uint64_t now=App::now();
  if(applyAt&&now>=applyAt){applyAt=0;apply();}
  if(connecting){
    if(WiFi.status()==WL_CONNECTED){connecting=0;services();}
    else if(now>=connecting)fallback();
  }else if(activeMode=="wifi"&&WiFi.status()!=WL_CONNECTED)fallback();
  if(retryAt&&now>=retryAt){
    retryAt=0;
    if(activeMode=="wifi"&&serviceFails>=3)fallback();
    else if(retryRadio){uint8_t fails=serviceFails;stopLink();serviceFails=fails;ap();}
    else services();
  }
  if(dnsUp)dns.processNextRequest();
}
Outcome queueApply(){if(uncertain)return Outcome::Storage;if(!initialized)return Outcome::Unavailable;applyAt=App::now()+1000;return Outcome::Ok;}
String ip(){return activeMode=="ap"?WiFi.softAPIP().toString():activeMode=="wifi"?WiFi.localIP().toString():String("0.0.0.0");}
String mode(){return activeMode;}
const String& ssid(){return activeSSID;}
const String& apPassword(){return activePass;}
String warning(){return configNote.length()?(runtimeNote.length()?configNote+" "+runtimeNote:configNote):runtimeNote;}
void settings(SecureJson& out){out["ssid"]=cfg["ssid"];out["ap_ssid"]=cfg["ap_ssid"];out["wifi_mode"]=cfg["wifi_mode"];out["revision"]=cfg["revision"];out["has_password"]=strlen(cfg["password"]|"")>0;out["has_ap_password"]=true;out["warning"]=warning();out["network_state"]=stateName();}
Outcome save(JsonVariantConst input){
  if(uncertain)return Outcome::Storage;
  if(!input.is<JsonObjectConst>()||input.size()!=7||!textField(input["revision"],16,16)||!input["open_wifi"].is<bool>()||!textField(input["password"],0,63)||!textField(input["ap_password"],0,63)||!textField(input["ssid"],0,32)||!textField(input["ap_ssid"],1,32)||(input["wifi_mode"]!="ap"&&input["wifi_mode"]!="wifi"))return Outcome::Invalid;
  if(strcmp(input["revision"].as<const char*>(),cfg["revision"].as<const char*>()))return Outcome::Conflict;
  if(input["open_wifi"].as<bool>()&&strlen(input["password"].as<const char*>()))return Outcome::Invalid;
  SecureJson next(4096);if(!next.set(cfg))return Outcome::NoMemory;next["ssid"]=input["ssid"];next["ap_ssid"]=input["ap_ssid"];next["wifi_mode"]=input["wifi_mode"];
  if(input["open_wifi"].as<bool>())next["password"]="";else if(strlen(input["password"]))next["password"]=input["password"];
  if(strlen(input["ap_password"]))next["ap_password"]=input["ap_password"];
  if(!input["open_wifi"].as<bool>()&&!strlen(next["password"]|""))return Outcome::Invalid;
  String revision=Crypto::token(8);if(revision.length()!=16)return Outcome::NoMemory;next["revision"]=revision;return persist(next);
}
Outcome saveMode(const String& selected){SecureJson next(4096);if(!next.set(cfg))return Outcome::NoMemory;next["wifi_mode"]=selected;String revision=Crypto::token(8);if(revision.length()!=16)return Outcome::NoMemory;next["revision"]=revision;return persist(next);}
}
