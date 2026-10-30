#include "storage.h"
#include "crypto.h"
#include "journal.h"
#include <SPIFFS.h>
#include <EEPROM.h>
#include <Preferences.h>
#include <climits>
#include <cstddef>
namespace Vault {
#pragma pack(push,1)
struct WrappedKey {uint8_t iv[12],cipher[32],tag[16];};
struct Header {
  char magic[8];uint32_t version,generation,length;
  uint8_t uuid[16],masterSalt[16],pinSalt[16];
  WrappedKey master,pin;uint8_t iv[12],tag[16];
};
#pragma pack(pop)
static_assert(sizeof(Header)==216,"On-disk format");
static State status=State::FsError;
static Outcome last=Outcome::Ok;
static uint32_t lastReadMs=0,peakReadMs=0;
Outcome lastResult(){return last;}
uint32_t readLastMillis(){return lastReadMs;}
uint32_t readPeakMillis(){return peakReadMs;}
struct ReadTiming {
  uint32_t started=millis();
  ~ReadTiming(){uint32_t ms=millis()-started;lastReadMs=ms;if(ms>peakReadMs)peakReadMs=ms;}
};
static bool failure(Outcome r){last=r;return false;}
static Preferences meta;
static Journal::Head head{};
static Header header{};
static Secret<32> dataKey;
static bool mounted=false;
static uint64_t nonceNext=0,nonceLimit=0;
static uint8_t nonceUUID[16]{};
static const char* slotPath(uint32_t slot){return slot==0?"/pps0.bin":"/pps1.bin";}
State state(){return status;}
const char* stateName(){static const char* names[]={"empty","legacy","locked","unlocked","corrupt","fs_error"};return names[int(status)];}
void lock(){wipe(dataKey.data,32);if(status==State::Unlocked)status=State::Locked;}
static bool damaged(){lock();status=State::Corrupt;return failure(Outcome::Corrupt);}
static bool readFailure(const PpsMemory::Attempt& memory){return memory.failed()?failure(Outcome::NoMemory):damaged();}
bool validPin(const String& s){if(s.length()<6||s.length()>8)return false;for(size_t i=0;i<s.length();i++)if(s[i]<'0'||s[i]>'9')return false;return true;}
bool validMaster(const String& s){return s.length()>=12&&s.length()<=128;}
static bool str(JsonVariantConst v,size_t min,size_t max){if(!v.is<const char*>())return false;auto s=v.as<JsonString>();return s.size()>=min&&s.size()<=max&&s.size()==strlen(s.c_str());}
bool validate(JsonVariantConst v){
  if(!v.is<JsonObjectConst>())return false;auto root=v.as<JsonObjectConst>();
  if(root.size()!=2||!root["schema"].is<int>()||root["schema"].as<int>()!=2||!root["entries"].is<JsonArrayConst>())return false;
  auto entries=root["entries"].as<JsonArrayConst>();if(entries.size()>Config::MAX_ENTRIES)return false;
  uint16_t idSlots[Config::MAX_ENTRIES*2]{};
  constexpr size_t idSlotCount=Config::MAX_ENTRIES*2;
  for(size_t i=0;i<entries.size();i++){
    auto e=entries[i].as<JsonObjectConst>();Secret<16> id;
    if(e.isNull()||e.size()!=5||!str(e["id"],32,32)||!Crypto::unhex(e["id"].as<const char*>(),id.data,16)||!str(e["site"],1,128)||!str(e["login"],0,256)||!str(e["password"],0,256)||!e["extras"].is<JsonArrayConst>())return false;
    const char* idText=e["id"].as<const char*>();
    uint32_t hash=2166136261u;
    for(size_t n=0;n<32;n++)hash=(hash^static_cast<uint8_t>(idText[n]))*16777619u;
    size_t slot=hash%idSlotCount;
    while(idSlots[slot]){
      const char* other=entries[idSlots[slot]-1]["id"].as<const char*>();
      if(!strcmp(idText,other))return false;
      slot=(slot+1)%idSlotCount;
    }
    idSlots[slot]=static_cast<uint16_t>(i+1);
    auto extras=e["extras"].as<JsonArrayConst>();if(extras.size()>Config::MAX_EXTRAS)return false;
    for(size_t j=0;j<extras.size();j++){
      auto x=extras[j].as<JsonObjectConst>();if(x.isNull()||x.size()!=2||!str(x["name"],1,64)||!str(x["value"],0,512))return false;
      for(size_t k=0;k<j;k++)if(!strcmp(x["name"],extras[k]["name"]))return false;
    }
  }
  return measureJson(v)<=Config::VAULT_MAX;
}
bool importEntries(JsonVariantConst input,SecureJson& out,bool legacy){
  if((legacy&&!input.is<JsonArrayConst>())||(!legacy&&!validate(input)))return false;
  auto source=legacy?input.as<JsonArrayConst>():input["entries"].as<JsonArrayConst>();
  if(source.size()>Config::MAX_ENTRIES)return false;
  out.clear();out["schema"]=2;auto dest=out["entries"].to<JsonArray>();
  for(auto value:source){
    auto old=value.as<JsonObjectConst>();if(old.isNull())return false;
    auto e=jsonAddObject(dest);String id=Crypto::token(16);if(id.length()!=32)return false;e["id"]=id;
    if(!str(old["site"],1,128)||!str(old["login"],0,256)||!str(old["password"],0,256))return false;
    e["site"]=old["site"];e["login"]=old["login"];e["password"]=old["password"];
    if(!legacy)e["extras"]=old["extras"];
    else {
      auto extras=e["extras"].to<JsonArray>();
      for(auto kv:old){const char* name=kv.key().c_str();if(!strcmp(name,"site")||!strcmp(name,"login")||!strcmp(name,"password"))continue;
        if(!strlen(name)||strlen(name)>64||!str(kv.value(),0,512))return false;
        auto x=jsonAddObject(extras);x["name"]=kv.key();x["value"]=kv.value();
      }
    }
  }
  return !out.overflowed()&&validate(out.as<JsonVariantConst>());
}
static bool structure(const Bytes& b,Header& h){
  if(b.size()<sizeof(h)||b.size()>sizeof(h)+Config::VAULT_MAX)return false;memcpy(&h,b.data(),sizeof(h));
  return !memcmp(h.magic,"PPS2VAUL",8)&&(h.version==2||h.version==3)&&h.generation>0&&h.length==b.size()-sizeof(h)&&h.length>0;
}
static bool readFile(const char* path,Bytes& b,size_t max){auto f=SPIFFS.open(path,"r");if(!f||f.size()>max){return false;}if(!b.resize(f.size())){f.close();return false;}bool ok=f.read(b.data(),b.size())==b.size();f.close();return ok;}
static bool loadRef(const Journal::Ref& r,Bytes& b,Header* out=nullptr){
  if(r.slot>1||!r.generation||r.length<sizeof(Header)||r.length>sizeof(Header)+Config::VAULT_MAX)return false;
  if(!readFile(slotPath(r.slot),b,sizeof(Header)+Config::VAULT_MAX)||b.size()!=r.length)return false;
  Header h{};Secret<32> digest;
  if(!structure(b,h)||h.generation!=r.generation||!Crypto::hash(b.data(),b.size(),digest.data)||!Crypto::equal(digest.data,r.digest,32))return false;
  if(out)*out=h;return true;
}
struct DiskIO {
  bool writeSlot(uint32_t slot,const uint8_t* p,size_t n){auto f=SPIFFS.open(slotPath(slot),"w");if(!f)return false;bool ok=f.write(p,n)==n;f.flush();f.close();return ok;}
  bool verifySlot(const Journal::Ref& r){Bytes b;return loadRef(r,b);}
  bool writeHead(const Journal::Head& h){return meta.putBytes("head",&h,sizeof(h))==sizeof(h);}
  bool readHead(Journal::Head& h){return meta.getBytesLength("head")==sizeof(h)&&meta.getBytes("head",&h,sizeof(h))==sizeof(h);}
};

#pragma pack(push,1)
struct Nonces {uint32_t magic;uint8_t uuid[16];uint64_t limit;uint8_t digest[32];};
#pragma pack(pop)
static bool nextNonce(const Header& h,uint8_t out[12]){
  if(!Crypto::equal(nonceUUID,h.uuid,16)){nonceNext=nonceLimit=0;memcpy(nonceUUID,h.uuid,16);}
  if(nonceNext==nonceLimit){
    Nonces prior{};bool fresh=status==State::Empty||status==State::Legacy;
    if(!fresh&&meta.isKey("nonce")){
      Secret<32> digest;
      if(meta.getBytesLength("nonce")!=sizeof(prior)||meta.getBytes("nonce",&prior,sizeof(prior))!=sizeof(prior)||prior.magic!=0x334e5050||!prior.limit||!Crypto::equal(prior.uuid,h.uuid,16)||!Crypto::hash(&prior,offsetof(Nonces,digest),digest.data)||!Crypto::equal(digest.data,prior.digest,32))return false;
    }else if(!fresh){
      if(header.version>=3)return false;
      for(uint32_t slot=0;slot<2;slot++){
        Bytes b;Header candidate{};
        if(SPIFFS.exists(slotPath(slot))){
          if(!readFile(slotPath(slot),b,sizeof(Header)+Config::VAULT_MAX)||b.size()<sizeof(Header))return false;
          memcpy(&candidate,b.data(),sizeof(candidate));if(candidate.version>=3)return false;
        }
      }
    }
    uint64_t first=prior.limit?prior.limit:1;
    if(first>UINT64_MAX-256)return false;
    Nonces wanted{};wanted.magic=0x334e5050;memcpy(wanted.uuid,h.uuid,16);wanted.limit=first+256;
    if(!Crypto::hash(&wanted,offsetof(Nonces,digest),wanted.digest))return false;
    meta.putBytes("nonce",&wanted,sizeof(wanted));Nonces actual{};
    if(meta.getBytesLength("nonce")!=sizeof(actual)||meta.getBytes("nonce",&actual,sizeof(actual))!=sizeof(actual)||memcmp(&actual,&wanted,sizeof(actual)))return false;
    nonceNext=first;nonceLimit=wanted.limit;
  }
  uint64_t counter=nonceNext++;memcpy(out,"PPS3",4);
  for(int i=11;i>=4;i--){out[i]=uint8_t(counter);counter>>=8;}return true;
}
static bool wrap(const String& password,const uint8_t* key,Header& h,bool pin){
  auto& w=pin?h.pin:h.master;uint8_t* salt=pin?h.pinSalt:h.masterSalt;Secret<32> kek;Secret<17> aad;Bytes cipher;
  memcpy(aad.data,h.uuid,16);aad.data[16]=pin?'P':'M';
  if(!Crypto::random(salt,16)||!nextNonce(h,w.iv)||!Crypto::derive(password,salt,16,Config::KDF_ROUNDS,kek.data,32)||!Crypto::seal(kek.data,256,w.iv,12,aad.data,17,key,32,cipher,w.tag))return false;
  memcpy(w.cipher,cipher.data(),32);return true;
}
static bool unwrap(const String& password,const Header& h,bool pin,uint8_t* key){
  const auto& w=pin?h.pin:h.master;const uint8_t* salt=pin?h.pinSalt:h.masterSalt;Secret<32> kek;Secret<17> aad;Bytes plain;
  memcpy(aad.data,h.uuid,16);aad.data[16]=pin?'P':'M';
  if(!Crypto::derive(password,salt,16,Config::KDF_ROUNDS,kek.data,32)||!Crypto::open(kek.data,256,w.iv,12,aad.data,17,w.cipher,32,plain,w.tag))return false;
  memcpy(key,plain.data(),32);return true;
}
static bool decode(const Bytes& b,const Header& h,const uint8_t* key,SecureJson& doc){
  Secret<32> payloadKey;
  if(h.version==3){if(!Crypto::subkey(key,"PPS v3 payload",payloadKey.data))return false;}else memcpy(payloadKey.data,key,32);
  Bytes plain;if(!Crypto::open(payloadKey.data,256,h.iv,12,&h,offsetof(Header,tag),b.data()+sizeof(h),h.length,plain,h.tag))return false;
  return deserializeChecked(doc,plain.data(),plain.size())&&validate(doc.as<JsonVariantConst>());
}
bool begin(){
  PpsMemory::Attempt memory;last=Outcome::Ok;
  lock();meta.end();head={};header={};nonceNext=nonceLimit=0;wipe(nonceUUID,sizeof(nonceUUID));mounted=SPIFFS.begin(false);
  if(!mounted){status=State::FsError;return failure(Outcome::Storage);}
  if(!meta.begin("ppsvault",false))return damaged();
  if(meta.isKey("head")){
    DiskIO io;Bytes b;if(!io.readHead(head)||head.magic!=Journal::MAGIC)return damaged();
    status=State::Locked;if(!loadRef(head.current,b,&header))return readFailure(memory);return true;
  }
  if(SPIFFS.exists(slotPath(0))||SPIFFS.exists(slotPath(1)))return damaged();
  if(!EEPROM.begin(128))return damaged();bool oldKey=false;
  for(int i=0;i<16;i++)oldKey|=EEPROM.read(i)!=0xff;EEPROM.end();
  status=(SPIFFS.exists("/passwords.enc")||oldKey)?State::Legacy:State::Empty;return true;
}
bool unlock(const String& password,bool byPin){
  PpsMemory::Attempt memory;last=Outcome::Ok;
  if(status!=State::Locked&&status!=State::Unlocked)return failure(Outcome::Unavailable);
  Bytes b;Header h;Secret<32> key;SecureJson doc(Config::JSON_CAPACITY);
  if(!loadRef(head.current,b,&h))return readFailure(memory);
  if(!unwrap(password,h,byPin,key.data))return failure(memory.failed()?Outcome::NoMemory:Outcome::Credentials);
  if(!decode(b,h,key.data,doc))return readFailure(memory);
  memcpy(dataKey.data,key.data,32);header=h;status=State::Unlocked;return true;
}
bool read(SecureJson& doc){
  ReadTiming timing;
  PpsMemory::Attempt memory;last=Outcome::Ok;doc.clear();
  if(status!=State::Unlocked)return failure(Outcome::Unavailable);
  Bytes b;Header h;
  if(!loadRef(head.current,b,&h)||!decode(b,h,dataKey.data,doc)){doc.clear();return readFailure(memory);}return true;
}
static bool commit(JsonVariantConst doc,Header next,const uint8_t* key){
  PpsMemory::Attempt memory;last=Outcome::Ok;
  if(!validate(doc))return failure(Outcome::Invalid);
  bool hadHead=head.magic==Journal::MAGIC;
  if(hadHead){
    if(head.current.generation==UINT32_MAX)return failure(Outcome::Storage);
    Bytes current;if(!loadRef(head.current,current))return readFailure(memory);
  }
  Bytes plain;Secret<32> payloadKey,expected,actual;
  if(!serializeVariantChecked(doc,plain,Config::VAULT_MAX)||!Crypto::hash(plain.data(),plain.size()-1,expected.data)||!Crypto::subkey(key,"PPS v3 payload",payloadKey.data))return failure(memory.failed()?Outcome::NoMemory:Outcome::Storage);
  size_t n=plain.size()-1;next.version=3;next.generation=hadHead?head.current.generation+1:1;next.length=n;
  Bytes blob(sizeof(next)+n);if(!blob.valid())return failure(Outcome::NoMemory);
  if(!nextNonce(next,next.iv)||!Crypto::sealInto(payloadKey.data,256,next.iv,12,&next,offsetof(Header,tag),plain.data(),n,blob.data()+sizeof(next),next.tag))return failure(memory.failed()?Outcome::NoMemory:Outcome::Storage);
  memcpy(blob.data(),&next,sizeof(next));
  if(!Crypto::open(payloadKey.data,256,next.iv,12,&next,offsetof(Header,tag),blob.data()+sizeof(next),n,plain,next.tag)||!Crypto::hash(plain.data(),plain.size(),actual.data)||!Crypto::equal(actual.data,expected.data,32))return failure(memory.failed()?Outcome::NoMemory:Outcome::Storage);
  plain.clear();Journal::Ref ref{};ref.slot=hadHead?1-head.current.slot:0;ref.generation=next.generation;ref.length=blob.size();
  if(!Crypto::hash(blob.data(),blob.size(),ref.digest))return failure(memory.failed()?Outcome::NoMemory:Outcome::Storage);
  DiskIO io;Journal::Head committed{};
  if(!Journal::publish(io,blob.data(),blob.size(),ref,head,committed)){
    Journal::Head observed{};
    if(memory.failed()&&!hadHead&&!meta.isKey("head")){
      if(SPIFFS.exists(slotPath(ref.slot))&&!SPIFFS.remove(slotPath(ref.slot)))return damaged();return failure(Outcome::NoMemory);
    }
    if(!io.readHead(observed)||memcmp(&observed,&head,sizeof(head)))return damaged();
    return failure(memory.failed()?Outcome::NoMemory:Outcome::Storage);
  }
  head=committed;header=next;last=Outcome::Ok;return true;
}
static bool commit(const SecureJson& doc,Header next,const uint8_t* key){
  if(doc.overflowed()){PpsMemory::failed();return failure(Outcome::NoMemory);}return commit(doc.as<JsonVariantConst>(),next,key);
}
bool save(const SecureJson& doc){return status==State::Unlocked?commit(doc,header,dataKey.data):failure(Outcome::Unavailable);}
bool save(JsonVariantConst doc){return status==State::Unlocked?commit(doc,header,dataKey.data):failure(Outcome::Unavailable);}
String revision(){
  const char* digits="0123456789abcdef";char value[64];size_t n=0;
  for(uint8_t b:header.uuid){value[n++]=digits[b>>4];value[n++]=digits[b&15];}
  value[n++]=':';int written=snprintf(value+n,sizeof(value)-n,"%lu:",static_cast<unsigned long>(header.generation));
  if(written<0||size_t(written)>=sizeof(value)-n){PpsMemory::failed();return String();}n+=size_t(written);
  for(size_t i=0;i<8;i++){uint8_t b=head.current.digest[i];value[n++]=digits[b>>4];value[n++]=digits[b&15];}value[n]=0;
  String out(value);if(out.length()!=n){PpsMemory::failed();wipe(out);}return out;
}
Outcome changeMaster(const String& old,const String& next){
  PpsMemory::Attempt memory;
  if(status!=State::Unlocked)return Outcome::Unavailable;if(!validMaster(next))return Outcome::Invalid;
  Secret<32> key;SecureJson doc(Config::JSON_CAPACITY);
  if(!unwrap(old,header,false,key.data)||!Crypto::equal(key.data,dataKey.data,32))return memory.failed()?Outcome::NoMemory:Outcome::Credentials;
  if(!read(doc))return last;
  Header h=header;if(!wrap(next,dataKey.data,h,false))return memory.failed()?Outcome::NoMemory:Outcome::Storage;
  return commit(doc,h,dataKey.data)?Outcome::Ok:last;
}
Outcome restorePrevious(const String& password){
  PpsMemory::Attempt memory;if(status!=State::Unlocked)return Outcome::Unavailable;
  Secret<32> key;
  if(!unwrap(password,header,false,key.data)||!Crypto::equal(key.data,dataKey.data,32))return memory.failed()?Outcome::NoMemory:Outcome::Credentials;
  if(!head.previous.generation)return Outcome::NoPrevious;
  Bytes blob;Header old{};SecureJson doc(Config::JSON_CAPACITY);
  if(!loadRef(head.previous,blob,&old)||!Crypto::equal(old.uuid,header.uuid,16)||!decode(blob,old,dataKey.data,doc))return memory.failed()?Outcome::NoMemory:Outcome::NoPrevious;
  blob.clear();return commit(doc,header,dataKey.data)?Outcome::Ok:last;
}
bool changePin(const String& next){
  PpsMemory::Attempt memory;last=Outcome::Ok;
  if(status!=State::Unlocked)return failure(Outcome::Unavailable);if(!validPin(next))return failure(Outcome::Invalid);
  SecureJson doc(Config::JSON_CAPACITY);if(!read(doc))return false;
  Header h=header;if(!wrap(next,dataKey.data,h,true))return failure(memory.failed()?Outcome::NoMemory:Outcome::Storage);return commit(doc,h,dataKey.data);
}
static bool loadLegacy(const String& password,SecureJson& doc){
  Bytes settings;if(!readFile("/settings.json",settings,4096))return false;SecureJson conf(6144);
  if(!deserializeChecked(conf,settings.data(),settings.size())||!str(conf["salt"],32,32))return false;
  Secret<16> salt,key,stored;if(!Crypto::unhex(conf["salt"].as<const char*>(),salt.data,16)||!Crypto::derive(password,salt.data,16,50000,key.data,16)||!EEPROM.begin(128))return false;
  for(int i=0;i<16;i++)stored.data[i]=EEPROM.read(i);EEPROM.end();
  if(!Crypto::equal(key.data,stored.data,16))return false;
  if(!SPIFFS.exists("/passwords.enc")){doc.clear();doc["schema"]=2;doc["entries"].to<JsonArray>();return true;}
  Bytes old,plain;if(!readFile("/passwords.enc",old,Config::VAULT_MAX+28)||old.size()<=28)return false;
  if(!Crypto::open(key.data,128,old.data(),12,nullptr,0,old.data()+28,old.size()-28,plain,old.data()+12))return false;
  SecureJson flat(Config::JSON_CAPACITY);
  if(!deserializeChecked(flat,plain.data(),plain.size()))return false;
  return importEntries(flat.as<JsonVariantConst>(),doc,true);
}
bool finishLegacyCleanup(){
  PpsMemory::Attempt memory;if(head.magic!=Journal::MAGIC)return failure(Outcome::Unavailable);
  {Bytes verified;if(!loadRef(head.current,verified))return readFailure(memory);}
  if(!EEPROM.begin(128))return failure(Outcome::Storage);bool dirty=false;
  for(int i=0;i<128;i++)if(EEPROM.read(i)!=0xff){EEPROM.write(i,0xff);dirty=true;}
  bool ok=!dirty||EEPROM.commit();EEPROM.end();if(!ok)return damaged();
  for(const char* p:{"/passwords.enc","/settings.json"})if(SPIFFS.exists(p)&&!SPIFFS.remove(p))ok=false;
  if(!ok)return damaged();return true;
}
bool initialize(const String& password,const String& pin,bool migrate){
  PpsMemory::Attempt memory;last=Outcome::Ok;
  if((migrate?status!=State::Legacy:status!=State::Empty)||!validPin(pin)||(migrate?(password.length()<4||password.length()>128):!validMaster(password)))return failure(Outcome::Invalid);
  SecureJson doc(Config::JSON_CAPACITY);if(migrate){if(!loadLegacy(password,doc))return failure(memory.failed()?Outcome::NoMemory:Outcome::Credentials);}else{doc["schema"]=2;doc["entries"].to<JsonArray>();}
  Header h{};memcpy(h.magic,"PPS2VAUL",8);h.version=3;Secret<32> key;
  if(!Crypto::random(key.data,32)||!Crypto::random(h.uuid,16)||!wrap(password,key.data,h,false)||!wrap(pin,key.data,h,true))return failure(memory.failed()?Outcome::NoMemory:Outcome::Storage);
  if(!commit(doc,h,key.data))return false;
  status=State::Locked;return finishLegacyCleanup();
}
bool recoverPrevious(const String& pin){
  PpsMemory::Attempt memory;last=Outcome::Credentials;
  if(status!=State::Corrupt||!mounted)return false;
  Journal::Ref ref{};Bytes blob;Header h{};
  if(head.magic==Journal::MAGIC){ref=head.previous;if(!loadRef(ref,blob,&h))return failure(memory.failed()?Outcome::NoMemory:Outcome::NoPrevious);}
  else {
    for(uint32_t slot=0;slot<2;slot++){Bytes candidate;Header test;
      if(readFile(slotPath(slot),candidate,sizeof(Header)+Config::VAULT_MAX)&&structure(candidate,test)&&test.generation>ref.generation){
        ref.slot=slot;ref.generation=test.generation;ref.length=candidate.size();if(!Crypto::hash(candidate.data(),candidate.size(),ref.digest))return false;blob=std::move(candidate);h=test;
      }
    }
    if(memory.failed())return failure(Outcome::NoMemory);if(!ref.generation)return failure(Outcome::NoPrevious);
  }
  Secret<32> key;SecureJson doc(Config::JSON_CAPACITY);if(!unwrap(pin,h,true,key.data)||!decode(blob,h,key.data,doc))return failure(memory.failed()?Outcome::NoMemory:Outcome::Credentials);
  Journal::Head next{};next.magic=Journal::MAGIC;next.current=ref;DiskIO io;io.writeHead(next);Journal::Head observed{};
  if(!io.readHead(observed)||memcmp(&next,&observed,sizeof(next)))return false;
  head=next;header=h;status=State::Locked;last=Outcome::Ok;return true;
}
bool reset(bool allowFormat){
  lock();if(!mounted){if(!allowFormat||!SPIFFS.format()||!SPIFFS.begin(false))return false;mounted=true;}
  for(const char* p:{"/pps0.bin","/pps1.bin","/passwords.enc","/settings.json"})if(SPIFFS.exists(p)&&!SPIFFS.remove(p))return damaged();
  meta.end();if(!meta.begin("ppsvault",false)||!meta.clear()||!EEPROM.begin(128))return damaged();
  for(int i=0;i<128;i++)EEPROM.write(i,0xff);bool ok=EEPROM.commit();EEPROM.end();if(!ok)return damaged();
  head={};header={};nonceNext=nonceLimit=0;wipe(nonceUUID,sizeof(nonceUUID));status=State::Empty;return true;
}
}
