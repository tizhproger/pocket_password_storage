#ifndef PPS_PROJECT_SECURE_H_INCLUDED
#define PPS_PROJECT_SECURE_H_INCLUDED

#include <Arduino.h>
#include "pps_json_config.h"
#include <cstddef>
#include <cstdint>
#include <limits>
#include <mbedtls/platform_util.h>
#include <algorithm>
#include "pps_memory.h"
#include <cstring>
#include <cstdlib>
#include "json_syntax.h"
inline void wipe(void* p,size_t n){if(p&&n)mbedtls_platform_zeroize(p,n);}
inline void wipe(String& s){if(s.length())wipe(&s[0],s.length());s="";}
template<size_t N> struct Secret { uint8_t data[N]{}; ~Secret(){wipe(data,N);} };
struct alignas(void*) alignas(double) alignas(uint64_t) JsonAllocationHeader {size_t size;};
#if ARDUINOJSON_VERSION_MAJOR == 7
class JsonSecureAllocator final : public ArduinoJson::Allocator {
  size_t limit_,used_=0;
 public:
  explicit JsonSecureAllocator(size_t limit):limit_(limit){}
  size_t used()const{return used_;}
  size_t limit()const{return limit_;}
  void* allocate(size_t n) override {
    if(!n)return nullptr;
    if(n>std::numeric_limits<size_t>::max()-sizeof(JsonAllocationHeader)){PpsMemory::failed();return nullptr;}
    size_t charge=n+sizeof(JsonAllocationHeader);if(charge>limit_-used_){PpsMemory::failed();return nullptr;}
    auto h=static_cast<JsonAllocationHeader*>(PpsMemory::allocate(charge));if(!h)return nullptr;
    h->size=n;used_+=charge;return h+1;
  }
  void deallocate(void* p) override {
    if(!p)return;auto h=static_cast<JsonAllocationHeader*>(p)-1;
    size_t charge=h->size+sizeof(*h);used_-=charge;wipe(h,charge);PpsMemory::release(h);
  }
  void* reallocate(void* p,size_t n) override {
    if(!p)return allocate(n);if(!n){deallocate(p);return nullptr;}
    auto h=static_cast<JsonAllocationHeader*>(p)-1;
    if(n==h->size)return p;
    if(n<h->size){
      wipe(static_cast<uint8_t*>(p)+n,h->size-n);
      void* q=allocate(n);if(!q)return p;
      memcpy(q,p,n);deallocate(p);return q;
    }
    void* q=allocate(n);if(!q)return nullptr;
    memcpy(q,p,h->size);deallocate(p);return q;
  }
};
struct SecureJsonOwner {JsonSecureAllocator storage;explicit SecureJsonOwner(size_t n):storage(n){}};
class SecureJson : private SecureJsonOwner, public ArduinoJson::JsonDocument {
 public:
  explicit SecureJson(size_t n):SecureJsonOwner(n),ArduinoJson::JsonDocument(&storage){}
  SecureJson(const SecureJson&)=delete;SecureJson(SecureJson&&)=delete;
  SecureJson& operator=(const SecureJson&)=delete;SecureJson& operator=(SecureJson&&)=delete;
  size_t allocatedBytes()const{return storage.used();}
  size_t allocationLimit()const{return storage.limit();}
};
#endif
inline JsonObject jsonAddObject(JsonArray a){return a.add<JsonObject>();}

inline bool deserializeChecked(SecureJson& doc,const uint8_t* data,size_t n,bool terminated=false){
  if(terminated&&n&&data[n-1]==0)n--;
  return JsonSyntax(data,n).valid()
    && !deserializeJson(doc,data,n,DeserializationOption::NestingLimit(8))
    && !doc.overflowed();
}
inline bool serializeVariantChecked(JsonVariantConst value,Bytes& out,size_t limit){
  size_t n=measureJson(value);if(!n||n>limit)return false;
  if(!out.assign(n+1,0))return false;
  if(serializeJson(value,reinterpret_cast<char*>(out.data()),out.size())!=n){out.clear();return false;}return true;
}
inline bool serializeChecked(const SecureJson& doc,Bytes& out,size_t limit){
  if(doc.overflowed()){PpsMemory::failed();return false;}
  return serializeVariantChecked(doc.as<JsonVariantConst>(),out,limit);
}
struct SecretString {
  String value;
  explicit SecretString(const char* s):value(s?s:""){if(s&&value.length()!=strlen(s))PpsMemory::failed();}
  explicit SecretString(String&& s):value(std::move(s)){}
  ~SecretString(){wipe(value);}
  SecretString(const SecretString&)=delete;
  SecretString& operator=(const SecretString&)=delete;
};

#endif
