#ifndef PPS_MEMORY_H
#define PPS_MEMORY_H
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <mbedtls/platform_util.h>
#ifdef ARDUINO_ARCH_ESP32
#include <esp_heap_caps.h>
#endif
namespace PpsMemory {
inline std::atomic<uint32_t> failures{0};
inline void failed(){failures.fetch_add(1,std::memory_order_relaxed);}
struct Attempt {uint32_t start=failures.load(std::memory_order_relaxed);bool failed()const{return start!=failures.load(std::memory_order_relaxed);}};
#ifdef PPS_MEMORY_TEST
inline void* (*allocateHook)(size_t)=std::malloc;
inline void (*releaseHook)(void*)=std::free;
#endif
inline void* allocate(size_t n){
#ifdef ARDUINO_ARCH_ESP32

  constexpr size_t reserve=16384;
  size_t available=heap_caps_get_free_size(MALLOC_CAP_8BIT);
  if(n>available||available-n<reserve||heap_caps_get_largest_free_block(MALLOC_CAP_8BIT)<n){failed();return nullptr;}
#endif
#ifdef PPS_MEMORY_TEST
  void* p=allocateHook(n);
#else
  void* p=std::malloc(n);
#endif
  if(!p)failed();return p;
}
inline void release(void* p){
#ifdef PPS_MEMORY_TEST
  releaseHook(p);
#else
  std::free(p);
#endif
}
}

class Bytes {
  uint8_t* p_=nullptr;size_t size_=0,capacity_=0;bool valid_=true;
  inline static uint8_t empty_[1]{};
 public:
  Bytes()=default;explicit Bytes(size_t n){resize(n);}
  Bytes(const Bytes&)=delete;Bytes& operator=(const Bytes&)=delete;
  Bytes(Bytes&& other)noexcept{swap(other);}
  Bytes& operator=(Bytes&& other)noexcept{if(this!=&other){clear();swap(other);}return *this;}
  ~Bytes(){clear();}
  bool valid()const{return valid_;}size_t size()const{return size_;}bool empty()const{return size_==0;}
  uint8_t* data(){return p_?p_:empty_;}const uint8_t* data()const{return p_?p_:empty_;}
  uint8_t* begin(){return data();}const uint8_t* begin()const{return data();}
  uint8_t* end(){return data()+size_;}const uint8_t* end()const{return data()+size_;}
  uint8_t& operator[](size_t i){return data()[i];}const uint8_t& operator[](size_t i)const{return data()[i];}
  void swap(Bytes& other)noexcept{std::swap(p_,other.p_);std::swap(size_,other.size_);std::swap(capacity_,other.capacity_);std::swap(valid_,other.valid_);}
  bool resize(size_t n){
    if(n<=capacity_){if(n<size_)mbedtls_platform_zeroize(data()+n,size_-n);else if(n>size_)memset(data()+size_,0,n-size_);size_=n;valid_=true;return true;}
    auto next=static_cast<uint8_t*>(PpsMemory::allocate(n));if(!next){valid_=false;return false;}
    if(size_)memcpy(next,data(),size_);memset(next+size_,0,n-size_);
    if(p_){mbedtls_platform_zeroize(p_,capacity_);PpsMemory::release(p_);}p_=next;size_=capacity_=n;valid_=true;return true;
  }
  bool assign(size_t n,uint8_t value){if(!resize(n))return false;if(n)memset(data(),value,n);return true;}
  bool assign(const uint8_t* first,const uint8_t* last){size_t n=size_t(last-first);if(!resize(n))return false;if(n)memcpy(data(),first,n);return true;}
  void clear(){if(p_){mbedtls_platform_zeroize(p_,capacity_);PpsMemory::release(p_);}p_=nullptr;size_=capacity_=0;valid_=true;}
  bool operator==(const Bytes& b)const{return size_==b.size_&&(!size_||!memcmp(data(),b.data(),size_));}bool operator!=(const Bytes& b)const{return !(*this==b);}
};
#endif
