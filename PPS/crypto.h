#ifndef PPS_PROJECT_CRYPTO_H_INCLUDED
#define PPS_PROJECT_CRYPTO_H_INCLUDED

#include "secure.h"
namespace Crypto {
bool begin();
void radioEntropy(bool active);
bool random(void*,size_t);
int rng(void*,unsigned char*,size_t);
bool hash(const void*,size_t,uint8_t out[32]);
bool subkey(const uint8_t key[32],const char* domain,uint8_t out[32]);
using Progress=void(*)(uint32_t,uint32_t);
void setProgress(Progress);
bool equal(const void*,const void*,size_t);
String hex(const void*,size_t);
bool unhex(const String&,void*,size_t);
bool unhex(const char*,void*,size_t);
String token(size_t n=32);
bool derive(const String&,const uint8_t*,size_t,uint32_t,uint8_t*,size_t);
bool sealInto(const uint8_t*,int,const uint8_t*,size_t,const void*,size_t,const uint8_t*,size_t,uint8_t*,uint8_t[16]);
bool seal(const uint8_t*,int,const uint8_t*,size_t,const void*,size_t,const uint8_t*,size_t,Bytes&,uint8_t[16]);
bool open(const uint8_t*,int,const uint8_t*,size_t,const void*,size_t,const uint8_t*,size_t,Bytes&,const uint8_t[16]);
}

#endif
