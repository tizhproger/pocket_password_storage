#include "crypto.h"
#include "pps_mbedtls_compat.h"
#include <esp_system.h>
#include <bootloader_random.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <mbedtls/gcm.h>
#include <mbedtls/bignum.h>

namespace Crypto {
static bool result(int rc){
  if(rc<0){int high=(-rc)&0xff80,low=(-rc)&0x7f;
    if(high==-MBEDTLS_ERR_MD_ALLOC_FAILED||high==-MBEDTLS_ERR_CIPHER_ALLOC_FAILED||low==-MBEDTLS_ERR_MPI_ALLOC_FAILED)PpsMemory::failed();
  }return rc==0;
}
static mbedtls_ctr_drbg_context drbg;
static bool ready=false;
static bool entropyActive=false;
void radioEntropy(bool active){entropyActive=active;}
static Progress progress=nullptr;
void setProgress(Progress p){progress=p;}
static int entropy(void*,unsigned char* out,size_t n){if(!entropyActive)return -1;esp_fill_random(out,n);return 0;}
bool begin(){
  if(ready)return true;
  mbedtls_ctr_drbg_init(&drbg);
  bootloader_random_enable();
  entropyActive=true;
  const unsigned char domain[]="PPS vault v2";
  int rc=mbedtls_ctr_drbg_seed(&drbg,entropy,nullptr,domain,sizeof(domain)-1);
  bootloader_random_disable();entropyActive=false;ready=rc==0;
  if(!ready)mbedtls_ctr_drbg_free(&drbg);return ready;
}
int rng(void*,unsigned char* p,size_t n){return ready?mbedtls_ctr_drbg_random(&drbg,p,n):-1;}
bool random(void* p,size_t n){return rng(nullptr,static_cast<unsigned char*>(p),n)==0;}
bool hash(const void* p,size_t n,uint8_t out[32]){return result(PpsMbedTls::sha256(static_cast<const unsigned char*>(p),n,out));}
bool subkey(const uint8_t key[32],const char* domain,uint8_t out[32]){return result(mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),key,32,reinterpret_cast<const uint8_t*>(domain),strlen(domain),out));}
bool equal(const void* a,const void* b,size_t n){const auto x=static_cast<const uint8_t*>(a),y=static_cast<const uint8_t*>(b);uint8_t v=0;for(size_t i=0;i<n;i++)v|=x[i]^y[i];return v==0;}
String hex(const void* p,size_t n){
  String s;if(n>SIZE_MAX/2){PpsMemory::failed();return s;}
#ifdef ARDUINO_ARCH_ESP32
  if(!s.reserve(n*2)){PpsMemory::failed();return s;}
#endif
  const auto b=static_cast<const uint8_t*>(p);const char* digits="0123456789abcdef";
  for(size_t i=0;i<n;i++){s+=digits[b[i]>>4];s+=digits[b[i]&15];}
  if(s.length()!=n*2){PpsMemory::failed();wipe(s);}return s;
}
bool unhex(const char* s,void* p,size_t n){if(!s||n>SIZE_MAX/2||strlen(s)!=n*2)return false;auto b=static_cast<uint8_t*>(p);for(size_t i=0;i<n;i++){int v=0;for(int j=0;j<2;j++){char c=s[i*2+j];int d=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:-1;if(d<0)return false;v=v*16+d;}b[i]=v;}return true;}
bool unhex(const String& s,void* p,size_t n){return unhex(s.c_str(),p,n);}
String token(size_t n){Bytes b(n);return b.valid()&&random(b.data(),n)?hex(b.data(),n):String();}
bool derive(const String& password,const uint8_t* salt,size_t n,uint32_t rounds,uint8_t* out,size_t len){
  if(!rounds||len>32||n>64)return false;
  if(progress)progress(0,rounds);
  mbedtls_md_context_t c;mbedtls_md_init(&c);
  Secret<68> input;memcpy(input.data,salt,n);input.data[n+3]=1;
  Secret<32> u,acc;
  int rc=mbedtls_md_setup(&c,mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),1);
  if(!rc)rc=mbedtls_md_hmac_starts(&c,reinterpret_cast<const uint8_t*>(password.c_str()),password.length());
  if(!rc)rc=mbedtls_md_hmac_update(&c,input.data,n+4);
  if(!rc)rc=mbedtls_md_hmac_finish(&c,u.data);
  memcpy(acc.data,u.data,32);
  for(uint32_t i=1;!rc&&i<rounds;i++){
    rc=mbedtls_md_hmac_reset(&c);
    if(!rc)rc=mbedtls_md_hmac_update(&c,u.data,32);
    if(!rc)rc=mbedtls_md_hmac_finish(&c,u.data);
    if(!rc)for(size_t j=0;j<32;j++)acc.data[j]^=u.data[j];
    if((i&255)==0){if(progress)progress(i,rounds);delay(1);}
  }
  if(!rc)memcpy(out,acc.data,len);mbedtls_md_free(&c);if(progress)progress(rounds,rounds);return result(rc);
}
bool sealInto(const uint8_t* key,int bits,const uint8_t* iv,size_t ivlen,const void* aad,size_t an,const uint8_t* in,size_t n,uint8_t* out,uint8_t tag[16]){
  mbedtls_gcm_context c;mbedtls_gcm_init(&c);int rc=mbedtls_gcm_setkey(&c,MBEDTLS_CIPHER_ID_AES,key,bits);
  if(!rc)rc=mbedtls_gcm_crypt_and_tag(&c,MBEDTLS_GCM_ENCRYPT,n,iv,ivlen,static_cast<const uint8_t*>(aad),an,in,out,16,tag);
  mbedtls_gcm_free(&c);if(rc)wipe(out,n);return result(rc);
}
bool seal(const uint8_t* key,int bits,const uint8_t* iv,size_t ivlen,const void* aad,size_t an,const uint8_t* in,size_t n,Bytes& out,uint8_t tag[16]){
  if(!out.resize(n))return false;
  if(!sealInto(key,bits,iv,ivlen,aad,an,in,n,out.data(),tag)){out.clear();return false;}return true;
}
bool open(const uint8_t* key,int bits,const uint8_t* iv,size_t ivlen,const void* aad,size_t an,const uint8_t* in,size_t n,Bytes& out,const uint8_t tag[16]){
  if(!out.resize(n))return false;
  mbedtls_gcm_context c;mbedtls_gcm_init(&c);int rc=mbedtls_gcm_setkey(&c,MBEDTLS_CIPHER_ID_AES,key,bits);
  if(!rc)rc=mbedtls_gcm_auth_decrypt(&c,n,iv,ivlen,static_cast<const uint8_t*>(aad),an,tag,16,in,out.data());
  mbedtls_gcm_free(&c);if(rc)out.clear();return result(rc);
}
}
