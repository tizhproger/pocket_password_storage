#ifndef PPS_MBEDTLS_COMPAT_H
#define PPS_MBEDTLS_COMPAT_H
#include <cstddef>
#include <mbedtls/version.h>
#include <mbedtls/sha256.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/oid.h>
#if MBEDTLS_VERSION_MAJOR != 2 && MBEDTLS_VERSION_MAJOR != 3
#error "PPS crypto adapters support Mbed TLS 2/3; review a new major API."
#endif
namespace PpsMbedTls {
using Rng=int (*)(void*,unsigned char*,size_t);
inline int sha256(const unsigned char* p,size_t n,unsigned char out[32]){
#if MBEDTLS_VERSION_MAJOR >= 3
  return mbedtls_sha256(p,n,out,0);
#else
  return mbedtls_sha256_ret(p,n,out,0);
#endif
}
inline int parseKey(mbedtls_pk_context* key,const unsigned char* der,size_t n,Rng rng,void* ctx){
#if MBEDTLS_VERSION_MAJOR >= 3
  return mbedtls_pk_parse_key(key,der,n,nullptr,0,rng,ctx);
#else
  (void)rng;(void)ctx;return mbedtls_pk_parse_key(key,der,n,nullptr,0);
#endif
}
inline int checkPair(const mbedtls_pk_context* pub,const mbedtls_pk_context* key,Rng rng,void* ctx){
#if MBEDTLS_VERSION_MAJOR >= 3
  return mbedtls_pk_check_pair(pub,key,rng,ctx);
#else
  (void)rng;(void)ctx;return mbedtls_pk_check_pair(pub,key);
#endif
}
inline int setSerial(mbedtls_x509write_cert* cert,unsigned char* bytes,size_t n){
#if MBEDTLS_VERSION_NUMBER >= 0x03060000
  return mbedtls_x509write_crt_set_serial_raw(cert,bytes,n);
#else
  mbedtls_mpi serial;mbedtls_mpi_init(&serial);
  int rc=mbedtls_mpi_read_binary(&serial,bytes,n);
  if(!rc)rc=mbedtls_x509write_crt_set_serial(cert,&serial);
  mbedtls_mpi_free(&serial);return rc;
#endif
}

#if MBEDTLS_VERSION_MAJOR >= 3
#define PPS_OLD_FIELD(name) MBEDTLS_PRIVATE(name)
#else
#define PPS_OLD_FIELD(name) name
#endif
template<class Key> auto group(const Key* k,int)->decltype(mbedtls_ecp_keypair_get_group_id(k)){return mbedtls_ecp_keypair_get_group_id(k);}
template<class Key> mbedtls_ecp_group_id group(const Key* k,long){return k->PPS_OLD_FIELD(grp).id;}
template<class Cert> auto isCa(const Cert* c,int)->decltype(mbedtls_x509_crt_get_ca_istrue(c)){return mbedtls_x509_crt_get_ca_istrue(c);}
template<class Cert> int isCa(const Cert* c,long){return c->PPS_OLD_FIELD(ca_istrue)?1:0;}
template<class Cert> auto hasExtension(const Cert* c,int t,int)->decltype(mbedtls_x509_crt_has_ext_type(c,t)){return mbedtls_x509_crt_has_ext_type(c,t);}
template<class Cert> int hasExtension(const Cert* c,int t,long){return c->PPS_OLD_FIELD(ext_types)&t;}
#undef PPS_OLD_FIELD
inline bool p256(const mbedtls_pk_context& key){return mbedtls_pk_can_do(&key,MBEDTLS_PK_ECDSA)&&group(mbedtls_pk_ec(key),0)==MBEDTLS_ECP_DP_SECP256R1;}
inline bool signedWithSha256(const mbedtls_x509_crt& c){
  mbedtls_md_type_t md;mbedtls_pk_type_t pk;
  return mbedtls_oid_get_sig_alg(&c.sig_oid,&md,&pk)==0&&md==MBEDTLS_MD_SHA256&&pk==MBEDTLS_PK_ECDSA;
}
}
#endif
