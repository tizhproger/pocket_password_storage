#ifndef PPS_PROJECT_PPS_TLS_OVERRIDE_H_INCLUDED
#define PPS_PROJECT_PPS_TLS_OVERRIDE_H_INCLUDED
#define PPS_TLS_TRUST_API 2

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/oid.h>
#include <mbedtls/ecp.h>
#include "pps_mbedtls_compat.h"

#if defined(__has_include)
#if __has_include("pps_tls_certificate.h")
#include "pps_tls_certificate.h"
#define PPS_TLS_COMPILED_CERTIFICATE 1
#endif
#endif

namespace PpsTls {
#ifdef PPS_TLS_COMPILED_CERTIFICATE
static int bootClock(void*, mbedtls_x509_crt*, int, uint32_t* flags) {
  *flags &= ~(MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE);
  return 0;
}

static bool p256(const mbedtls_pk_context& key) {
  return PpsMbedTls::p256(key);
}

static bool expectedNames(const mbedtls_x509_crt& leaf) {
  bool dns = false, ip = false;
  const unsigned char address[] = {192, 168, 4, 1};
  for (const mbedtls_x509_sequence* s = &leaf.subject_alt_names; s; s = s->next) {
    if (s->buf.tag == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 2) && s->buf.len == 9 &&
        !memcmp(s->buf.p, "pps.local", 9)) dns = true;
    else if (s->buf.tag == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 7) && s->buf.len == 4 &&
             !memcmp(s->buf.p, address, 4)) ip = true;
    else return false;
  }
  return dns && ip;
}

template<class Buffer>
bool validateAndSelect(Buffer& certificate, const Buffer& privateKey,
                       const unsigned char* leafDer, size_t leafSize,
                       const unsigned char* rootDer, size_t rootSize, PpsMbedTls::Rng rng, void* rngContext) {
  if (!leafDer || !rootDer || leafSize < 100 || rootSize < 100 ||
      leafSize > 2048 || rootSize > 2048 || privateKey.empty() || privateKey.size() > 2048)
    return false;
  mbedtls_x509_crt leaf, root;
  mbedtls_pk_context key;
  mbedtls_x509_crt_init(&leaf);
  mbedtls_x509_crt_init(&root);
  mbedtls_pk_init(&key);
  bool ok = mbedtls_x509_crt_parse_der(&leaf, leafDer, leafSize) == 0 &&
            mbedtls_x509_crt_parse_der(&root, rootDer, rootSize) == 0 &&
            leaf.raw.len == leafSize && root.raw.len == rootSize &&
            !leaf.next && !root.next && leaf.version == 3 && root.version == 3 &&
            !PpsMbedTls::isCa(&leaf,0) && PpsMbedTls::isCa(&root,0) && p256(leaf.pk) && p256(root.pk) &&
            PpsMbedTls::signedWithSha256(leaf) && PpsMbedTls::signedWithSha256(root) &&
            expectedNames(leaf) &&
            PpsMbedTls::hasExtension(&leaf,MBEDTLS_X509_EXT_BASIC_CONSTRAINTS,0) &&
            PpsMbedTls::hasExtension(&leaf,MBEDTLS_X509_EXT_KEY_USAGE,0) &&
            PpsMbedTls::hasExtension(&leaf,MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE,0) &&
            PpsMbedTls::hasExtension(&root,MBEDTLS_X509_EXT_KEY_USAGE,0) &&
            mbedtls_x509_crt_check_key_usage(&leaf, MBEDTLS_X509_KU_DIGITAL_SIGNATURE) == 0 &&
            mbedtls_x509_crt_check_key_usage(&root, MBEDTLS_X509_KU_KEY_CERT_SIGN) == 0 &&
            mbedtls_x509_crt_check_extended_key_usage(&leaf, MBEDTLS_OID_SERVER_AUTH,
                                                    MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH)) == 0;
  if (ok) ok = PpsMbedTls::parseKey(&key, privateKey.data(), privateKey.size(), rng, rngContext) == 0 &&
               p256(key) && PpsMbedTls::checkPair(&leaf.pk, &key, rng, rngContext) == 0;
  uint32_t flags = 0;
  if (ok) ok = mbedtls_x509_crt_verify(&leaf, &root, nullptr, "pps.local", &flags,
                                     bootClock, nullptr) == 0 && flags == 0;

  if (ok) {
    if constexpr (std::is_same_v<decltype(certificate.assign(leafDer, leafDer + leafSize)), bool>)
      ok = certificate.assign(leafDer, leafDer + leafSize);
    else certificate.assign(leafDer, leafDer + leafSize);
    ok = ok && certificate.size() == leafSize && !memcmp(certificate.data(), leafDer, leafSize);
  }
  mbedtls_pk_free(&key);
  mbedtls_x509_crt_free(&root);
  mbedtls_x509_crt_free(&leaf);
  return ok;
}
#endif

template<class Buffer>
bool selectCertificate(Buffer& certificate, const Buffer& privateKey, PpsMbedTls::Rng rng, void* rngContext) {
#ifdef PPS_TLS_COMPILED_CERTIFICATE
  static_assert(PpsTlsBundle::format == 1, "Unsupported PPS TLS certificate bundle");
  return validateAndSelect(certificate, privateKey,
                           PpsTlsBundle::leaf, sizeof(PpsTlsBundle::leaf),
                           PpsTlsBundle::root, sizeof(PpsTlsBundle::root), rng, rngContext);
#else
  (void)certificate;
  (void)privateKey;(void)rng;(void)rngContext;
  return true;
#endif
}
}

#endif
