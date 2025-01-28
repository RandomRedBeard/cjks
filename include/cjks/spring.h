#ifndef CJKS_SPRING_H
#define CJKS_SPRING_H

#include <stddef.h>
#include <openssl/ossl_typ.h>
#include <openssl/err.h>
#include <cjks/base64.h>
#include <cjks/hex.h>
#include <cjks/bits.h>
#include <cjks/lib.h>
#include <cjks/cjks.h>

static const uchar CJKS_SPRING_SALT[] = { 0xde, 0xad, 0xbe, 0xef };

CJKS_DLL int cjks_spring_decrypt(EVP_PKEY* pkey, uchar* src, size_t slen, uchar* dst);
CJKS_DLL int cjks_spring_decrypt2(cjks* jks, uchar* src, size_t slen, uchar* dst);

#endif
