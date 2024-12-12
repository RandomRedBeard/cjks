#ifndef CJKS_SPRING_H
#define CJKS_SPRING_H

#include <stddef.h>
#include <openssl/ossl_typ.h>
#include <openssl/err.h>
#include <cjks/utl.h>
#include <cjks/bits.h>
#include <cjks/lib.h>
#include <cjks/cjks.h>

CJKS_DLL int cjks_spring_decrypt(EVP_PKEY *pkey, uchar *src, size_t slen, unsigned char* dst);
CJKS_DLL int cjks_spring_decrypt2(cjks* jks, uchar *src, size_t slen, unsigned char* dst);

#endif
