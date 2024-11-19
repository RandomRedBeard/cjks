#ifndef CJKS_SPRING_H
#define CJKS_SPRING_H

#include <stddef.h>
#include <openssl/ossl_typ.h>
#include <openssl/err.h>
#include <cjks/utl.h>
#include <cjks/bits.h>
#include <cjks/lib.h>

CJKS_DLL int cjks_spring_decrypt(EVP_PKEY *pkey, unsigned char *src, size_t slen, unsigned char* dst);

#endif