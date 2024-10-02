#ifndef CJKS_SPRING_H
#define CJKS_SPRING_H

#include <stddef.h>
#include <openssl/types.h>
#include <openssl/err.h>
#include <cjks/utl.h>
#include <cjks/bits.h>
#include <cjks/lib.h>

CJKS_DLL int cjks_spring_decrypt(EVP_PKEY *pkey, unsigned char *str, size_t len);

#endif