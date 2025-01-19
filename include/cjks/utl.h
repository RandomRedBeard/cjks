#ifndef CJKS_UTL_H
#define CJKS_UTL_H


#include <string.h>
#include <stdarg.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <cjks/lib.h>
#include <cjks/bits.h>

CJKS_DLL int cjks_sha1(void* out, int n, ...);
CJKS_DLL int cjks_vsha1(void* out, int n, va_list args);
CJKS_DLL int cjks_sha1_cmp(const void* sha1, int n, ...);

#endif
