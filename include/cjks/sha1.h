#ifndef CJKS_SHA1_H
#define CJKS_SHA1_H

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <cjks/bits.h>
#include <cjks/lib.h>

#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

#define cir_ls(i, n) ((i << n) | (i >> (32 - n)))

typedef struct cjks_sha1_st {
    uint32 h[5];
    uint64 len;
    uint32 words[16];
    uint32 i;
} cjks_sha1_t;

CJKS_DLL cjks_sha1_t* cjks_sha1_new();
CJKS_DLL void cjks_sha1_free(cjks_sha1_t*);
CJKS_DLL void cjks_sha1_hsh(cjks_sha1_t*);
CJKS_DLL void cjks_sha1_cnsm(cjks_sha1_t*, const uchar* v, uint64 len);
CJKS_DLL void cjks_sha1_cmpl(cjks_sha1_t*, uint32 v[5]);

CJKS_DLL int cjks_sha1(void* out, int n, ...);
CJKS_DLL int cjks_vsha1(void* out, int n, va_list args);
CJKS_DLL int cjks_sha1_cmp(const void* sha1, int n, ...);

#endif
