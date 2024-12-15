#ifndef CJKS_SHA1_H
#define CJKS_SHA1_H

#include <stdlib.h>
#include <string.h>

#include <cjks/bits.h>
#include <cjks/lib.h>

#define cir_ls(i, n) ((i << n) | (i >> (32 - n)))

typedef struct cjks_sha1_st {
    uint32 h[5];
    uint64 len;
    uint32 words[16];
    uint32 i;
} cjks_sha1_t;

CJKS_DLL cjks_sha1_t* cjks_sha1_new();
CJKS_DLL void cjks_sha1_hsh(cjks_sha1_t*);
CJKS_DLL void cjks_sha1_cnsm(cjks_sha1_t*, const uchar* v, uint64 len);
CJKS_DLL void cjks_sha1_cmpl(cjks_sha1_t*);

#endif