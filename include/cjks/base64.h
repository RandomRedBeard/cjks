#ifndef CJKS_BASE64_H
#define CJKS_BASE64_H

#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include <cjks/bits.h>
#include <cjks/lib.h>

static const char CJKS_BASE64_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

typedef struct cjks_b64_st cjks_b64_t;

struct cjks_b64_vt {
    int (*update)(cjks_b64_t* b, const void* src, size_t len, void* dst);
    int (*final)(cjks_b64_t* b, void* dst);
};

struct cjks_b64_st {
    uint32 b;
    uint8 i, p;
    struct cjks_b64_vt* vt;
};

CJKS_DLL char cjks_b64i(char c);

CJKS_DLL cjks_b64_t* cjks_b64_encoder();
CJKS_DLL cjks_b64_t* cjks_b64_decoder();
CJKS_DLL void cjks_b64_free(cjks_b64_t* b);

CJKS_DLL int cjks_b64_update(cjks_b64_t* b, const void* src, size_t len, void* dst);
CJKS_DLL int cjks_b64_final(cjks_b64_t* b, void* dst);

CJKS_DLL int cjks_b64decode(uchar *dest, const uchar *src, size_t len);
CJKS_DLL int cjks_b64encode(uchar *dest, const uchar *src, size_t len);

#endif
