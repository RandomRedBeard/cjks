#include <cjks/bits.h>
#include <cjks/base64.h>

#include "test_base.h"

typedef struct b64_st {
    uint32 b;
    uint8 i, p;
} b64;

int b64_encode_chunk(b64 *b, void *dst) {
    uchar *dptr = dst;
    b->b = cjks_htoni(b->b);
    for (int j = 0; j < b->i + 1; j++) {
        *dptr++ = cjks_base64_chars[b->b >> 26];
        b->b = b->b << 6;
    }
    return dptr - dst;
}

int b64_encode_update(b64 *b, const void *src, size_t len, void *dst) {
    const uchar *psrc = src, *psrce = psrc + len;
    uchar *dptr = dst;
    int j;

    while (psrc != psrce) {
        *(((uchar *)&b->b) + b->i++) = *psrc++;
        if (b->i == 3) {
            dptr += b64_encode_chunk(b, dptr);
            b->i = 0;
            b->b = 0;
        }
    }


    return dptr - dst;
}

int b64_encode_final(b64 *b, void *dst) {
    if (b->i == 0) {
        return 0;
    }

    uchar *dptr = (uchar *)dst + b64_encode_chunk(b, dst);
    b->i = 3 - b->i;
    dptr = (uchar *)memcpy(dptr, "==", b->i) + b->i;

    return dptr - dst;
}

int b64_decode_update(b64 *b, const void *src, size_t len, void *dst) {
    const uchar *psrc = src, *psrce = psrc + len;
    uchar *dptr = dst, cp;
    int j;
    uint32 index;

    while (psrc != psrce) {
        if (*psrc == '\n' || *psrc == '\r') {
            psrc++;
            continue;
        }

        // Expecting pad
        if (b->p > 0 && *psrc != '=') {
            return -1;
        }

        if (*psrc == '=') { // Pad
            if (b->p == 2) {
                return -1;
            }
            b->p++;
        }
        else { // Value
            index = cjks_b64i(*psrc);
            if (index < 0) {
                return -1;
            }
            b->b |= (int)index << (2 + (6 * (4 - b->i++)));
        }

        psrc++;

        if (b->i + b->p == 4) {
            b->b = cjks_ntohi(b->b);
            cp = (b->p == 0 ? 3 : 3 - b->p);
            dptr = (uchar *)memcpy(dptr, &b->b, cp) + cp;
            b->b = 0;
            b->i = 0;
        }
    }

    return dptr - dst;
}

int b64_decode_final(b64 *b, void *dst) {
    if (b->i > 0) {
        return -1;
    }
    return 0;
}

int main() {
    b64 b = {
        0, 0, 0
    };

    const char src1[] = "aGVsbG";
    const char src2[] = "9oZWxsbw==";
    uchar dest[16];
    int i = b64_decode_update(&b, src1, sizeof(src1) - 1, dest);
    i += b64_decode_update(&b, src2, sizeof(src2) - 1, dest + i);
    printf("%.*s\n", i, dest);
}

int mainx() {
    b64 b = { 0, 0 };
    const char src[] = "hello";
    uchar dest[128];
    int i = b64_encode_update(&b, src, sizeof(src) - 1, dest);
    i += b64_encode_update(&b, src, sizeof(src) - 1, dest + i);
    printf("%d\n", i);
    i += b64_encode_final(&b, dest + i);
    printf("%.*s\n", i, dest);

    return 0;
}