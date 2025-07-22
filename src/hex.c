#include "cjks/hex.h"

char cjks_v2a(int c) {
    return CJKS_HEX_CHARS[c];
}

int cjks_hex(char *dest, const uchar *src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        *dest++ = cjks_v2a(src[i] >> 4);
        *dest++ = cjks_v2a((src[i]) & 0x0F);
    }
    return (int)(len * 2);
}
