#include "cjks/hex.h"

char cjks_v2a(int c) {
    return cjks_hex_chars[c];
}

int cjks_hex(char *dest, const uchar *src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        *dest++ = cjks_v2a((src[i] >> 4) & 0x0F);
        *dest++ = cjks_v2a((src[i]) & 0x0F);
    }
    return (int)(len * 2);
}