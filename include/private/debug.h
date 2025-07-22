#ifndef CJKS_DEBUG_H
#define CJKS_DEBUG_H

#include <stdio.h>
#include <cjks/base64.h>
#include <cjks/hex.h>

/**
 * @brief Print bytes as they exist in memory
 * 
 * @param buf 
 * @param l 
 */
static void showbits(void* buf, int l) {
    uchar* c = buf;
    for (int i = 0; i < l; i++) {
        uchar byte = c[i];
        for (int j = 0; j < 8; j++) {
            if (byte >> (7 - j) & 1) {
                putchar('1');
            } else {
                putchar('0');
            }
        }
        putchar(' ');
    }
    putchar('\n');
}

static void b64print(const uchar* buf, size_t len) {
    size_t plen = ((len * 4.0) / 3) + 3;
    uchar* dst = malloc(plen);
    int blen = cjks_b64encode(dst, buf, len);
    printf("%.*s\n", blen, (char*)dst);
    free(dst);
}

static void hexprint(const uchar* buf, size_t len) {
    char* dst = malloc(len * 2);
    cjks_hex(dst, buf, len);
    printf("%.*s\n", (int)(len * 2), dst);
    free(dst);
}

#endif