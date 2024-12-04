#ifndef CJKS_DEBUG_H
#define CJKS_DEBUG_H

#include <stdio.h>
#include <stdlib.h>

#include <cjks/utl.h>

static void cjks_b64_print(const unsigned char* v, size_t len) {
    int l = (len * 4) / 3;
    unsigned char* dest = (unsigned char*)malloc(l);
    int i = cjks_b64encode(dest, v, len);
    *(dest + i) = 0;
    printf("%s\n", dest);
    free(dest);
}

#endif