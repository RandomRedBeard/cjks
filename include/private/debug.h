#ifndef CJKS_DEBUG_H
#define CJKS_DEBUG_H

#include <stdio.h>
#include <stdlib.h>

#include <cjks/utl.h>

static void cjks_b64_print(const unsigned char* v, size_t len) {
    int l = (int)(((len + 2)/ 3.0) * 4.0);
    l += (l / 64) + 1;
    unsigned char* dest = (unsigned char*)malloc(l);
    int i = cjks_b64encode(dest, v, len);
    if (i < 0) {
        perror("Failed to b64 data");
        free(dest);
        return;
    }
    *(dest + i) = 0;
    printf("%s\n", dest);
    free(dest);
}

#endif