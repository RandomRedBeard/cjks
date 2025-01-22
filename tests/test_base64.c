#include <cjks/bits.h>
#include <cjks/base64.h>

#include "test_base.h"

int main() {
    cjks_b64_t* b = cjks_b64_decoder();

    const char src1[] = "aGVsbG";
    const char src2[] = "9oZWxsbw==";
    uchar dest[16];
    int i = cjks_b64_update(b, src1, sizeof(src1) - 1, dest);
    i += cjks_b64_update(b, src2, sizeof(src2) - 1, dest + i);
    printf("%.*s\n", i, dest);
}
