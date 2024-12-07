
#include <cjks/cjks.h>
#include <private/debug.h>

#include "test_base.h"

char b64iv[] = "24Zy9qgZlnJBNMMDpOEXDIEBJas=";
unsigned char b64password[] = "AGMAaABhAG4AZwBlAGkAdA==";

int main() {
    char ksp[128];
    memcpy(ksp, CJKS_RES_DIR, sizeof(CJKS_RES_DIR));
    strcat(ksp, "/d.key");

    cjks_buf b64data = CJKS_BUF_INIT;
    cjks_io_read_all(ksp, &b64data);

    unsigned char data[2024];
    int dlen = cjks_b64decode(data, b64data.buf, b64data.len);

    unsigned char password[128];
    int plen = cjks_b64decode(password, b64password, sizeof(b64password) - 1);

    char iv[32], *cptr = iv;
    int ivlen = cjks_b64decode(iv, b64iv, sizeof(b64iv) - 1);

    char dest[2048], *pkey_ptr = dest;

    cjks_keystream(iv, password, plen);

    char *dptr = data;
    char *pkey_end = data + dlen;

    while (dptr != pkey_end) {
        *pkey_ptr++ = *dptr++ ^ *cptr++;

        if (cptr - iv == SHA_DIGEST_LENGTH) {
            cjks_keystream(iv, password, plen);
            cptr = iv;
        }
    }

    cjks_b64_print(dest, dlen);

    return 0;
}