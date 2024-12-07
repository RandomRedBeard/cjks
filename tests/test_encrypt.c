
#include <cjks/cjks.h>
#include <private/debug.h>

#include "test_base.h"

unsigned char b64password[] = "AGMAaABhAG4AZwBlAGkAdA==";

int main() {
    char ksp[128];
    memcpy(ksp, CJKS_RES_DIR, sizeof(CJKS_RES_DIR));
    strcat(ksp, "/dig");

    cjks_buf b64data = CJKS_BUF_INIT;
    cjks_io_read_all(ksp, &b64data);

    unsigned char data[2024];
    int dlen = cjks_b64decode(data, b64data.buf, b64data.len);

    unsigned char password[128];
    int plen = cjks_b64decode(password, b64password, sizeof(b64password) - 1);

    char dest[2048], *pkey_ptr = dest;

    int r = cjks_sun_jks_decrypt(data, dest, dlen, password, plen);
    printf("%d\n", r);

    cjks_b64_print(dest, dlen - 40);

    return 0;
}