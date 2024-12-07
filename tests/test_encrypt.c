
#include <cjks/cjks.h>
#include <private/debug.h>

#include "test_base.h"

void test_decrpyt_dig() {
    const unsigned char b64password[] = "AGMAaABhAG4AZwBlAGkAdA==";

    char ksp[128];
    memcpy(ksp, CJKS_RES_DIR, sizeof(CJKS_RES_DIR));
    strcat(ksp, "/dig");

    cjks_buf b64data = CJKS_BUF_INIT;
    cjks_io_read_all(ksp, &b64data);

    unsigned char data[2024];
    int dlen = cjks_b64decode(data, b64data.buf, b64data.len);

    unsigned char password[128];
    int plen = cjks_b64decode(password, b64password, sizeof(b64password) - 1);

    char dest[2048], b64dest[4096];

    int r = cjks_sun_jks_decrypt(data, dest, dlen, password, plen);
    cjks_b64encode(b64dest, dest, dlen - 40);

    memcpy(ksp, CJKS_RES_DIR, sizeof(CJKS_RES_DIR));
    strcat(ksp, "/d.key");

    cjks_buf_clear(&b64data);
    cjks_io_read_all(ksp, &b64data);

    assert(memcmp(b64data.buf, b64dest, b64data.len) == 0);
}

test_st tests[] = {
    {"decrypt_dig", test_decrpyt_dig},
    {NULL, NULL}
};

int main() {
    cjks_run_tests(tests);
    return 0;
}