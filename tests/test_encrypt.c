
#include <cjks/cjks.h>
#include <private/debug.h>

#include "test_base.h"

const unsigned char b64password[] = "AGMAaABhAG4AZwBlAGkAdA==";

void test_decrpyt_dig() {
    char ksp[128];
    memcpy(ksp, CJKS_RES_DIR, sizeof(CJKS_RES_DIR));
    strcat(ksp, "/dig");

    cjks_buf b64data = CJKS_BUF_INIT;
    cjks_io_read_all(ksp, &b64data);

    unsigned char data[2024];
    int dlen = cjks_b64decode(data, b64data.buf, b64data.len);

    cjks_b64_print(data, SHA_DIGEST_LENGTH);

    unsigned char password[128];
    int plen = cjks_b64decode(password, b64password, sizeof(b64password) - 1);

    unsigned char dest[2048], b64dest[4096];

    int r = cjks_sun_jks_decrypt(data, dest, dlen, password, plen);
    cjks_b64encode(b64dest, dest, dlen - 40);

    memcpy(ksp, CJKS_RES_DIR, sizeof(CJKS_RES_DIR));
    strcat(ksp, "/d.key");

    cjks_buf_clear(&b64data);
    cjks_io_read_all(ksp, &b64data);

    assert(memcmp(b64data.buf, b64dest, b64data.len) == 0);

    cjks_buf_clear(&b64data);

}

void test_encrypt_dig() {
    const unsigned char b64iv[] = "24Zy9qgZlnJBNMMDpOEXDIEBJas=";

    unsigned char iv[SHA_DIGEST_LENGTH];
    cjks_b64decode(iv, b64iv, sizeof(b64iv) - 1);

    unsigned char password[128];
    int plen = cjks_b64decode(password, b64password, sizeof(b64password) - 1);

    char ksp[128];
    memcpy(ksp, CJKS_RES_DIR, sizeof(CJKS_RES_DIR));
    strcat(ksp, "/d.key");

    cjks_buf b64data = CJKS_BUF_INIT;
    cjks_io_read_all(ksp, &b64data);

    unsigned char data[2024];
    int dlen = cjks_b64decode(data, b64data.buf, b64data.len);

    unsigned char dest[2048], fdest[4096], b64fdest[4096];
    memcpy(fdest, iv, SHA_DIGEST_LENGTH);

    cjks_sun_jks_crypt(data, dest, dlen, iv, password, plen);

    memcpy(fdest + SHA_DIGEST_LENGTH, dest, dlen);
    cjks_sha1(fdest + SHA_DIGEST_LENGTH + dlen, 2, password, (size_t)plen, data, (size_t)dlen);

    int b64len = cjks_b64encode(b64fdest, fdest, SHA_DIGEST_LENGTH + dlen + SHA_DIGEST_LENGTH);
    printf("%.*s\n", b64len, b64fdest);

    memcpy(ksp, CJKS_RES_DIR, sizeof(CJKS_RES_DIR));
    strcat(ksp, "/dig");

    cjks_buf_clear(&b64data);
    cjks_io_read_all(ksp, &b64data);

    printf("%d - %d\n", b64data.len, b64len);

    assert(memcmp(b64fdest, b64data.buf, b64data.len) == 0);

    cjks_buf_clear(&b64data);

}

test_st tests[] = {
    {"decrypt_dig", test_decrpyt_dig},
    {"encrypt_dig", test_encrypt_dig},
    {NULL, NULL}
};

int main() {
    cjks_run_tests(tests);
    return 0;
}