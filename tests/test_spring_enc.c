#include <stdlib.h>
#include <string.h>
#include <iconv.h>
#include <cjks/io.h>
#include <cjks/spring.h>
#include <cjks/cjks.h>
#include "private/debug.h"
#include "test_base.h"

#include <openssl/pem.h>

void test_spring_enc() {
    cjks_buf pk_buf = CJKS_BUF_INIT;
    cjks_read_from_res("/d.key", &pk_buf);
    pk_buf.len = cjks_b64decode(pk_buf.buf, pk_buf.buf, pk_buf.len);
    printf("%zu\n", pk_buf.len);

    const uchar* pkey = pk_buf.buf;
    EVP_PKEY* pk = d2i_AutoPrivateKey(NULL, &pkey, pk_buf.len);
    assert(pk);

    const char c[] = "hello this is thomas from your cars extended warranty";
    char b64_dbuf[4096];
    int b64_len = cjks_spring_encrypt(pk, c, sizeof(c) - 1, b64_dbuf);
    puts("test");
    printf("Config: %.*s\n", b64_len, b64_dbuf);

    b64_len = cjks_spring_decrypt(pk, b64_dbuf, b64_len, b64_dbuf);
    printf("Config: %.*s\n", b64_len, b64_dbuf);
}

void test_lkey() {
    FILE* fp = cjks_fp_from_res("/test.key");
    EVP_PKEY* pk = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    int sz = EVP_PKEY_size(pk);
    printf("pk size %d\n", sz);

    const char c[] = "hello this is thomas from your cars extended warranty";
    char b64_dbuf[4096];
    int b64_len = cjks_spring_encrypt(pk, c, sizeof(c) - 1, b64_dbuf);
    puts("test");
    printf("Config: %.*s\n", b64_len, b64_dbuf);

    b64_len = cjks_spring_decrypt(pk, b64_dbuf, b64_len, b64_dbuf);
    printf("Config: %.*s\n", b64_len, b64_dbuf);
}

CJKS_TESTS_ST
CJKS_TEST(test_spring_enc)
CJKS_TEST(test_lkey)
CJKS_TESTS_END