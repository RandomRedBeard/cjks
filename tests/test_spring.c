#include <stdlib.h>
#include <string.h>
#include <iconv.h>
#include <cjks/io.h>
#include <cjks/spring.h>
#include <cjks/cjks.h>
#include "test_base.h"

void test_decrypt() {
    cjks_buf pk_buf = CJKS_BUF_INIT;
    cjks_read_from_res("/d.key", &pk_buf);
    pk_buf.len = cjks_b64decode(pk_buf.buf, pk_buf.buf, pk_buf.len);
    printf("%zu\n", pk_buf.len);

    assert(pk_buf.len != 0);

    cjks_buf es_buf = CJKS_BUF_INIT;
    cjks_read_from_res("/estring", &es_buf);

    assert(es_buf.len != 0);

    const uchar* pkey = pk_buf.buf;
    EVP_PKEY* pk = d2i_AutoPrivateKey(NULL, &pkey, pk_buf.len);
    assert(pk);

    int i = cjks_spring_decrypt(pk, es_buf.buf, es_buf.len, es_buf.buf);
    assert(strncmp("asd", es_buf.buf, i) == 0);

    EVP_PKEY_free(pk);
    cjks_buf_clear(&pk_buf);
    cjks_buf_clear(&es_buf);
}

void test_jks_decrypt() {
    char kp[128] = CJKS_RES_DIR;
    strcat(kp, "/keystore");

    cjks_buf es_buf = CJKS_BUF_INIT;
    cjks_read_from_res("/estring", &es_buf);

    FILE* fp = fopen(kp, "rb");
    assert(fp);

    cjks_io* io = cjks_io_fs_new(fp);
    cjks* jks = cjks_parse_ex(io, "changeit", sizeof("changeit") - 1, "US-ASCII");
    assert(jks);
    cjks* mk = cjks_get(jks, "mytestkey");
    assert(mk && mk->tag == CJKS_PRIVATE_KEY_TAG);

    EVP_PKEY* pk = cjks_2evp(mk->pk);
    int i = cjks_spring_decrypt(pk, es_buf.buf, es_buf.len, es_buf.buf);
    assert(strncmp("asd", es_buf.buf, i) == 0);

    cjks_io_close(io);
    EVP_PKEY_free(pk);
    cjks_buf_clear(&es_buf);
    cjks_io_fs_free(io);
    cjks_free(jks);
}

void test_jks_decrypt2() {
    cjks_buf es_buf = CJKS_BUF_INIT;
    cjks_read_from_res("/estring", &es_buf);

    FILE* fp = cjks_fp_from_res("/keystore");
    assert(fp);

    cjks_io* io = cjks_io_fs_new(fp);
    cjks* jks = cjks_parse_ex(io, "changeit", sizeof("changeit") - 1, "US-ASCII");
    assert(jks);
    cjks* mk = cjks_get(jks, "mytestkey");
    EVP_PKEY* pk = cjks_2evp2(mk);
    assert(pk);

    int i = cjks_spring_decrypt(pk, es_buf.buf, es_buf.len, es_buf.buf);
    assert(strncmp("asd", es_buf.buf, i) == 0);

    cjks_io_close(io);
    EVP_PKEY_free(pk);
    cjks_buf_clear(&es_buf);
    cjks_io_fs_free(io);
    cjks_free(jks);
}


void test_jks_decrypt3() {
    char kp[128] = CJKS_RES_DIR;
    strcat(kp, "/keystore");

    cjks_buf es_buf = CJKS_BUF_INIT;
    cjks_read_from_res("/estring", &es_buf);

    cjks* jks = cjks_parse_ex2(kp, "changeit", sizeof("changeit") - 1, "US-ASCII");
    assert(jks);
    cjks* mk = cjks_get(jks, "mytestkey");

    int i = cjks_spring_decrypt2(mk, es_buf.buf, es_buf.len, es_buf.buf);
    assert(strncmp("asd", es_buf.buf, i) == 0);

    cjks_buf_clear(&es_buf);
    cjks_free(jks);
}

CJKS_TESTS_ST
    CJKS_TEST(test_decrypt)
    CJKS_TEST(test_jks_decrypt)
    CJKS_TEST(test_jks_decrypt2)
    CJKS_TEST(test_jks_decrypt3)
CJKS_TESTS_END
