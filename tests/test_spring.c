#include <stdlib.h>
#include <string.h>
#include <iconv.h>
#include <cjks/io.h>
#include <cjks/spring.h>
#include <cjks/cjks.h>
#include "test_base.h"

void test_decrypt() {
    char kp[128];
    memcpy(kp, CJKS_RES_DIR, strlen(CJKS_RES_DIR) + 1);
    strcat(kp, "/d.key");
    cjks_buf pk_buf;
    cjks_io_read_all(kp, &pk_buf);
    pk_buf.len = cjks_b64decode(pk_buf.buf, pk_buf.buf, pk_buf.len);

    assert(pk_buf.len != 0);

    char est[128];
    memcpy(est, CJKS_RES_DIR, strlen(CJKS_RES_DIR) + 1);
    strcat(est, "/estring");
    cjks_buf es_buf;
    cjks_io_read_all(est, &es_buf);

    assert(es_buf.len != 0);

    const unsigned char* pkey = pk_buf.buf;
    EVP_PKEY* pk = d2i_AutoPrivateKey(NULL, &pkey, pk_buf.len);
    assert(pk);

    int i = cjks_spring_decrypt(pk, es_buf.buf, es_buf.len);
    assert(strncmp("asd", es_buf.buf, i) == 0);

    EVP_PKEY_free(pk);
    cjks_buf_clear(&pk_buf);
    cjks_buf_clear(&es_buf);
}

void test_jks_decrypt() {
    char kp[128];
    memcpy(kp, CJKS_RES_DIR, strlen(CJKS_RES_DIR) + 1);
    strcat(kp, "/keystore");

    char est[128];
    memcpy(est, CJKS_RES_DIR, strlen(CJKS_RES_DIR) + 1);
    strcat(est, "/estring");
    cjks_buf es_buf;
    cjks_io_read_all(est, &es_buf);

    FILE* fp = fopen(kp, "rb");
    assert(fp);

    cjks_io* io = cjks_io_fs_new(fp);
    cjks* jks = cjks_parse_ex(io, "changeit", sizeof("changeit") - 1, "US-ASCII");
    assert(jks);
    cjks* mk = cjks_get(jks, "mytestkey");
    assert(mk && mk->tag == CJKS_PRIVATE_KEY_TAG);

    EVP_PKEY* pk = cjks_2evp(mk->entry.pk);
    int i = cjks_spring_decrypt(pk, es_buf.buf, es_buf.len);
    assert(strncmp("asd", es_buf.buf, i) == 0);

    fclose(fp);
    EVP_PKEY_free(pk);
    cjks_buf_clear(&es_buf);
    cjks_io_fs_free(io);
    cjks_free(jks);
    
}

test_st tests[] = {
    {"decrypt", test_decrypt},
    {"decrypt_from_jks", test_jks_decrypt},
    {NULL, NULL}
};

int main() {
    cjks_run_tests(tests);
    return 0;
}