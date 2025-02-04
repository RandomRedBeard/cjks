
#include <iconv.h>
#include <cjks/cjks.h>
#include "test_base.h"

void validate_jks(cjks *jks) {
    cjks *jptr = jks;
    uint32 cnt = 0;

    // 0-based indexing on entries
    assert(jptr->n == 2);

    while (jptr) {
        printf("%d - %s\n", jptr->tag, jptr->alias);
        jptr = jptr->next;
        cnt++;
    }

    assert(cnt == 3);

    cjks *mk = cjks_get(jks, "mytestkey");
    assert(mk);
    assert(mk->tag == CJKS_PRIVATE_KEY_TAG);
    assert(mk->pk->key.len > 0);
    
    cjks_buf dkey = CJKS_BUF_INIT;
    cjks_read_from_res("/d.key", &dkey);

    uchar *mk_key = malloc(2048);
    int mk_key_len = cjks_b64encode(mk_key, mk->pk->key.buf, mk->pk->key.len);

    assert(memcmp(dkey.buf, mk_key, dkey.len) == 0);
    free(mk_key);
    cjks_buf_clear(&dkey);

}

void test_load() {
    FILE* fp = cjks_fp_from_res("/keystore");
    assert(fp);
    cjks_io *io = cjks_io_fs_new(fp);

    cjks *jks = cjks_parse_ex(io, "changeit", sizeof("changeit") - 1, "US-ASCII");
    validate_jks(jks);

    cjks_io_close(io);
    cjks_io_fs_free(io);
    cjks_free(jks);
}

void test_load2() {
    char ksp[128] = CJKS_RES_DIR;
    strcat(ksp, "/keystore");

    cjks *jks = cjks_parse_ex2(ksp, "changeit", sizeof("changeit") - 1, "US-ASCII"), *jptr = jks;

    validate_jks(jks);
    cjks_free(jks);
}

void test_chain() {
    char ksp[128] = CJKS_RES_DIR;
    strcat(ksp, "/keystore");

    cjks *jks = cjks_parse_ex2(ksp, "changeit", sizeof("changeit") - 1, "US-ASCII"), *jptr = jks;
    jptr = cjks_get(jks, "mytestkey");
    assert(jptr->tag == CJKS_PRIVATE_KEY_TAG);

    const uchar* cert = jptr->pk->cert_chain->cert.buf;
    size_t cert_len = jptr->pk->cert_chain->cert.len;

    X509* x509_cert = NULL;
    if (!d2i_X509(&x509_cert, &cert, cert_len)) {
        ERR_print_errors_fp(stderr);
    }
    assert(x509_cert);
    X509_free(x509_cert);

    cjks_free(jks);
}

void test_chain2() {
    char ksp[128] = CJKS_RES_DIR;
    strcat(ksp, "/keystore_ca");

    cjks *jks = cjks_parse_ex2(ksp, "changeit", sizeof("changeit") - 1, "US-ASCII"), *jptr = jks;

    assert(jks);
    assert(jks->tag == CJKS_PRIVATE_KEY_TAG);

    cjks_ca* ca = jks->pk->cert_chain;
    assert(ca->n == 2);
    uint16 cnt = 0;
    while (ca) {
        printf("Count - %d\n", ca->n);
        ca = ca->next;
        cnt++;
    }

    assert(cnt == 3);

    cjks_free(jks);
}

CJKS_TESTS_ST
    CJKS_TEST(test_load)
    CJKS_TEST(test_load2)
    CJKS_TEST(test_chain)
    CJKS_TEST(test_chain2)
CJKS_TESTS_END