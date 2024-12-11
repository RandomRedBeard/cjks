
#include <iconv.h>
#include <cjks/cjks.h>
#include "test_base.h"

void validate_jks(cjks *jks) {
    cjks *jptr = jks;
    unsigned int cnt = 0;
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

    char kp[128];
    memcpy(kp, CJKS_RES_DIR, sizeof(CJKS_RES_DIR));
    strcat(kp, "/d.key");

    cjks_buf dkey = CJKS_BUF_INIT;
    cjks_io_read_all(kp, &dkey);

    unsigned char *mk_key = malloc(2048);
    int mk_key_len = cjks_b64encode(mk_key, mk->pk->key.buf, mk->pk->key.len);

    assert(memcmp(dkey.buf, mk_key, dkey.len) == 0);
    free(mk_key);
    cjks_buf_clear(&dkey);

}

void test_load() {
    char ksp[128];
    memcpy(ksp, CJKS_RES_DIR, sizeof(CJKS_RES_DIR));
    strcat(ksp, "/keystore");
    FILE *fp = fopen(ksp, "rb");
    assert(fp);
    cjks_io *io = cjks_io_fs_new(fp);

    cjks *jks = cjks_parse_ex(io, "changeit", sizeof("changeit") - 1, "US-ASCII");
    validate_jks(jks);

    cjks_io_close(io);
    cjks_io_fs_free(io);
    cjks_free(jks);
}

void test_load2() {
    char ksp[128];
    memcpy(ksp, CJKS_RES_DIR, sizeof(CJKS_RES_DIR));
    strcat(ksp, "/keystore");

    cjks *jks = cjks_parse_ex2(ksp, "changeit", sizeof("changeit") - 1, "US-ASCII"), *jptr = jks;

    validate_jks(jks);
    cjks_free(jks);
}

void test_chain() {
    char ksp[128];
    memcpy(ksp, CJKS_RES_DIR, sizeof(CJKS_RES_DIR));
    strcat(ksp, "/keystore");

    cjks *jks = cjks_parse_ex2(ksp, "changeit", sizeof("changeit") - 1, "US-ASCII"), *jptr = jks;

    const unsigned char* cert = jks->pk->cert_chain->cert.buf;
    size_t cert_len = jks->pk->cert_chain->cert.len;

    X509* x509_cert = NULL;
    if (!d2i_X509(&x509_cert, &cert, cert_len)) {
        ERR_print_errors_fp(stderr);
    }

    X509_print_fp(stderr, x509_cert);

    cjks_free(jks);
}

void test_chain2() {
    char ksp[128];
    memcpy(ksp, CJKS_RES_DIR, sizeof(CJKS_RES_DIR));
    strcat(ksp, "/keystore_ca");

    cjks *jks = cjks_parse_ex2(ksp, "password", sizeof("password") - 1, "US-ASCII"), *jptr = jks;

    assert(jks);
    assert(jks->tag == CJKS_PRIVATE_KEY_TAG);

    cjks_ca* ca = jks->pk->cert_chain;
    while (ca) {
        printf("Count\n");
        ca = ca->next;
    }

    cjks_free(jks);
}

test_st tests[] = {
    {"load", test_load},
    {"load2", test_load2},
    {"chain", test_chain},
    {"chain2", test_chain2},
    {NULL, NULL}
};

int main() {
    cjks_run_tests(tests);
    return 0;
}