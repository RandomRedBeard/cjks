#include "test_base.h"
#include "private/debug.h"
#include <cjks/cjks.h>

#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/dsa.h>
#include <openssl/pem.h>

X509* gen_x509(EVP_PKEY* pk) {
    X509* test = X509_new();
    int i = X509_set_pubkey(test, pk);
    ASN1_INTEGER_set(X509_get_serialNumber(test), 1);
    X509_gmtime_adj(X509_get_notBefore(test), 0); // now
    X509_gmtime_adj(X509_get_notAfter(test), 365 * 24 * 3600); // accepts secs

    X509_NAME* name;
    name = X509_get_subject_name(test);

    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
        (unsigned char*)"WA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
        (unsigned char*)"cosmic", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (unsigned char*)"localhost", -1, -1, 0);

    X509_set_issuer_name(test, name);
    X509_sign(test, pk, EVP_sha256());

    return test;
}

void test_write_cjks_1() {
    // iconv sux
    uchar pwd[] = "AGMAaABhAG4AZwBlAGkAdA==";
    int plen = cjks_b64decode(pwd, pwd, sizeof(pwd) - 1);

    FILE* fp = cjks_fp_from_res("/keystore");
    cjks_io* io = cjks_io_fs_new(fp);
    cjks* jks = cjks_parse_ex(io, "changeit", sizeof("changeit") - 1, "US-ASCII"), * jptr = jks;
    cjks_io_close(io);
    cjks_io_fs_free(io);

    fp = fopen("cjks.jks", "wb");
    io = cjks_io_fs_new(fp);

    cjks_write_jks(io, jks, pwd, plen);

    cjks_io_close(io);
    cjks_io_fs_free(io);

    cjks_free(jks);
}

void test_write_cjks_2() {
    uchar pwd[] = "AGMAaABhAG4AZwBlAGkAdA==";
    int plen = cjks_b64decode(pwd, pwd, sizeof(pwd) - 1);

    time_t tm = time(0);

    EVP_PKEY* pk = EVP_RSA_gen(2048);
    printf("gen %d\n", time(0) - tm);
    char* data = malloc(4096), * buf = data;
    int i = i2d_PrivateKey(pk, &buf);

    cjks_pkey* cpk = cjks_pk_new();
    cpk->key.buf = data;
    cpk->key.len = i;

    X509* test = gen_x509(pk);

    cjks_ca* ca = cjks_ca_from_x509(test);

    EVP_PKEY_free(pk);
    X509_free(test);

    printf("EVP %d\n", time(0) - tm);

    cpk->cert_chain = ca;

    cjks* jks = cjks_new(CJKS_PRIVATE_KEY_TAG);
    jks->pk = cpk;
    jks->alias = strdup("thomas");
    jks->ts = time(0);

    FILE* fp = fopen("cjks.jks", "wb");
    cjks_io* io = cjks_io_fs_new(fp);

    tm = time(0);
    cjks_write_jks(io, jks, pwd, plen);
    printf("%d\n", time(0) - tm);

    cjks_io_close(io);
    cjks_io_fs_free(io);

    cjks_free(jks);
}

void test_write_cjks_3() {
    uchar pwd[] = "AGMAaABhAG4AZwBlAGkAdA==";
    int plen = cjks_b64decode(pwd, pwd, sizeof(pwd) - 1);

    time_t tm = time(0);

    EVP_PKEY* pk = EVP_RSA_gen(2048);

    X509* test = gen_x509(pk);

    cjks_ca* ca = cjks_ca_from_x509(test);

    EVP_PKEY_free(pk);
    X509_free(test);

    printf("EVP %d\n", time(0) - tm);

    cjks* jks = cjks_new(CJKS_TRUSTED_CERT_TAG);
    jks->ca = ca;
    jks->alias = strdup("thomas");
    jks->ts = time(0);

    FILE* fp = fopen("cjks.jks", "wb");
    cjks_io* io = cjks_io_fs_new(fp);

    tm = time(0);
    cjks_write_jks(io, jks, pwd, plen);
    printf("%d\n", time(0) - tm);

    cjks_io_close(io);
    cjks_io_fs_free(io);

    cjks_free(jks);
}

void test_write_cjks_4() {
    uchar pwd[] = "AGMAaABhAG4AZwBlAGkAdA==";
    int plen = cjks_b64decode(pwd, pwd, sizeof(pwd) - 1);

    time_t tm = time(0);

    // EVP_RSA_gen;
    DSA* dsa = DSA_new();
    DSA_generate_parameters_ex(dsa, 2048 /*bits*/, NULL, 0, NULL, NULL,
        NULL);
    DSA_generate_key(dsa);

    EVP_PKEY* pk = EVP_PKEY_new();
    EVP_PKEY_set1_DSA(pk, dsa);
    DSA_free(dsa);

    ERR_print_errors_fp(stdout);

    printf("x509\n");
    X509* test = gen_x509(pk);

    cjks_ca* ca = cjks_ca_from_x509(test);

    EVP_PKEY_free(pk);
    X509_free(test);

    printf("EVP %d\n", time(0) - tm);

    cjks* jks = cjks_new(CJKS_TRUSTED_CERT_TAG);
    jks->ca = ca;
    jks->alias = strdup("thomas123");
    jks->ts = time(0);

    FILE* fp = fopen("cjks.jks", "wb");
    cjks_io* io = cjks_io_fs_new(fp);

    tm = time(0);
    cjks_write_jks(io, jks, pwd, plen);
    printf("%d\n", time(0) - tm);

    cjks_io_close(io);
    cjks_io_fs_free(io);

    cjks_free(jks);
}

CJKS_TESTS_ST
CJKS_TEST(test_write_cjks_1)
CJKS_TEST(test_write_cjks_2)
CJKS_TEST(test_write_cjks_3)
CJKS_TEST(test_write_cjks_4)
CJKS_TESTS_END
