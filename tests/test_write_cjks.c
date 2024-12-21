#include "test_base.h"
#include "private/debug.h"
#include <cjks/cjks.h>

#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

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

    EVP_PKEY* pk = EVP_RSA_gen(2048);
    char* data = malloc(4096), * buf = data;
    int i = i2d_PrivateKey(pk, &buf);

    cjks_pkey* cpk = cjks_pk_new();
    cpk->key.buf = data;
    cpk->key.len = i;

    char* kbuf = malloc(4096), * kptr = kbuf;
    size_t klen = 4096;

    X509* test = X509_new();
    i = X509_set_pubkey(test, pk);
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

    i = i2d_X509(test, &kptr);
    ERR_print_errors_fp(stdout);
    assert(i > 0);

    EVP_PKEY_free(pk);
    X509_free(test);

    cjks_ca* ca = cjks_ca_new();
    ca->cert.buf = kbuf;
    ca->cert.len = i;
    ca->cert_type = strdup("X.509");
    ca->n = 1;

    cpk->cert_chain = ca;

    cjks* jks = cjks_new(CJKS_PRIVATE_KEY_TAG);
    jks->pk = cpk;
    jks->alias = strdup("thomas");
    jks->ts = time(0);
    jks->n = 1;

    FILE* fp = fopen("cjks.jks", "wb");
    cjks_io* io = cjks_io_fs_new(fp);

    time_t tm = time(0);
    cjks_write_jks(io, jks, pwd, plen);
    printf("%d\n", time(0) - tm);

    cjks_io_close(io);
    cjks_io_fs_free(io);

    cjks_free(jks);

}

CJKS_TESTS_ST
CJKS_TEST(test_write_cjks_1)
CJKS_TEST(test_write_cjks_2)
CJKS_TESTS_END
