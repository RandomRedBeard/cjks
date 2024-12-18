#include "test_base.h"
#include <cjks/cjks.h>
#include <openssl/rand.h>

void test_encrypt_pk() {
    char pth[128] = CJKS_RES_DIR;
    strcat(pth, "/keystore");

    cjks* jks = cjks_parse_ex2(pth, "changeit", sizeof("changeit") - 1, "US-ASCII"), * jptr = jks;
    assert(jks);
    jptr = cjks_get(jks, "mytestkey");
    assert(jptr->tag == CJKS_PRIVATE_KEY_TAG);

    // No cjks_parse function for path + pwd
    uchar pwd[] = "AGMAaABhAG4AZwBlAGkAdA==";
    int plen = cjks_b64decode(pwd, pwd, sizeof(pwd) - 1);

    int len = cjks_encrypt_pk(jptr->pk, (const char*)pwd, plen);

    cjks_pkey* cmp = cjks_pk_new();
    cmp->encrypted_ber = jptr->pk->encrypted_ber;

    assert(cjks_decrypt_pk(cmp, (const char*)pwd, plen) == 0);

    assert(memcmp(cmp->key.buf, jptr->pk->key.buf, cmp->key.len) == 0);

    cjks_free(jks);
    cmp->encrypted_ber.buf = NULL;
    cjks_pk_free(cmp);

}

CJKS_TESTS_ST
CJKS_TEST(test_encrypt_pk)
CJKS_TESTS_END