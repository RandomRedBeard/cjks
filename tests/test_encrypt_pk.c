#include "test_base.h"
#include <cjks/cjks.h>

int cjks_encrypt_pk(cjks_pkey* pk) {

    return 0;
}

void test_encrypt_pk() {
    char pth[128] = CJKS_RES_DIR;
    strcat(pth, "/keystore");
    cjks* jks = cjks_parse_ex2(pth, "changeit", sizeof("changeit") - 1, "US-ASCII"), * jptr = jks;
    assert(jks);
    jptr = cjks_get(jks, "mytestkey");
    assert(jptr->tag == CJKS_PRIVATE_KEY_TAG);

    int len = cjks_encrypt_pk(jptr->pk);
}

CJKS_TESTS_ST
CJKS_TEST(test_encrypt_pk)
CJKS_TESTS_END