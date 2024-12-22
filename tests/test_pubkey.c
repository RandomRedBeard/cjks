#include "test_base.h"

#include <cjks/cjks.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>

void test_pubkey_1() {
    cjks_ca* ca = cjks_ca_new();
    ca->cert_type = strdup("X.509");
    cjks_read_from_res("/domain.crt", &ca->cert);
    ca->n = 1;
    
    cjks* jks = cjks_new(CJKS_TRUSTED_CERT_TAG);
    jks->ca = ca;
    jks->n = 1;
    jks->ts = time(0);
    jks->alias = strdup("ca");


    cjks_free(jks);
}

CJKS_TESTS_ST
CJKS_TEST(test_pubkey_1)
CJKS_TESTS_END