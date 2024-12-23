#include "test_base.h"

#include <cjks/cjks.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>

void test_pubkey_1() {
    FILE* fp = cjks_fp_from_res("/chain.crt");

    X509* x;

    do {
        X509* x = PEM_read_X509(fp, NULL, NULL, NULL);
        ERR_print_errors_fp(stdout);
        if (!x) {
            break;
        }

        X509_NAME* name = X509_get_subject_name(x);
        X509_NAME_print_ex_fp(stdout, name, 0, 0);

        puts("");

        X509_free(x);
    } while (x);
    fclose(fp);
}

CJKS_TESTS_ST
CJKS_TEST(test_pubkey_1)
CJKS_TESTS_END