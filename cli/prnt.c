#define NOCRYPT
#include <time.h>
#include <cjks/cjks.h>
#include <openssl/x509.h>
#include "private/debug.h"

void print_ca(cjks_ca* ca) {
    printf("%d\n", ca->n);
    const uchar* b = ca->cert.buf;
    X509* x = d2i_X509(NULL, &b, ca->cert.len);
    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME* issuer = X509_get_issuer_name(x);
    X509_NAME_print_ex_fp(stdout, name, 0, 0);
    puts("");
    X509_NAME_print_ex_fp(stdout, issuer, 0, 0);
    puts("");

    X509_free(x);
}

void print_pk(cjks_pkey* pk) {
    printf("klen: %zu\n", pk->key.len);
    cjks_ca* ca = pk->cert_chain;
    while (ca) {
        print_ca(ca);
        ca = ca->next;
    }
}

void print_jks(cjks* jks) {
    while (jks) {
        printf("%u: %s - %d - %llu\n", jks->n, jks->alias, jks->tag, jks->ts);
        if (jks->tag == CJKS_PRIVATE_KEY_TAG) {
            print_pk(jks->pk);
        }
        else {
            print_ca(jks->ca);
        }

        puts("");
        jks = jks->next;
    }
}
