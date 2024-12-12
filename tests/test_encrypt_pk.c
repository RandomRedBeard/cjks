#include "test_base.h"
#include <cjks/cjks.h>
#include <openssl/rand.h>

int cjks_encrypt_pk(cjks_pkey* pk, const char* pwd, size_t plen) {
    // Clear eber, since we will write to it
    cjks_buf_clear(&pk->encrypted_ber);

    // Length of X509_SIG->digest should be pk->key.len + (SHA_DIGEST_LENGTH * 2)
    uchar* ekey = malloc(pk->key.len + 40);
    uchar iv[SHA_DIGEST_LENGTH];

    // Generate new IV
    RAND_bytes(iv, SHA_DIGEST_LENGTH);
    // Write iv to digest first
    memcpy(ekey, iv, SHA_DIGEST_LENGTH);

    cjks_sun_jks_crypt(pk->key.buf, ekey + SHA_DIGEST_LENGTH, pk->key.len, iv, pwd, plen);

    // SHA1 append
    cjks_sha1(ekey + SHA_DIGEST_LENGTH + pk->key.len, 2, pwd, plen, pk->key.buf, pk->key.len);

    ASN1_OCTET_STRING* pdigest;
    X509_ALGOR* palg;
    X509_SIG* sig = X509_SIG_new();

    X509_SIG_getm(sig, &palg, &pdigest);

    ASN1_OBJECT* obj = OBJ_txt2obj("1.3.6.1.4.1.42.2.17.1.1", 1);
    assert(obj);
    int i = X509_ALGOR_set0(palg, obj, V_ASN1_NULL, NULL);

    ASN1_OCTET_STRING_set(pdigest, ekey, pk->key.len + 40);

    int slen = i2d_X509_SIG(sig, NULL);
    pk->encrypted_ber.buf = malloc(slen);
    pk->encrypted_ber.len = slen;

    uchar* eber = pk->encrypted_ber.buf;

    slen = i2d_X509_SIG(sig, &eber);

    return 0;
}

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

}

CJKS_TESTS_ST
CJKS_TEST(test_encrypt_pk)
CJKS_TESTS_END