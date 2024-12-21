#include "cjks/cjks.h"

cjks_pkey* cjks_pk_new() {
    return calloc(1, sizeof(cjks_pkey));
}

void cjks_pk_free(cjks_pkey* pk) {
    cjks_buf_clear(&pk->key);
    cjks_buf_clear(&pk->encrypted_ber);
    if (pk->cert_chain) {
        cjks_ca_free(pk->cert_chain);
    }
    free(pk);
}

int cjks_parse_pk(cjks_io* io, cjks_pkey* pk) {
    cjks_io_aread_data(io, &pk->encrypted_ber);

    uint32 chain_len = cjks_io_read_be4(io);
    cjks_ca* p1 = NULL, * p2 = NULL, * tmp;
    for (uint32 i = chain_len; i > 0; i--) {
        tmp = cjks_ca_new();
        tmp->n = i;
        cjks_parse_ca(io, tmp);

        if (!p1) {
            p1 = p2 = tmp;
        }
        else {
            p2->next = tmp;
            p2 = tmp;
        }
    }
    pk->cert_chain = p1;
    return 0;
}

int cjks_parse_eber(const cjks_buf* eber, X509_SIG** sig) {
    const uchar* dptr = eber->buf;
    if (!d2i_X509_SIG(sig, &dptr, (long)eber->len)) {
        return -1;
    }

    return 0;
}


int cjks_decrypt_pk(cjks_pkey* pk, const char* password, size_t len) {
    X509_SIG* sig = NULL;
    const X509_ALGOR* algor = NULL;
    const ASN1_OCTET_STRING* digest = NULL;
    if (cjks_parse_eber(&pk->encrypted_ber, &sig) < 0) {
        perror("EBER parse failed");
        return -1;
    }

    X509_SIG_get0(sig, &algor, &digest);

    // SUN_JKS Algo check
    if (sizeof(SUN_JKS_ALGO_ID) != OBJ_length(algor->algorithm) || \
        memcmp(SUN_JKS_ALGO_ID, OBJ_get0_data(algor->algorithm), sizeof(SUN_JKS_ALGO_ID)) != 0) {
        X509_SIG_free(sig);
        perror("SUN_JKS_ALGO wrong");
        return -1;
    }

    uchar* pkey_buf = malloc(digest->length - 40);

    if (!cjks_sun_jks_decrypt(digest->data, pkey_buf, digest->length, password, len)) {
        free(pkey_buf);
        X509_SIG_free(sig);
        perror("sun_jks_dec failed");
        return -1;
    }

    pk->key.buf = pkey_buf;
    pk->key.len = digest->length - 40;

    X509_SIG_free(sig);

    return 0;
}

int cjks_encrypt_pk(cjks_pkey* pk, const char* password, size_t len) {
    ASN1_OCTET_STRING* pdigest = NULL;
    X509_ALGOR* palg = NULL;
    X509_SIG* sig = NULL;
    ASN1_OBJECT* obj = NULL;

    // Clear eber, since we will write to it
    cjks_buf_clear(&pk->encrypted_ber);

    // Length of X509_SIG->digest should be pk->key.len + (SHA_DIGEST_LENGTH * 2)
    uchar* ekey = malloc(pk->key.len + 40);

    cjks_sun_jks_encrypt(pk->key.buf, ekey, pk->key.len, password, len);

    sig = X509_SIG_new();

    X509_SIG_getm(sig, &palg, &pdigest);

    obj = OBJ_txt2obj("1.3.6.1.4.1.42.2.17.1.1", 1);
    int i = X509_ALGOR_set0(palg, obj, V_ASN1_NULL, NULL);

    ASN1_OCTET_STRING_set(pdigest, ekey, pk->key.len + 40);
    free(ekey);

    int slen = i2d_X509_SIG(sig, NULL);
    pk->encrypted_ber.buf = malloc(slen);
    pk->encrypted_ber.len = slen;

    uchar* eber = pk->encrypted_ber.buf;

    slen = i2d_X509_SIG(sig, &eber);
    X509_SIG_free(sig);

    return slen;
}

int cjks_write_pk(cjks_io* io, cjks_pkey* pk, const char* password, size_t len) {
    int i = 0, tmp;
    cjks_encrypt_pk(pk, password, len);

    if ((tmp = cjks_io_write_data(io, &pk->encrypted_ber)) < 0) {
        return -1;
    }

    i += tmp;

    cjks_ca* ca = pk->cert_chain;
    if (!ca) {
        if ((tmp = cjks_io_write_be4(io, 0)) < 0) {
            return -1;
        }

        return i + tmp;
    }

    if ((tmp = cjks_io_write_be4(io, ca->n)) < 0) {
        return -1;
    }

    i += tmp;
    while (ca) {
        if ((tmp = cjks_write_ca(io, ca)) < 0) {
            return -1;
        }
        i += tmp;
        ca = ca->next;
    }
    return i;
}


EVP_PKEY* cjks_2evp(const cjks_pkey* pkey) {
    const uchar* ptr = pkey->key.buf;
    return d2i_AutoPrivateKey(NULL, &ptr, (long)pkey->key.len);
}
