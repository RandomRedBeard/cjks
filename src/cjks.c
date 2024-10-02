#include "cjks/cjks.h"

cjks* cjks_parse(cjks_io* io, const char* password, size_t len) {
    char header[4];
    cjks_io_read(io, header, 4);

    unsigned int version = cjks_io_read_be4(io);
    unsigned int entry_count = cjks_io_read_be4(io);

    cjks *root = NULL, *chain = NULL;

    for (unsigned int i = 0; i < entry_count; i++) {
        unsigned int tag = cjks_io_read_be4(io);
        chain = cjks_new(tag);
        chain->alias = cjks_io_aread_utf(io);
        chain->ts = cjks_io_read_be8(io);

        if (tag == CJKS_PRIVATE_KEY_TAG) {
            if (cjks_parse_pk(io, &chain->entry.pk) > 0) {
                cjks_decrypt_pk(&chain->entry.pk, password, len);
            }
        }
        else if (tag == CJKS_TRUSTED_CERT_TAG) {
            if (cjks_parse_ca(io, &chain->entry.ca) < 0) {
                perror("Failed to parse jks");
                break;
            }
        }
        chain->next = root;
        root = chain;
    }

    return root;
}

cjks *cjks_new(int tag) {
    cjks *e = calloc(1, sizeof(cjks));
    e->tag = tag;
    return e;
}

cjks_ca *cjks_ca_new() {
    return calloc(1, sizeof(cjks_ca));
}

cjks_ca* cjks_parse_ca(cjks_io* io, cjks_ca* ca) {
    ca->cert_type = cjks_io_aread_utf(io);
    cjks_io_aread_data(io, &ca->cert);
    return ca;
}

int cjks_parse_pk(cjks_io* io, cjks_pkey* pk) {
    cjks_io_aread_data(io, &pk->encrypted_ber);
    unsigned int chain_len = cjks_io_read_be4(io);

    cjks_ca *chain = NULL, *root = NULL;
    for (unsigned int i = 0; i < chain_len; i++) {
        chain = cjks_ca_new();
        chain = cjks_parse_ca(io, chain);
        chain->next = root;
        root = chain;
    }
    pk->cert_chain = root;
    return 0;
}


int cjks_parse_eber(const cjks_buf *eber, cjks_buf *ber) {
    ASN1_SEQUENCE_ANY *seq = NULL;
    ASN1_TYPE *type = NULL;

    const unsigned char *bptr = eber->buf;
    long rlen;
    int ptag, pclass;

    ASN1_get_object(&bptr, &rlen, &ptag, &pclass, (long)eber->len);
    if (ptag != V_ASN1_SEQUENCE) {
        return -1;
    }

    bptr = eber->buf;
    if (!d2i_ASN1_SEQUENCE_ANY(&seq, &bptr, (long)eber->len)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    while ((type = sk_ASN1_TYPE_pop(seq))) {
        switch (ASN1_TYPE_get(type)) {
        case V_ASN1_OCTET_STRING:
            cjks_buf_dup(ber, type->value.octet_string->data, type->value.octet_string->length);
            break;
        default:
            break;
        }

        ASN1_TYPE_free(type);
    }

    sk_ASN1_TYPE_free(seq);

    return 0;
}

void cjks_keystream(unsigned char *cur, const char *password, size_t plen) {
    unsigned int olen;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit(ctx, EVP_sha1());

    EVP_DigestUpdate(ctx, password, plen);
    EVP_DigestUpdate(ctx, cur, SHA_DIGEST_LENGTH);

    EVP_DigestFinal(ctx, cur, &olen);
    EVP_MD_CTX_free(ctx);
}

int cjks_decrypt_pk(cjks_pkey* pk, const char* password, size_t len) {
    cjks_buf ber = CJKS_BUF_INIT;
    cjks_parse_eber(&pk->encrypted_ber, &ber);

    unsigned char cur[SHA_DIGEST_LENGTH], *cptr = cur;
    memcpy(cur, ber.buf, SHA_DIGEST_LENGTH);

    // 20 bytes for iv in front, 20 for hash in back
    unsigned char *pkey_buf = malloc(ber.len - 40), *pkey_ptr = pkey_buf, *pkey_end = (unsigned char *)ber.buf + ber.len - 20, *dptr = (unsigned char *)ber.buf + 20;
    cjks_keystream(cur, password, len);

    while (dptr != pkey_end) {
        *pkey_ptr++ = *dptr++ ^ *cptr++;

        if (cptr - cur == SHA_DIGEST_LENGTH) {
            cjks_keystream(cur, password, len);
            cptr = cur;
        }
    }

    pk->key.buf = pkey_buf;
    pk->key.len = ber.len - 40;

    return 0;
}

EVP_PKEY *cjks_2evp(const cjks_pkey *pkey) {
    const unsigned char *ptr = pkey->key.buf;
    return d2i_AutoPrivateKey(NULL, &ptr, (long)pkey->key.len);
}
