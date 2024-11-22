#include "cjks/cjks.h"

cjks* cjks_parse(cjks_io* io, const char* password, size_t len) {
    char header[4];
    cjks_io_read(io, header, 4);

    // Not magic header
    if (memcmp(cjks_jks_magic_number, header, 4) != 0) {
        return NULL;
    }

    unsigned int version = cjks_io_read_be4(io);

    // Only supporting v2
    if (version != 2) {
        return NULL;
    }

    unsigned int entry_count = cjks_io_read_be4(io);

    cjks *root = NULL, *chain = NULL;

    for (unsigned int i = 0; i < entry_count; i++) {
        unsigned int tag = cjks_io_read_be4(io);
        chain = cjks_new(tag);
        chain->alias = cjks_io_aread_utf(io);
        chain->ts = cjks_io_read_be8(io);

        if (tag == CJKS_PRIVATE_KEY_TAG) {
            chain->pk = cjks_pk_new();
            if (cjks_parse_pk(io, chain->pk) < 0) {
                perror("Failed to parse jks");
                break;
            }
            cjks_decrypt_pk(chain->pk, password, len);
        }
        else if (tag == CJKS_TRUSTED_CERT_TAG) {
            chain->ca = cjks_ca_new();
            if (cjks_parse_ca(io, chain->ca) < 0) {
                perror("Failed to parse jks");
                break;
            }
        }
        chain->next = root;
        root = chain;
    }

    return root;
}

cjks* cjks_parse_ex(cjks_io* io, char* password, size_t len, const char* encoding) {
    char epwd[128], *ptr = epwd;
    size_t epwd_len = 128;
    
    iconv_t cnv = iconv_open("UTF-16BE", encoding);
    iconv(cnv, NULL, NULL, &ptr, &epwd_len);
    if (iconv(cnv, &password, &len, &ptr, &epwd_len) == (size_t) -1) {
        iconv_close(cnv);
        return NULL;
    }
    iconv_close(cnv);

    epwd_len = sizeof(epwd) - epwd_len;

    return cjks_parse(io, epwd, epwd_len);
}

cjks* cjks_parse_ex2(const char* pth, char* password, size_t len, const char* encoding) {
    FILE* fp = fopen(pth, "rb");
    if (!fp) {
        return NULL;
    }

    cjks_io* io = cjks_io_fs_new(fp);
    cjks* jks = cjks_parse_ex(io, password, len, encoding);
    cjks_io_fs_free(io);
    fclose(fp);
    return jks;
}


cjks* cjks_get(cjks* jks, const char* alias) {
    while (jks) {
        if (strcmp(jks->alias, alias) == 0) {
            return jks;
        }
        jks = jks->next;
    }
    return NULL;
}

cjks *cjks_new(int tag) {
    cjks *e = calloc(1, sizeof(cjks));
    e->tag = tag;
    return e;
}

void cjks_free(cjks* jks) {
    cjks* n;
    do {
        n = jks->next;
        free(jks->alias);
        switch(jks->tag) {
        case CJKS_PRIVATE_KEY_TAG:
            cjks_pk_free(jks->pk);
            break;
        case CJKS_TRUSTED_CERT_TAG:
            cjks_ca_free(jks->ca);
            break;
        }
        free(jks);
        jks = n;
    } while (jks);
}

cjks_ca *cjks_ca_new() {
    return calloc(1, sizeof(cjks_ca));
}

void cjks_ca_free(cjks_ca* ca) {
    cjks_ca* n;
    do {
        n = ca->next;
        free(ca->cert_type);
        cjks_buf_clear(&ca->cert);
        free(ca);
        ca = n;
    } while(ca);
}

int cjks_parse_ca(cjks_io* io, cjks_ca* ca) {
    ca->cert_type = cjks_io_aread_utf(io);
    cjks_io_aread_data(io, &ca->cert);
    return 0;
}

cjks_pkey* cjks_pk_new() {
    return calloc(1, sizeof(cjks_pkey));
}

void cjks_pk_free(cjks_pkey* pk) {
    cjks_buf_clear(&pk->key);
    cjks_buf_clear(&pk->encrypted_ber);
    cjks_ca_free(pk->cert_chain);
    free(pk);
}

int cjks_parse_pk(cjks_io* io, cjks_pkey* pk) {
    cjks_io_aread_data(io, &pk->encrypted_ber);
    unsigned int chain_len = cjks_io_read_be4(io);

    cjks_ca *chain = NULL, *root = NULL;
    for (unsigned int i = 0; i < chain_len; i++) {
        chain = cjks_ca_new();
        cjks_parse_ca(io, chain);
        chain->next = root;
        root = chain;
    }
    pk->cert_chain = root;
    return 0;
}


int cjks_parse_eber(const cjks_buf *eber, ASN1_TYPE **ber) {
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
        if (ASN1_TYPE_get(type) == V_ASN1_OCTET_STRING) {
            *ber = type;
        } else {
            ASN1_TYPE_free(type);
        }
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
    ASN1_TYPE* ber = NULL;
    ASN1_OCTET_STRING* ber_s = NULL;
    cjks_parse_eber(&pk->encrypted_ber, &ber);
    ber_s = ber->value.octet_string;

    unsigned char cur[SHA_DIGEST_LENGTH], *cptr = cur;
    memcpy(cur, ber->value.octet_string->data, SHA_DIGEST_LENGTH);

    // 20 bytes for iv in front, 20 for hash in back
    unsigned char *pkey_buf = malloc(ber->value.octet_string->length - 40), *pkey_ptr = pkey_buf;
    unsigned char *pkey_end = ber_s->data + ber_s->length - 20, *dptr = ber_s->data + 20;
    cjks_keystream(cur, password, len);

    while (dptr != pkey_end) {
        *pkey_ptr++ = *dptr++ ^ *cptr++;

        if (cptr - cur == SHA_DIGEST_LENGTH) {
            cjks_keystream(cur, password, len);
            cptr = cur;
        }
    }

    pk->key.buf = pkey_buf;
    pk->key.len = ber_s->length - 40;

    ASN1_TYPE_free(ber);

    return 0;
}

EVP_PKEY *cjks_2evp(const cjks_pkey *pkey) {
    const unsigned char *ptr = pkey->key.buf;
    return d2i_AutoPrivateKey(NULL, &ptr, (long)pkey->key.len);
}

EVP_PKEY *cjks_2evp2(const cjks* jks) {
    if (jks->tag != CJKS_PRIVATE_KEY_TAG) {
        return NULL;
    }
    return cjks_2evp(jks->pk);
}
