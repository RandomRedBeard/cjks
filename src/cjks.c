#include "cjks/cjks.h"

cjks* cjks_parse(cjks_io* io, const char* password, size_t len) {
    char header[4];
    cjks_io_read(io, header, 4);

    // Not magic header
    if (memcmp(cjks_jks_magic_number, header, 4) != 0) {
        return NULL;
    }

    uint32 version = cjks_io_read_be4(io);

    // Only supporting v2
    if (version != 2) {
        return NULL;
    }

    uint32 entry_count = cjks_io_read_be4(io);

    cjks* root = NULL, * chain = NULL;

    for (uint32 i = 0; i < entry_count; i++) {
        uint32 tag = cjks_io_read_be4(io);
        chain = cjks_new(tag);
        chain->alias = cjks_io_aread_utf(io);
        chain->ts = cjks_io_read_be8(io);

        if (tag == CJKS_PRIVATE_KEY_TAG) {
            chain->pk = cjks_pk_new();
            if (cjks_parse_pk(io, chain->pk) < 0) {
                perror("Failed to parse jks");
                break;
            }
            if (cjks_decrypt_pk(chain->pk, password, len) < 0) {
                perror("Failed to decrypt pk");
                break;
            }
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
    char epwd[128], * ptr = epwd;
    size_t epwd_len = 128;

    iconv_t cnv = iconv_open("UTF-16BE", encoding);
    iconv(cnv, NULL, NULL, &ptr, &epwd_len);
    if (iconv(cnv, &password, &len, &ptr, &epwd_len) == (size_t)-1) {
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

cjks* cjks_new(int tag) {
    cjks* e = calloc(1, sizeof(cjks));
    e->tag = tag;
    return e;
}

void cjks_free(cjks* jks) {
    cjks* n;
    do {
        n = jks->next;
        free(jks->alias);
        switch (jks->tag) {
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

cjks_ca* cjks_ca_new() {
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
    } while (ca);
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
    uint32 chain_len = cjks_io_read_be4(io);

    cjks_ca* chain = NULL, * root = NULL;
    for (uint32 i = 0; i < chain_len; i++) {
        chain = cjks_ca_new();
        cjks_parse_ca(io, chain);
        chain->next = root;
        root = chain;
    }
    pk->cert_chain = root;
    return 0;
}


int cjks_parse_eber(const cjks_buf* eber, X509_SIG** sig) {
    const uchar* dptr = eber->buf;
    if (!d2i_X509_SIG(sig, &dptr, (long)eber->len)) {
        return -1;
    }

    return 0;
}

void cjks_sun_jks_crypt(const uchar* src, unsigned char* dest, size_t len, unsigned char* iv, const char* password, size_t plen) {
    uchar* ivptr = iv, * ivptrend = iv + SHA_DIGEST_LENGTH;
    uchar* dptr = dest;
    const uchar* sptr = src, * sptrend = src + len;

    cjks_sha1(iv, 2, password, plen, iv, (size_t)20);
    while (sptr != sptrend) {
        *dptr++ = *sptr++ ^ *ivptr++;
        if (ivptr == ivptrend) {
            cjks_sha1(iv, 2, password, plen, iv, (size_t)20);
            ivptr = iv;
        }
    }
}

int cjks_sun_jks_decrypt(const uchar* data, unsigned char* dest, int len, const char* password, size_t plen) {
    uchar iv[SHA_DIGEST_LENGTH];
    uchar sha[SHA_DIGEST_LENGTH];
    size_t dlen = len - (SHA_DIGEST_LENGTH * 2);

    memcpy(iv, data, SHA_DIGEST_LENGTH);
    memcpy(sha, data + len - SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH);

    cjks_sun_jks_crypt(data + SHA_DIGEST_LENGTH, dest, dlen, iv, password, plen);

    // SHA1 hash check
    return cjks_sha1_cmp(sha, 2, password, plen, dest, dlen);
}

int cjks_decrypt_pk(cjks_pkey* pk, const char* password, size_t len) {
    X509_SIG* sig = NULL;
    const X509_ALGOR* algor = NULL;
    const ASN1_OCTET_STRING* digest = NULL;
    if (cjks_parse_eber(&pk->encrypted_ber, &sig) < 0) {
        return -1;
    }

    X509_SIG_get0(sig, &algor, &digest);

    // SUN_JKS Algo check
    if (sizeof(SUN_JKS_ALGO_ID) != OBJ_length(algor->algorithm) || \
        memcmp(SUN_JKS_ALGO_ID, OBJ_get0_data(algor->algorithm), sizeof(SUN_JKS_ALGO_ID)) != 0) {
        X509_SIG_free(sig);
        return -1;
    }

    uchar* pkey_buf = malloc(digest->length - 40);

    if (!cjks_sun_jks_decrypt(digest->data, pkey_buf, digest->length, password, len)) {
        free(pkey_buf);
        X509_SIG_free(sig);
        return -1;
    }

    pk->key.buf = pkey_buf;
    pk->key.len = digest->length - 40;

    X509_SIG_free(sig);

    return 0;
}

EVP_PKEY* cjks_2evp(const cjks_pkey* pkey) {
    const uchar* ptr = pkey->key.buf;
    return d2i_AutoPrivateKey(NULL, &ptr, (long)pkey->key.len);
}

EVP_PKEY* cjks_2evp2(const cjks* jks) {
    if (jks->tag != CJKS_PRIVATE_KEY_TAG) {
        return NULL;
    }
    return cjks_2evp(jks->pk);
}
