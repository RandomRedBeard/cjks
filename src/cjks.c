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
        chain->n = i;

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

void cjks_sun_jks_crypt(const uchar* src, uchar* dest, size_t len, uchar* iv, const char* password, size_t plen) {
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

int cjks_sun_jks_decrypt(const uchar* data, uchar* dest, int len, const char* password, size_t plen) {
    uchar iv[SHA_DIGEST_LENGTH];
    uchar sha[SHA_DIGEST_LENGTH];
    size_t dlen = len - (SHA_DIGEST_LENGTH * 2);

    memcpy(iv, data, SHA_DIGEST_LENGTH);
    memcpy(sha, data + len - SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH);

    cjks_sun_jks_crypt(data + SHA_DIGEST_LENGTH, dest, dlen, iv, password, plen);

    // SHA1 hash check
    return cjks_sha1_cmp(sha, 2, password, plen, dest, dlen);
}

int cjks_sun_jks_encrypt(const uchar* src, uchar* dest, int dlen, const char* password, size_t plen) {
    uchar iv[SHA_DIGEST_LENGTH];

    // Generate new IV
    RAND_bytes(iv, SHA_DIGEST_LENGTH);
    // Write iv to digest first
    memcpy(dest, iv, SHA_DIGEST_LENGTH);

    cjks_sun_jks_crypt(src, dest + SHA_DIGEST_LENGTH, dlen, iv, password, plen);

    // SHA1 append
    cjks_sha1(dest + SHA_DIGEST_LENGTH + dlen, 2, password, plen, src, dlen);

    return 0;
}

EVP_PKEY* cjks_2evp2(const cjks* jks) {
    if (jks->tag != CJKS_PRIVATE_KEY_TAG) {
        return NULL;
    }
    return cjks_2evp(jks->pk);
}
