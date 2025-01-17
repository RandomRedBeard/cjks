#include "cjks/cjks.h"

cjks *cjks_parse(cjks_io *io, const char *password, size_t len) {
    char header[4];
    cjks_io_read(io, header, 4);

    // Not magic header
    if (memcmp(&JKS_MAGIC_NUMBER, header, 4) != 0) {
        return NULL;
    }

    uint32 version = cjks_io_read_be4(io);

    // Only supporting v2
    if (version != 2) {
        return NULL;
    }

    uint32 entry_count = cjks_io_read_be4(io);

    cjks *p1 = NULL, *p2 = NULL, *tmp;
    for (int i = entry_count - 1; i >= 0; i--) {
        uint32 tag = cjks_io_read_be4(io);
        tmp = cjks_new(tag);
        tmp->alias = cjks_io_aread_utf(io);
        tmp->ts = cjks_io_read_be8(io);
        tmp->n = i;

        if (tag == CJKS_PRIVATE_KEY_TAG) {
            tmp->pk = cjks_pk_new();
            if (cjks_parse_pk(io, tmp->pk) < 0) {
                perror("Failed to parse jks");
                break;
            }
            if (cjks_decrypt_pk(tmp->pk, password, len) < 0) {
                perror("Failed to decrypt pk");
                break;
            }
        }
        else if (tag == CJKS_TRUSTED_CERT_TAG) {
            tmp->ca = cjks_ca_new();
            if (cjks_parse_ca(io, tmp->ca) < 0) {
                perror("Failed to parse jks");
                break;
            }
        }

        if (!p1) {
            p1 = p2 = tmp;
        }
        else {
            p2->next = tmp;
            p2 = tmp;
        }
    }

    return p1;
}

cjks *cjks_parse_ex(cjks_io *io, char *password, size_t len, const char *encoding) {
    char epwd[128], *ptr = epwd;
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

cjks *cjks_parse_ex2(const char *pth, char *password, size_t len, const char *encoding) {
    FILE *fp = fopen(pth, "rb");
    if (!fp) {
        return NULL;
    }

    cjks_io *io = cjks_io_fs_new(fp);
    cjks *jks = cjks_parse_ex(io, password, len, encoding);
    cjks_io_fs_free(io);
    fclose(fp);
    return jks;
}


int cjks_write_jks_header(cjks_io *io, cjks *jks) {
    int r = 0, tmp;
    if ((tmp = cjks_io_write(io, &JKS_MAGIC_NUMBER, 4)) < 0) {
        return -1;
    }
    r += tmp;
    if ((tmp = cjks_io_write_be4(io, 2)) < 0) {
        return -1;
    }
    r += tmp;
    if ((tmp = cjks_io_write_be4(io, jks->n + 1)) < 0) {
        return -1;
    }
    return  r + tmp;
}

int cjks_write_jks_entry(cjks_io *io, cjks *jks, const char *password, size_t len) {
    int r = 0, tmp;
    if ((tmp = cjks_io_write_be4(io, jks->tag)) < 0) {
        return -1;
    }
    r += tmp;
    if ((tmp = cjks_io_write_utf(io, jks->alias, strlen(jks->alias))) < 0) {
        return -1;
    }
    r += tmp;
    if ((tmp = cjks_io_write_be8(io, jks->ts)) < 0) {
        return -1;
    }
    r += tmp;

    if (jks->tag == CJKS_TRUSTED_CERT_TAG) {
        if ((tmp = cjks_write_ca(io, jks->ca)) < 0) {
            return -1;
        }
    }
    else {
        if ((tmp = cjks_write_pk(io, jks->pk, password, len)) < 0) {
            return -1;
        }
    }

    return r + tmp;
}

int cjks_write_jks(cjks_io *io, cjks *jks, const char *password, size_t len) {
    int tmp;
    uint32 r = 0;
    io = cjks_io_sha1_new(io, NULL);

    cjks_io_sha1_cnsm(io, (const uchar *)password, len);
    cjks_io_sha1_cnsm(io, CJKS_SIGWHITE, sizeof(CJKS_SIGWHITE) - 1);

    if ((tmp = cjks_write_jks_header(io, jks)) < 0) {
        cjks_io_sha1_free(io, 1);
        return -1;
    }
    r += tmp;
    while (jks) {
        if ((tmp = cjks_write_jks_entry(io, jks, password, len)) < 0) {
            cjks_io_sha1_free(io, 1);
            return -1;
        }
        r += tmp;
        jks = jks->next;
    }

    uchar hash[SHA_DIGEST_LENGTH];
    cjks_io_sha1_cmpl(io, (uint32 *)hash);

    io = cjks_io_sha1_free(io, 1);
    if ((tmp = cjks_io_write(io, hash, SHA_DIGEST_LENGTH)) < 0) {
        return -1;
    }

    return r + tmp;
}

int cjks_write_jks_ex(cjks_io *io, cjks *jks, char *password, size_t len, const char *encoding) {
    char epwd[128], *ptr = epwd;
    size_t epwd_len = 128;

    iconv_t cnv = iconv_open("UTF-16BE", encoding);
    iconv(cnv, NULL, NULL, &ptr, &epwd_len);
    if (iconv(cnv, &password, &len, &ptr, &epwd_len) == (size_t)-1) {
        iconv_close(cnv);
        return -1;
    }
    iconv_close(cnv);

    epwd_len = sizeof(epwd) - epwd_len;

    return cjks_write_jks(io, jks, epwd, epwd_len);
}

cjks *cjks_get(cjks *jks, const char *alias) {
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

void cjks_free(cjks *jks) {
    cjks *n;
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

void cjks_sun_jks_crypt(const uchar *src, uchar *dest, size_t len, uchar *iv, const char *password, size_t plen) {
    uchar *ivptr = iv, *ivptrend = iv + SHA_DIGEST_LENGTH;
    uchar *dptr = dest;
    const uchar *sptr = src, *sptrend = src + len;

    cjks_sha1(iv, 2, password, plen, iv, (size_t)20);
    while (sptr != sptrend) {
        *dptr++ = *sptr++ ^ *ivptr++;
        if (ivptr == ivptrend) {
            cjks_sha1(iv, 2, password, plen, iv, (size_t)20);
            ivptr = iv;
        }
    }
}

int cjks_sun_jks_decrypt(const uchar *data, uchar *dest, int len, const char *password, size_t plen) {
    uchar iv[SHA_DIGEST_LENGTH];
    uchar sha[SHA_DIGEST_LENGTH];
    size_t dlen = len - (SHA_DIGEST_LENGTH * 2);

    memcpy(iv, data, SHA_DIGEST_LENGTH);
    memcpy(sha, data + len - SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH);

    cjks_sun_jks_crypt(data + SHA_DIGEST_LENGTH, dest, dlen, iv, password, plen);

    // SHA1 hash check
    return cjks_sha1_cmp(sha, 2, password, plen, dest, dlen);
}

int cjks_sun_jks_encrypt(const uchar *src, uchar *dest, int dlen, const char *password, size_t plen) {
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

EVP_PKEY *cjks_2evp2(const cjks *jks) {
    if (jks->tag != CJKS_PRIVATE_KEY_TAG) {
        return NULL;
    }
    return cjks_2evp(jks->pk);
}
