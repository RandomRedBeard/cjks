#include "cjks/utl.h"

char cjks_v2a(int c) {
    return CJKS_HEX_CHARS[c];
}

int cjks_hex(char *dest, const uchar *src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        *dest++ = cjks_v2a((src[i] >> 4) & 0x0F);
        *dest++ = cjks_v2a((src[i]) & 0x0F);
    }
    return (int)(len * 2);
}

int cjks_sha1(void* out, int n, ...) {
    va_list args;
    va_start(args, n);
    int r = cjks_vsha1(out, n, args);
    va_end(args);
    return r;
}

int cjks_vsha1(void *out, int n, va_list args) {
    uint32 olen;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    void *d = NULL;
    size_t len;

    if (!EVP_DigestInit(ctx, EVP_sha1())) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    for (int i = 0; i < n; i++) {
        d = va_arg(args, void *);
        len = va_arg(args, size_t);

        if (!EVP_DigestUpdate(ctx, d, len)) {
            EVP_MD_CTX_free(ctx);
            return -1;
        }
    }

    if (!EVP_DigestFinal(ctx, out, &olen)) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);

    return olen;
}

int cjks_sha1_cmp(const void* sha1, int n, ...) {
    uchar sha2[SHA_DIGEST_LENGTH];
    va_list args;
    va_start(args, n);
    if (cjks_vsha1(sha2, n, args) < 0) {
        va_end(args);
        return -1;
    }
    va_end(args);
    return memcmp(sha1, sha2, SHA_DIGEST_LENGTH) == 0;
}
