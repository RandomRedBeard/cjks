#include "cjks/utl.h"
#include "private/debug.h"

int cjks_b64decode(unsigned char *dest, const unsigned char *src, size_t len) {
    unsigned char *dptr = dest;
    int dlen;
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    EVP_DecodeInit(ctx);
    if (EVP_DecodeUpdate(ctx, dptr, &dlen, src, (int)len) < 0) {
        EVP_ENCODE_CTX_free(ctx);
        return -1;
    }
    dptr += dlen;
    if (EVP_DecodeFinal(ctx, dptr, &dlen) < 0) {
        EVP_ENCODE_CTX_free(ctx);
        return -1;
    }

    EVP_ENCODE_CTX_free(ctx);
    return (int)(dptr + dlen - dest);
}

int cjks_b64encode(unsigned char *dest, const unsigned char *src, size_t len) {
    unsigned char *dptr = dest;
    int dlen;
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    EVP_EncodeInit(ctx);
    if (EVP_EncodeUpdate(ctx, dptr, &dlen, src, (int)len) < 0) {
        EVP_ENCODE_CTX_free(ctx);
        return -1;
    }
    dptr += dlen;
    EVP_EncodeFinal(ctx, dptr, &dlen);
    dptr += dlen;
    EVP_ENCODE_CTX_free(ctx);
    return (int)(dptr - dest);
}

char cjks_v2a(int c) {
    return cjks_hex_chars[c];
}

int cjks_hex(char *dest, const unsigned char *src, size_t len) {
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
    unsigned int olen;
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
    unsigned char sha2[SHA_DIGEST_LENGTH];
    va_list args;
    va_start(args, n);
    if (cjks_vsha1(sha2, n, args) < 0) {
        va_end(args);
        return -1;
    }
    va_end(args);
    return memcmp(sha1, sha2, SHA_DIGEST_LENGTH) == 0;
}