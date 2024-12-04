#include "cjks/utl.h"

#include <openssl/err.h>

int cjks_b64decode(unsigned char *dest, const unsigned char *src, size_t len) {
    unsigned char *dptr = dest;
    int dlen;
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    EVP_DecodeInit(ctx);
    if (EVP_DecodeUpdate(ctx, dptr, &dlen, src, (int)len) < 0) {
        printf("Error Decode Update\n");
        ERR_print_errors_fp(stdout);
        EVP_ENCODE_CTX_free(ctx);
        return -1;
    }
    dptr += dlen;
    if (EVP_DecodeFinal(ctx, dptr, &dlen) < 0) {
        printf("Error Decode Final\n");
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


int cjks_sha1(const void *in, size_t ilen, void *out) {
    unsigned int olen;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!EVP_DigestInit(ctx, EVP_sha1())) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (!EVP_DigestUpdate(ctx, in, ilen)) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (!EVP_DigestFinal(ctx, out, &olen)) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    return 0;
}

int cjks_sha1_cmp(const void *data, size_t ilen, const void *sha) {
    char sha_src[SHA_DIGEST_LENGTH];
    if (cjks_sha1(data, ilen, sha_src) < 0) {
        return -1;
    }
    return memcmp(sha_src, sha, SHA_DIGEST_LENGTH) == 0;
}
