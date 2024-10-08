#include "cjks/utl.h"

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
