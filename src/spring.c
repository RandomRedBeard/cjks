#include "cjks/spring.h"

int cjks_spring_decrypt(EVP_PKEY *pkey, unsigned char *src, size_t slen, unsigned char* dst) {
    unsigned char salt[] = { 0xde, 0xad, 0xbe, 0xef };
    unsigned char *strptr = src, *dstr = dst, key[256], keybuf[32];
    char keyhex[32];
    int dstrlen, keyhexsz, dlen;
    unsigned short keylen;
    size_t keysz = sizeof(key);

    EVP_PKEY_CTX *evp_ctx = NULL;
    EVP_CIPHER_CTX *cipher = NULL;

    if ((dlen = cjks_b64decode(src, src, slen)) < 0) {
        goto error;
    }
    keylen = cjks_ntohs(*(unsigned short*)strptr);
    strptr += 2;

    evp_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_decrypt_init(evp_ctx);
    if (!EVP_PKEY_decrypt(evp_ctx, key, &keysz, strptr, keylen)) {
        goto error;
    }
    strptr += keylen;

    keyhexsz = cjks_hex(keyhex, key, keysz);
    if (!PKCS5_PBKDF2_HMAC_SHA1(keyhex, keyhexsz, salt, sizeof(salt), 1024, 32, keybuf)) {
        goto error;
    }

    cipher = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit(cipher, EVP_aes_256_cbc(), keybuf, strptr)) {
        goto error;
    }

    // IV
    strptr += 16;

    if (!EVP_DecryptUpdate(cipher, dstr, &dstrlen, strptr, dlen - 2 - keylen - 16)) {
        goto error;
    }
    dstr += dstrlen;
    if (!EVP_DecryptFinal(cipher, dstr, &dstrlen)) {
        goto error;
    }
    dstr += dstrlen;

    EVP_PKEY_CTX_free(evp_ctx);
    EVP_CIPHER_CTX_free(cipher);

    return (int)(dstr - dst);

error:
    ERR_print_errors_fp(stdout);
    if (evp_ctx) {
        EVP_PKEY_CTX_free(evp_ctx);
    }
    if (cipher) {
        EVP_CIPHER_CTX_free(cipher);
    }
    return -1;

}

int cjks_spring_decrypt2(cjks* jks, unsigned char *src, size_t slen, unsigned char* dst) {
    EVP_PKEY* pk = cjks_2evp2(jks);
    if (!pk) {
        return -1;
    }

    int i = cjks_spring_decrypt(pk, src, slen, dst);
    EVP_PKEY_free(pk);

    return i;
}
