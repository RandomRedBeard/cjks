#include "cjks/spring.h"

int cjks_spring_decrypt(EVP_PKEY *pkey, uchar *src, size_t slen, uchar* dst) {
    uchar *strptr = src, *dstr = dst, *key, keybuf[32];
    char keyhex[32];
    int dstrlen, keyhexsz, dlen;
    uint16 keylen;
    size_t keysz;
    EVP_PKEY_CTX *evp_ctx = EVP_PKEY_CTX_new(pkey, NULL);;
    EVP_CIPHER_CTX *cipher = EVP_CIPHER_CTX_new();

    if ((dlen = cjks_b64decode(src, src, slen)) < 0) {
        goto error;
    }
    keylen = cjks_ntohs(*(uint16*)strptr);
    strptr += 2;

    EVP_PKEY_decrypt_init(evp_ctx);
    keysz = EVP_PKEY_get_size(pkey);
    key = malloc(keysz);
    if (!EVP_PKEY_decrypt(evp_ctx, key, &keysz, strptr, keylen)) {
        goto error;
    }
    strptr += keylen;

    keyhexsz = cjks_hex(keyhex, key, keysz);
    if (!PKCS5_PBKDF2_HMAC_SHA1(keyhex, keyhexsz, CJKS_SPRING_SALT, sizeof(CJKS_SPRING_SALT), 1024, 32, keybuf)) {
        goto error;
    }

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

    free(key);
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
    if (key) {
        free(key);
    }
    return -1;

}

int cjks_spring_decrypt2(cjks* jks, uchar *src, size_t slen, uchar* dst) {
    EVP_PKEY* pk = cjks_2evp2(jks);
    if (!pk) {
        return -1;
    }

    int i = cjks_spring_decrypt(pk, src, slen, dst);
    EVP_PKEY_free(pk);

    return i;
}

int cjks_spring_encrypt(EVP_PKEY* pk, const uchar* src, size_t len, uchar* dst) {
    uchar key[16];
    uchar iv[16];
    uchar* ekey = NULL;
    EVP_PKEY_CTX* evp_ctx = EVP_PKEY_CTX_new(pk, NULL);
    size_t ekey_len = sizeof(ekey); // len
    char keyhex[32]; // hex
    uchar keybuf[32]; // kdf
    EVP_CIPHER_CTX* cipher = EVP_CIPHER_CTX_new(); // CBC
    const uchar* esrc = src + len;
    uchar buf[4096];
    int buflen;
    uint16 nkl;
    int keyhexsz;
    int i = 0;
    cjks_b64_t* b64 = cjks_b64_encoder();

    // Initialize
    RAND_priv_bytes(key, 16);
    RAND_bytes(iv, 16);
    keyhexsz = cjks_hex(keyhex, key, 16);

    PKCS5_PBKDF2_HMAC_SHA1(keyhex, keyhexsz, CJKS_SPRING_SALT, sizeof(CJKS_SPRING_SALT), 1024, 32, keybuf);
    EVP_EncryptInit(cipher, EVP_aes_256_cbc(), keybuf, iv);

    // Encrypt Key
    EVP_PKEY_encrypt_init(evp_ctx);
    ekey_len = EVP_PKEY_get_size(pk);
    ekey = malloc(ekey_len);
    EVP_PKEY_encrypt(evp_ctx, ekey, &ekey_len, key, sizeof(key));

    // Prep for encoding
    nkl = cjks_htons((uint16)ekey_len);
    i = cjks_b64_update(b64, &nkl, 2, dst);
    i += cjks_b64_update(b64, ekey, ekey_len, dst + i);
    i += cjks_b64_update(b64, iv, sizeof(iv), dst + i);

    // Encrypt and Encode data
    while (src != esrc) {
        int clen = esrc - src;
        if (clen > sizeof(buf)) {
            clen = sizeof(buf);
        }
        int l = EVP_EncryptUpdate(cipher, buf, &buflen, src, clen);
        i += cjks_b64_update(b64, buf, buflen, dst + i);
        src += clen;
    }

    EVP_EncryptFinal(cipher, buf, &buflen);
    i += cjks_b64_update(b64, buf, buflen, dst + i);
    i += cjks_b64_final(b64, dst + i);

cleanup:
    if (evp_ctx) {
        EVP_PKEY_CTX_free(evp_ctx);
    }

    if (cipher) {
        EVP_CIPHER_CTX_free(cipher);
    }

    if (b64) {
        cjks_b64_free(b64);
    }

    if (ekey) {
        free(ekey);
    }

    return i;
}