#include <stdlib.h>
#include <string.h>
#include <iconv.h>
#include <cjks/io.h>
#include <cjks/spring.h>
#include <cjks/cjks.h>
#include "private/debug.h"
#include "test_base.h"

int cjks_spring_encrypt(EVP_PKEY* pk, const uchar* src, size_t len, uchar* dst) {
    uchar key[16];
    uchar iv[16];
    uchar ekey[256];
    EVP_PKEY_CTX* evp_ctx = EVP_PKEY_CTX_new(pk, NULL);
    size_t ekey_len; // len
    char keyhex[32]; // hex
    uchar keybuf[32]; // kdf
    EVP_CIPHER_CTX* cipher; // CBC
    const uchar* esrc = src + len;
    uchar buf[32];
    int buflen;
    ushort nkl;
    int keyhexsz;
    int i = 0;
    cjks_b64_t* b64 = cjks_b64_encoder();

    // Initialize
    RAND_priv_bytes(key, 16);
    RAND_bytes(iv, 16);
    keyhexsz = cjks_hex(keyhex, key, 16);

    PKCS5_PBKDF2_HMAC_SHA1(keyhex, keyhexsz, CJKS_SPRING_SALT, sizeof(CJKS_SPRING_SALT), 1024, 32, keybuf);
    cipher = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(cipher, EVP_aes_256_cbc(), keybuf, iv);

    // Encrypt Key
    EVP_PKEY_encrypt_init(evp_ctx);
    EVP_PKEY_encrypt(evp_ctx, ekey, &ekey_len, key, sizeof(key));

    // Prep for encoding
    nkl = cjks_htons((ushort)ekey_len);
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

    return i;
}

void test_spring_enc() {
    cjks_buf pk_buf = CJKS_BUF_INIT;
    cjks_read_from_res("/d.key", &pk_buf);
    pk_buf.len = cjks_b64decode(pk_buf.buf, pk_buf.buf, pk_buf.len);
    printf("%zu\n", pk_buf.len);

    const uchar* pkey = pk_buf.buf;
    EVP_PKEY* pk = d2i_AutoPrivateKey(NULL, &pkey, pk_buf.len);
    assert(pk);

    const char c[] = "hello this is thomas from your cars extended warranty";
    char b64_dbuf[4096];
    int b64_len = cjks_spring_encrypt(pk, c, sizeof(c) - 1, b64_dbuf);
    puts("test");
    printf("Config: %.*s\n", b64_len, b64_dbuf);

    b64_len = cjks_spring_decrypt(pk, b64_dbuf, b64_len, b64_dbuf);
    printf("Config: %.*s\n", b64_len, b64_dbuf);
}

CJKS_TESTS_ST
CJKS_TEST(test_spring_enc)
CJKS_TESTS_END