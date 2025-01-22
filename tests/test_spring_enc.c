#include <stdlib.h>
#include <string.h>
#include <iconv.h>
#include <cjks/io.h>
#include <cjks/spring.h>
#include <cjks/cjks.h>
#include "test_base.h"

uchar salt[] = { 0xde, 0xad, 0xbe, 0xef };

int encrypt_data(const uchar* data, size_t dlen, uchar* data_out, uchar* key, size_t klen, uchar* iv) {
    char* keyhex = malloc(klen * 2);
    int keyhexsz = cjks_hex(keyhex, key, klen);
    uchar keybuf[32];

    PKCS5_PBKDF2_HMAC_SHA1(keyhex, keyhexsz, salt, sizeof(salt), 1024, 32, keybuf);

    uchar* pdata = data;
    EVP_CIPHER_CTX* cipher = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(cipher, EVP_aes_256_cbc(), keybuf, iv);

    uchar* pdata_out = data_out;
    int data_out_i;

    EVP_EncryptUpdate(cipher, pdata_out, &data_out_i, pdata, dlen);
    pdata_out += data_out_i;

    EVP_EncryptFinal(cipher, pdata_out, &data_out_i);
    pdata_out += data_out_i;

    return (int)(pdata_out - data_out);
}

size_t encrypt_key(EVP_PKEY* pk, uchar* key, size_t klen, uchar* ekey) {
    EVP_PKEY_CTX* evp_ctx = EVP_PKEY_CTX_new(pk, NULL);
    size_t ekey_len;
    EVP_PKEY_encrypt_init(evp_ctx);
    EVP_PKEY_encrypt(evp_ctx, ekey, &ekey_len, key, klen);

    return ekey_len;
}

int do_encrypt(EVP_PKEY* pk, const uchar* data, size_t len, uchar* dbuf) {
    uchar edata[256];

    uchar key[16];
    uchar iv[16];

    uchar ekey[256];

    RAND_priv_bytes(key, 16);
    RAND_bytes(iv, 16);

    int elen = encrypt_data(data, len, edata, key, 16, iv);
    size_t ekey_len = encrypt_key(pk, key, 16, ekey);

    // ekey_len ekey iv data
    cjks_b64_t* b64 = cjks_b64_encoder();
    ushort kl = cjks_htons(ekey_len);
    int i = cjks_b64_update(b64, &kl, 2, dbuf);
    i += cjks_b64_update(b64, ekey, ekey_len, dbuf + i);
    i += cjks_b64_update(b64, iv, 16, dbuf + i);
    i += cjks_b64_update(b64, edata, elen, dbuf + i);
    i += cjks_b64_final(b64, dbuf + i);
    cjks_b64_free(b64);

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

    const char c[] = "hello";
    char b64_dbuf[1024];
    int b64_len = do_encrypt(pk, c, sizeof(c) - 1, b64_dbuf);

    printf("Config %.*s\n", b64_len, b64_dbuf);

    b64_len = cjks_spring_decrypt(pk, b64_dbuf, b64_len, b64_dbuf);
    printf("Config %.*s\n", b64_len, b64_dbuf);

}

CJKS_TESTS_ST
CJKS_TEST(test_spring_enc)
CJKS_TESTS_END