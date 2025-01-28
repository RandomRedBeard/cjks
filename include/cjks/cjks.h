#ifndef CJKS_H
#define CJKS_H

#include <string.h>

#include <iconv.h>

#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>

#include <cjks/lib.h>
#include <cjks/io.h>
#include <cjks/bits.h>
#include <cjks/base64.h>
#include <cjks/sha1io.h>

#define CJKS_PRIVATE_KEY_TAG 1
#define CJKS_TRUSTED_CERT_TAG 2

static const uchar JKS_MAGIC_NUMBER[] = {0xFE, 0xED, 0xFE, 0xED};
static const uchar SUN_JKS_ALGO_ID[] = { 43,6,1,4,1,42,2,17,1,1 };
static const uchar CJKS_SIGWHITE[] = "Mighty Aphrodite";

typedef struct cjks_ca_st {
    char* cert_type;
    cjks_buf cert;
    uint32 n;
    struct cjks_ca_st* next;
} cjks_ca;

typedef struct cjks_pkey_st {
    cjks_buf encrypted_ber;
    cjks_buf key;
    cjks_ca* cert_chain;
} cjks_pkey;

typedef struct cjks_entry_st {
    int tag; // PKEY or CA
    char* alias;
    uint64 ts;
    union {
        cjks_pkey* pk;
        cjks_ca* ca;
    };
    uint32 n;
    struct cjks_entry_st* next;
} cjks;

/**
 * CA
 */

CJKS_DLL cjks_ca* cjks_ca_new();
CJKS_DLL cjks_ca* cjks_ca_from_x509(X509*);
CJKS_DLL cjks_ca* cjks_ca_add(cjks_ca* src, cjks_ca* dst);
CJKS_DLL void cjks_ca_free(cjks_ca* ca);
CJKS_DLL int cjks_parse_ca(cjks_io* io, cjks_ca* ca);
CJKS_DLL int cjks_write_ca(cjks_io* io, cjks_ca* ca);

/**
 * PK
 */

CJKS_DLL cjks_pkey* cjks_pk_new();
CJKS_DLL void cjks_pk_free(cjks_pkey* pk);
CJKS_DLL int cjks_parse_pk(cjks_io* io, cjks_pkey* pk);
CJKS_DLL int cjks_parse_eber(const cjks_buf* eber, X509_SIG** sig);
CJKS_DLL int cjks_decrypt_pk(cjks_pkey* pk, const char* password, size_t len);
CJKS_DLL int cjks_encrypt_pk(cjks_pkey* pk, const char* password, size_t len);
CJKS_DLL int cjks_write_pk(cjks_io* io, cjks_pkey* pk, const char* password, size_t len);

CJKS_DLL EVP_PKEY* cjks_2evp(const cjks_pkey* pkey);

/**
 * CRYPT
 */

CJKS_DLL void cjks_sun_jks_crypt(const uchar* src, uchar* dest, size_t len, uchar* iv, const char* password, size_t plen);
CJKS_DLL int cjks_sun_jks_decrypt(const uchar* data, uchar* dest, int dlen, const char* password, size_t plen);

/**
 * @brief dest should be dlen + (SHALEN * 2)
 *
 * @param src
 * @param dest
 * @param dlen
 * @param password
 * @param plen
 * @return CJKS_DLL
 */
CJKS_DLL int cjks_sun_jks_encrypt(const uchar* src, uchar* dest, int dlen, const char* password, size_t plen);

/**
 * CJKS
 */

CJKS_DLL cjks* cjks_parse(cjks_io* io, const char* password, size_t len);
CJKS_DLL cjks* cjks_parse_ex(cjks_io* io, char* password, size_t len, const char* encoding);
CJKS_DLL cjks* cjks_parse_ex2(const char* pth, char* password, size_t len, const char* encoding);

CJKS_DLL int cjks_write_jks_header(cjks_io* io, cjks* jks);
CJKS_DLL int cjks_write_jks_entry(cjks_io* io, cjks* jks, const char* password, size_t len);
CJKS_DLL int cjks_write_jks(cjks_io* io, cjks* jks, const char* password, size_t len);

CJKS_DLL cjks* cjks_get(cjks* jks, const char* alias);

CJKS_DLL cjks* cjks_new(int tag);
CJKS_DLL void cjks_free(cjks* jks);

CJKS_DLL EVP_PKEY* cjks_2evp2(const cjks* jks);

#endif
