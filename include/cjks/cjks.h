#ifndef CJKS_H
#define CJKS_H

#include <string.h>

#include <iconv.h>

#include <openssl/err.h>
#include <openssl/pkcs12.h>

#include <cjks/lib.h>
#include <cjks/io.h>
#include <cjks/bits.h>
#include <cjks/utl.h>

#define CJKS_PRIVATE_KEY_TAG 1
#define CJKS_TRUSTED_CERT_TAG 2

static const char cjks_jks_magic_number[] = "\xFE\xED\xFE\xED";

typedef struct cjks_ca_st {
    char *cert_type;
    cjks_buf cert;
    struct cjks_ca_st *next;
} cjks_ca;

typedef struct cjks_pkey_st {
    cjks_buf encrypted_ber;
    cjks_buf key;
    cjks_ca *cert_chain;
} cjks_pkey;

typedef struct cjks_entry_st {
    int tag; // PKEY or CA
    char *alias;
    unsigned long long ts;
    union {
        cjks_pkey* pk;
        cjks_ca* ca;
    } entry;
    struct cjks_entry_st *next;
} cjks;

CJKS_DLL cjks* cjks_parse(cjks_io* io, const char* password, size_t len);
CJKS_DLL cjks* cjks_parse_ex(cjks_io* io, char* password, size_t len, const char* encoding);
CJKS_DLL cjks* cjks_get(cjks* jks, const char* alias);
CJKS_DLL cjks *cjks_new(int tag);
CJKS_DLL void cjks_free(cjks* jks);
CJKS_DLL cjks_ca *cjks_ca_new();
CJKS_DLL void cjks_ca_free(cjks_ca* ca);
CJKS_DLL int cjks_parse_ca(cjks_io* io, cjks_ca* ca);
CJKS_DLL cjks_pkey* cjks_pk_new();
CJKS_DLL void cjks_pk_free(cjks_pkey* pk);
CJKS_DLL int cjks_parse_pk(cjks_io* io, cjks_pkey* pk);
CJKS_DLL int cjks_parse_eber(const cjks_buf *eber, ASN1_TYPE** ber);
CJKS_DLL void cjks_keystream(unsigned char *cur, const char *password, size_t plen);
CJKS_DLL int cjks_decrypt_pk(cjks_pkey* pk, const char* password, size_t len);
CJKS_DLL EVP_PKEY *cjks_2evp(const cjks_pkey *pkey);

#endif