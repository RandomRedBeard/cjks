#ifndef CJKS_UTL_H
#define CJKS_UTL_H


#include <string.h>
#include <stdarg.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <cjks/lib.h>
#include <cjks/bits.h>

static const char cjks_hex_chars[] = "0123456789abcdef";
static const char cjks_base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

CJKS_DLL int cjks_b64decode(u_char *dest, const u_char *src, size_t len);

/**
 * @brief b64 encode. src and dest cannot overlap
 * 
 * @param dest 
 * @param src 
 * @param len 
 * @return int 
 */
CJKS_DLL int cjks_b64encode(u_char *dest, const u_char *src, size_t len);

/**
 * @brief bin2hex. src and dest cannot overlap
 * 
 * @param dest 
 * @param src 
 * @param len 
 * @return int 
 */
CJKS_DLL int cjks_hex(char *dest, const u_char *src, size_t len);

CJKS_DLL int cjks_sha1(void* out, int n, ...);
CJKS_DLL int cjks_vsha1(void* out, int n, va_list args);
CJKS_DLL int cjks_sha1_cmp(const void* sha1, int n, ...);

#endif
