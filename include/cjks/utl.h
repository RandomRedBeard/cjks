#ifndef CJKS_UTL_H
#define CJKS_UTL_H

#include <openssl/evp.h>
#include <cjks/lib.h>

static const char cjks_hex_chars[] = "0123456789abcdef";

CJKS_DLL int cjks_b64decode(unsigned char *dest, const unsigned char *src, size_t len);
CJKS_DLL int cjks_b64encode(unsigned char *dest, const unsigned char *src, size_t len);

/**
 * dest and src should not overlap (one byte from src is written to 2 bytes in dest)
 */
CJKS_DLL int cjks_hex(char *dest, const unsigned char *src, size_t len);

#endif