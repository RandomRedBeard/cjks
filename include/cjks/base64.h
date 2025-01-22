#ifndef CJKS_BASE64_H
#define CJKS_BASE64_H

#include <stddef.h>
#include <string.h>

#include <cjks/bits.h>
#include <cjks/lib.h>

static const char CJKS_BASE64_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

CJKS_DLL char cjks_b64i(char c);
CJKS_DLL int cjks_b64decode(uchar *dest, const uchar *src, size_t len);

/**
 * @brief b64 encode. src and dest cannot overlap
 * 
 * @param dest 
 * @param src 
 * @param len 
 */
CJKS_DLL int cjks_b64encode(uchar *dest, const uchar *src, size_t len);

#endif