#ifndef CJKS_HEX_H
#define CJKS_HEX_H

#include <cjks/lib.h>
#include <cjks/bits.h>

static const char cjks_hex_chars[] = "0123456789abcdef";

/**
 * @brief bin2hex. src and dest cannot overlap
 * 
 * @param dest 
 * @param src 
 * @param len 
 * @return int 
 */
CJKS_DLL int cjks_hex(char *dest, const uchar *src, size_t len);

#endif