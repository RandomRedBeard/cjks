#ifndef BITS_CJKS_H
#define BITS_CJKS_H

#define cjks_buf2be(type, name)                   \
    type cjks_buf2be_##name(const void *buf) {    \
        const unsigned char* ptr = buf;           \
        type r = 0;                               \
        for (int i = 0; i < sizeof(type); i++) {  \
            int u = sizeof(type) - i - 1;         \
            r |= (type) * (ptr + i) << (u * 8);   \
        }                                         \
        return r;                                 \
    }

static cjks_buf2be(unsigned short, 2)
static cjks_buf2be(unsigned int, 4)
static cjks_buf2be(unsigned long long, 8)

#ifdef _WIN32
#include <WinSock2.h>
#define cjks_ntohs_f ntohs
#define cjks_ntohi_f ntohl
#define cjks_ntohll_f ntohll
#else
#include <endian.h>
#define cjks_ntohs_f be16toh
#define cjks_ntohi_f be32toh
#define cjks_ntohll_f be64toh
#endif

#include <cjks/lib.h>

CJKS_DLL unsigned short cjks_ntohs(const void* v);
CJKS_DLL unsigned int cjks_ntohi(const void* v);
CJKS_DLL unsigned long long cjks_ntohll(const void* v);

#endif