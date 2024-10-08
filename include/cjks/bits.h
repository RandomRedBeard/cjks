#ifndef BITS_CJKS_H
#define BITS_CJKS_H

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