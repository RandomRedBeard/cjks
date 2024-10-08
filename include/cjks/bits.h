#ifndef BITS_CJKS_H
#define BITS_CJKS_H

#ifdef HAS_ENDIAN_H
    #include <endian.h>
    #define cjks_ntohs_f be16toh
    #define cjks_ntohi_f be32toh
    #define cjks_ntohll_f be64toh
#elif defined _WIN32 // Windows
    #include <WinSock2.h>
    #define cjks_ntohs_f ntohs
    #define cjks_ntohi_f ntohl
    #define cjks_ntohll_f ntohll
#elif defined __APPLE__ // No endian.h and not win32
    #include <libkern/OSByteOrder.h>
    #define cjks_ntohs_f OSSwapBigToHostInt16
    #define cjks_ntohi_f OSSwapBigToHostInt32
    #define cjks_ntohll_f OSSwapBigToHostInt64
#endif 

#include <cjks/lib.h>

CJKS_DLL unsigned short cjks_ntohs(const void* v);
CJKS_DLL unsigned int cjks_ntohi(const void* v);
CJKS_DLL unsigned long long cjks_ntohll(const void* v);

#endif