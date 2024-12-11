#ifndef BITS_CJKS_H
#define BITS_CJKS_H

#ifdef HAS_ENDIAN_H
    #include <endian.h>
    #define cjks_ntohs be16toh
    #define cjks_ntohi be32toh
    #define cjks_ntohll be64toh

    #define cjks_htoni htobe32
#elif defined _WIN32 // Windows
    #include <WinSock2.h>
    #define cjks_ntohs ntohs
    #define cjks_ntohi ntohl
    #define cjks_ntohll ntohll

    #define cjks_htoni htonl
#elif defined __APPLE__ // No endian.h and not win32
    #include <libkern/OSByteOrder.h>
    #define cjks_ntohs OSSwapBigToHostInt16
    #define cjks_ntohi OSSwapBigToHostInt32
    #define cjks_ntohll OSSwapBigToHostInt64

    #define cjks_htoni OSSwapHostToBigInt32
#endif

#endif
