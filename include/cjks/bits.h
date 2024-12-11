#ifndef BITS_CJKS_H
#define BITS_CJKS_H

#ifdef HAS_ENDIAN_H
    #include <endian.h>
    #define cjks_ntohs be16toh
    #define cjks_ntohi be32toh
    #define cjks_ntohll be64toh

    #define cjks_htons htobe16
    #define cjks_htoni htobe32
    #define cjks_htonll htobe64
#elif defined _WIN32 // Windows
    #include <WinSock2.h>
    #define cjks_ntohs ntohs
    #define cjks_ntohi ntohl
    #define cjks_ntohll ntohll

    #define cjks_htons htons
    #define cjks_htoni htonl
    #define cjks_htonll htonll
#elif defined __APPLE__ // No endian.h and not win32
    #include <libkern/OSByteOrder.h>
    #define cjks_ntohs OSSwapBigToHostInt16
    #define cjks_ntohi OSSwapBigToHostInt32
    #define cjks_ntohll OSSwapBigToHostInt64

    #define cjks_htons OSSwapHostToBigInt16
    #define cjks_htoni OSSwapHostToBigInt32
    #define cjks_htonll OSSwapHostToBigInt64
#endif

#endif
