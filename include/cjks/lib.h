#ifndef CJKS_LIB_H
#define CJKS_LIB_H

#ifdef _WIN32
    #ifdef CJKS_DLL_EXPORT
        #define CJKS_DLL __declspec(dllexport)
    #elif defined(CJKS_STATIC)
        #define CJKS_DLL
    #else
        #define CJKS_DLL __declspec(dllimport)
    #endif // CJKS_DLL_EXPORT
#else
    #define CJKS_DLL
#endif // _WIN32

typedef unsigned char u_char;

#endif // Header
