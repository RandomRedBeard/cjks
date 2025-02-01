#ifndef CJKS_ARGS_H
#define CJKS_ARGS_H

#include <cjks/lib.h>

typedef struct arg_st {
    const char* lname;
    const char* sname;
    const char* desc;
    void* v;
    uint8 offset;
    int flags;
} arg_t;

#endif