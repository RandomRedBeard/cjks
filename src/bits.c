#include "cjks/bits.h"

unsigned short cjks_ntohs(const void* v) {
    const unsigned short* s = v;
    return cjks_ntohs_f(*s);
}

unsigned int cjks_ntohi(const void* v) {
    const unsigned int* i = v;
    return cjks_ntohi_f(*i);
}

unsigned long long cjks_ntohll(const void* v) {
    const unsigned long long* l = v;
    return cjks_ntohll_f(*l);
}