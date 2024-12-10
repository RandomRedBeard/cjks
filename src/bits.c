#include "cjks/bits.h"

unsigned short cjks_ntohs(const void* v) {
    return cjks_ntohs_f(*(const unsigned short*)v);
}

unsigned int cjks_ntohi(const void* v) {
    return cjks_ntohi_f(*(const unsigned int*)v);
}

unsigned long long cjks_ntohll(const void* v) {
    return cjks_ntohll_f(*(const unsigned long long*)v);
}

unsigned int cjks_htoni(const void* v) {
    return cjks_htoni_f(*(const unsigned int*)v);
}
