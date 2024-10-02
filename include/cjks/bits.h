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

#endif