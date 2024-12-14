#include "test_base.h"
#include <cjks/utl.h>
#include "private/debug.h"

/**
 * @brief S^n(X)  =  (X << n) OR (X >> 32-n).
 */
uint32 cir_ls(uint32 i, uchar n) {
    return (i << n) | (i >> (32 - n));
}

uint32 seq_f(uchar t, uint32 b, uint32 c, uint32 d) {
    if (t < 20) {
        return (b & c) | ((~b) & d);
    }
    if (t < 40) {
        return b ^ c ^ d;
    }
    if (t < 60) {
        return (b & c) | (b & d) | (c & d);
    }
    return b ^ c ^ d;
}

uint32 seq_k(uchar t) {
    if (t < 20) {
        return 0x5A827999;
    }
    if (t < 40) {
        return 0x6ED9EBA1;
    }
    if (t < 60) {
        return 0x8F1BBCDC;
    }
    return 0xCA62C1D6;
}

typedef struct block_st {
    uint32 words[16];
} block;

typedef struct hash_st {
    uint32 h[5];
} hash;

void init_hash(hash* hs) {
    hs->h[0] = 0x67452301;
    hs->h[1] = 0xEFCDAB89;
    hs->h[2] = 0x98BADCFE;
    hs->h[3] = 0x10325476;
    hs->h[4] = 0xC3D2E1F0;
}

void mpad(block* blk, uint64 len) {
    uchar* mptr = (uchar*)blk + len;
    *mptr = 0x80;
    len = cjks_htonll(len * 8);
    memcpy(&blk->words[14], &len, sizeof(len));
}

int main() {
    block blk;
    memset(&blk, 0, sizeof(blk));
    memcpy(&blk, "This is thomas", sizeof("This is thomas") - 1);
    mpad(&blk, sizeof("This is thomas") - 1);

    for (int i = 0; i < 16; i++) {
        blk.words[i] = cjks_htoni(blk.words[i]);
        showbits(blk.words + i, 4);
    }

    uint32 words[80];
    memcpy(words, &blk, sizeof(blk));

    hash hs;
    init_hash(&hs);

    uint32 a, b, c, d, e, tmp;

    a = hs.h[0];
    b = hs.h[1];
    c = hs.h[2];
    d = hs.h[3];
    e = hs.h[4];

    for (uchar i = 0; i < 80; i++) {
        if (i > 15) {
            // W(t-3) XOR W(t-8) XOR W(t-14) XOR W(t-16)
            words[i] = cir_ls(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);
        }

        // TEMP = S^5(A) + f(t;B,C,D) + E + W(t) + K(t);
        tmp = cir_ls(a, 5) + seq_f(i, b, c, d) + e + words[i] + seq_k(i);

        // E = D;  D = C;  C = S^30(B);  B = A; A = TEMP;
        e = d;
        d = c;
        c = cir_ls(b, 30);
        b = a;
        a = tmp;
    }

    // H0 = H0 + A, H1 = H1 + B, H2 = H2 + C, H3 = H3 + D, H4 = H4 + E.
    hs.h[0] += a;
    hs.h[1] += b;
    hs.h[2] += c;
    hs.h[3] += d;
    hs.h[4] += e;

    for (int i = 0; i < 5; i++) {
        hs.h[i] = cjks_ntohi(hs.h[i]);
    }

    hexprint(&hs, 20);
    printf("Done\n");

    // 375ea55ea6b5cacbfd03ea56d82da9da2114a52e

    return 0;
}