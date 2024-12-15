#include "test_base.h"
#include <cjks/utl.h>
#include "private/debug.h"

#define cir_ls(i, n) ((i << n) | (i >> (32 - n)))

typedef struct block_st {
    uint32 words[16];
    uint32 i;
} block;

typedef struct hash_st {
    uint32 h[5];
    uint64 len;
} hash;

void init_hash(hash* hs) {
    hs->h[0] = 0x67452301;
    hs->h[1] = 0xEFCDAB89;
    hs->h[2] = 0x98BADCFE;
    hs->h[3] = 0x10325476;
    hs->h[4] = 0xC3D2E1F0;

    hs->len = 0;
}

void hash_block(hash* hs, block* blk) {
    for (int i = 0; i < 16; i++) {
        blk->words[i] = cjks_htoni(blk->words[i]);
    }

    uint32 a, b, c, d, e, f, k, tmp;

    a = hs->h[0];
    b = hs->h[1];
    c = hs->h[2];
    d = hs->h[3];
    e = hs->h[4];

    for (uchar i = 0; i < 80; i++) {
        if (i > 15) {
            // W(t-3) XOR W(t-8) XOR W(t-14) XOR W(t-16)
            blk->words[i & 0x0F] = blk->words[i - 3 & 0x0F] ^ blk->words[i - 8 & 0x0F] ^ blk->words[i - 14 & 0x0F] ^ blk->words[i - 16 & 0x0F];
            blk->words[i & 0x0F] = cir_ls(blk->words[i & 0x0F], 1);
        }

        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        }
        else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        }
        else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        }
        else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        // TEMP = S^5(A) + f(t;B,C,D) + E + W(t) + K(t);
        tmp = cir_ls(a, 5) + f + e + blk->words[i & 0x0F] + k;

        // E = D;  D = C;  C = S^30(B);  B = A; A = TEMP;
        e = d;
        d = c;
        c = cir_ls(b, 30);
        b = a;
        a = tmp;
    }

    // H0 = H0 + A, H1 = H1 + B, H2 = H2 + C, H3 = H3 + D, H4 = H4 + E.
    hs->h[0] += a;
    hs->h[1] += b;
    hs->h[2] += c;
    hs->h[3] += d;
    hs->h[4] += e;
}

void process_message(hash* hs, block* blk, uchar* msg, size_t len) {
    hs->len += len;
    for (int i = 0; i < len; i++) {
        ((uchar*)blk)[blk->i++] = msg[i];
        if (blk->i == 64) {
            hash_block(hs, blk);
            blk->i = 0;
        }
    }
}

void finalize_hash(hash* hs, block* blk) {
    uchar* bptr = (uchar*)&blk->words + blk->i;
    *bptr = 0x80;
    memset(bptr + 1, 0, sizeof(blk->words) - blk->i - 1);

    if (blk->i > 55) {
        hash_block(hs, blk);
        memset(&blk->words, 0, sizeof(blk->words));
    }

    uint64 len = cjks_htonll(hs->len * 8);
    memcpy(&blk->words[14], &len, sizeof(len));

    hash_block(hs, blk);
}

int main() {
    hash hs;
    init_hash(&hs);

    block blk;
    blk.i = 0;

    FILE* fp = fopen("README.md", "rb");
    uchar buf[128];
    size_t rlen = 0;
    while ((rlen = fread(buf, 1, sizeof(buf), fp)) > 0) {
        process_message(&hs, &blk, buf, rlen);
    }

    // Padding
    finalize_hash(&hs, &blk);

    for (int i = 0; i < 5; i++) {
        hs.h[i] = cjks_ntohi(hs.h[i]);
    }

    hexprint((uchar*)&hs, 20);
    printf("Done\n");

    return 0;
}