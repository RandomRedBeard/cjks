#include "cjks/utl.h"

char cjks_b64i(char c) {
    switch (c) {
    case '+':
        return 62;
    case '/':
        return 63;
    }

    char f = (c & (3 << 5));
    char r = 0;

    switch (f) {
    case 32: // 0
        r = c - '0';
        return r < 10 ? 52 + r : -1;
    case 64: // A
        r = c - 'A';
        return r < 27 ? r : -1;
    case 96: // a
        r = c - 'a';
        return r < 27 ? 26 + r : -1;
    default:
        return -1;
    }
}

int cjks_b64decode(uchar* dest, const uchar* src, size_t len) {
    const uchar* psrce = src + len;
    uchar* dptr = dest;

    uint32 l, i;
    char index, pcnt = 0, cp;
    while (src != psrce) {
        l = 0;
        for (i = 0; i < 4 && src != psrce; i++) {
            if (*src == '\n' || *src == '\r') {
                src++;
                i--;
                continue;
            }
            // Expecting pad
            if (pcnt > 0 && *src != '=') {
                return -1;
            }

            if (*src == '=') { // Pad
                if (pcnt == 2) {
                    return -1;
                }
                pcnt++;
            }
            else { // Value
                index = cjks_b64i(*src);
                if (index < 0) {
                    return -1;
                }
                l |= (int)index << (2 + (6 * (4 - i)));
            }
            src++;
        }

        if (i == 0) {
            break;
        }
        if (i != 4) {
            return -1;
        }

        // Covers BigE case
        l = cjks_ntohi(l);
        cp = (pcnt == 0 ? 3 : 3 - pcnt);
        dptr = (uchar*)memcpy(dptr, &l, cp) + cp;
    }

    return (int)(dptr - dest);
}

int cjks_b64encode(uchar* dest, const uchar* src, size_t len) {
    const uchar* psrce = src + len;
    const uchar* padst = psrce - (len % 3);
    uchar* dptr = dest;

    uint32 l;
    int j;
    char cp = 3;
    while (src != psrce) {

        // Lazy pad calculation
        if (src == padst) {
            cp = (char)(psrce - src);
        }

        // Copy max 3 bytes
        l = 0;
        memcpy(&l, src, cp);
        src += cp;
        l = cjks_htoni(l);
        for (j = 0; j < cp + 1; j++) {
            *dptr++ = cjks_base64_chars[l >> 26];
            l = l << 6;
        }

        if (cp < 3) {
            cp = 3 - cp;
            dptr = (uchar*)memcpy(dptr, "==", cp) + cp;
        }
    }

    return (int)(dptr - dest);
}

char cjks_v2a(int c) {
    return cjks_hex_chars[c];
}

int cjks_hex(char *dest, const uchar *src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        *dest++ = cjks_v2a((src[i] >> 4) & 0x0F);
        *dest++ = cjks_v2a((src[i]) & 0x0F);
    }
    return (int)(len * 2);
}

int cjks_sha1(void* out, int n, ...) {
    va_list args;
    va_start(args, n);
    int r = cjks_vsha1(out, n, args);
    va_end(args);
    return r;
}

int cjks_vsha1(void *out, int n, va_list args) {
    uint32 olen;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    void *d = NULL;
    size_t len;

    if (!EVP_DigestInit(ctx, EVP_sha1())) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    for (int i = 0; i < n; i++) {
        d = va_arg(args, void *);
        len = va_arg(args, size_t);

        if (!EVP_DigestUpdate(ctx, d, len)) {
            EVP_MD_CTX_free(ctx);
            return -1;
        }
    }

    if (!EVP_DigestFinal(ctx, out, &olen)) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);

    return olen;
}

int cjks_sha1_cmp(const void* sha1, int n, ...) {
    uchar sha2[SHA_DIGEST_LENGTH];
    va_list args;
    va_start(args, n);
    if (cjks_vsha1(sha2, n, args) < 0) {
        va_end(args);
        return -1;
    }
    va_end(args);
    return memcmp(sha1, sha2, SHA_DIGEST_LENGTH) == 0;
}
