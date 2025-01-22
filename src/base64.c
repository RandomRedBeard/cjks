#include "cjks/base64.h"

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
            *dptr++ = CJKS_BASE64_CHARS[l >> 26];
            l = l << 6;
        }

        if (cp < 3) {
            cp = 3 - cp;
            dptr = (uchar*)memcpy(dptr, "==", cp) + cp;
        }
    }

    return (int)(dptr - dest);
}
