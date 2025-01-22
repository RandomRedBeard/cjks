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

int cjks_b64_encode_chunk(cjks_b64_t* b, void* dst) {
    uchar* dptr = dst;
    b->b = cjks_htoni(b->b);
    for (int j = 0; j < b->i + 1; j++) {
        *dptr++ = CJKS_BASE64_CHARS[b->b >> 26];
        b->b = b->b << 6;
    }
    return dptr - (uchar*)dst;
}

int cjks_b64_encode_update(cjks_b64_t* b, const void* src, size_t len, void* dst) {
    const uchar* psrc = src, * psrce = psrc + len;
    uchar* dptr = dst;

    while (psrc != psrce) {
        *(((uchar*)&b->b) + b->i++) = *psrc++;
        if (b->i == 3) {
            dptr += cjks_b64_encode_chunk(b, dptr);
            b->i = 0;
            b->b = 0;
        }
    }


    return dptr - (uchar*)dst;
}


int cjks_b64_encode_final(cjks_b64_t* b, void* dst) {
    if (b->i == 0) {
        return 0;
    }

    uchar* dptr = (uchar*)dst + cjks_b64_encode_chunk(b, dst);
    b->i = 3 - b->i;
    dptr = (uchar*)memcpy(dptr, "==", b->i) + b->i;

    return dptr - (uchar*)dst;
}


int cjks_b64_decode_update(cjks_b64_t* b, const void* src, size_t len, void* dst) {
    const uchar* psrc = src, * psrce = psrc + len;
    uchar* dptr = dst, cp;
    int index;

    while (psrc != psrce) {
        if (*psrc == '\n' || *psrc == '\r') {
            psrc++;
            continue;
        }

        // Expecting pad
        if (b->p > 0 && *psrc != '=') {
            return -1;
        }

        if (*psrc == '=') { // Pad
            if (b->p == 2) {
                return -1;
            }
            b->p++;
        }
        else { // Value
            index = cjks_b64i(*psrc);
            if (index < 0) {
                return -1;
            }
            b->b |= index << (2 + (6 * (4 - b->i++)));
        }

        psrc++;

        if (b->i + b->p == 4) {
            b->b = cjks_ntohi(b->b);
            cp = (b->p == 0 ? 3 : 3 - b->p);
            dptr = (uchar*)memcpy(dptr, &b->b, cp) + cp;
            b->b = 0;
            b->i = 0;
        }
    }

    return dptr - (uchar*)dst;
}

int cjks_b64_decode_final(cjks_b64_t* b, void* dst) {
    if (b->i > 0) {
        return -1;
    }
    return 0;
}

static struct cjks_b64_vt cjks_b64_decoder_vt = {
    cjks_b64_decode_update, cjks_b64_decode_final
};

static struct cjks_b64_vt cjks_b64_encoder_vt = {
    cjks_b64_encode_update, cjks_b64_encode_final
};

cjks_b64_t* cjks_b64_encoder() {
    cjks_b64_t* b = malloc(sizeof(cjks_b64_t));
    b->b = b->i = b->p = 0;
    b->vt = &cjks_b64_encoder_vt;
    return b;
}

cjks_b64_t* cjks_b64_decoder() {
    cjks_b64_t* b = malloc(sizeof(cjks_b64_t));
    b->b = b->i = b->p = 0;
    b->vt = &cjks_b64_decoder_vt;
    return b;
}

void cjks_b64_free(cjks_b64_t* b) {
    free(b);
}

int cjks_b64_update(cjks_b64_t* b, const void* src, size_t len, void* dst) {
    return b->vt->update(b, src, len, dst);
}

int cjks_b64_final(cjks_b64_t* b, void* dst) {
    return b->vt->final(b, dst);
}

int cjks_b64decode(uchar* dest, const uchar* src, size_t len) {
    cjks_b64_t* b = cjks_b64_decoder();
    int i = cjks_b64_update(b, src, len, dest);
    if (i < 0) {
        cjks_b64_free(b);
        return -1;
    }

    int j = cjks_b64_final(b, dest + i);
    if (j < 0) {
        cjks_b64_free(b);
        return -1;
    }
    cjks_b64_free(b);
    return i + j;
}

int cjks_b64encode(uchar* dest, const uchar* src, size_t len) {
    cjks_b64_t* b = cjks_b64_encoder();
    int i = cjks_b64_update(b, src, len, dest);
    if (i < 0) {
        cjks_b64_free(b);
        return -1;
    }

    int j = cjks_b64_final(b, dest + i);
    if (j < 0) {
        cjks_b64_free(b);
        return -1;
    }
    cjks_b64_free(b);
    return i + j;
}
