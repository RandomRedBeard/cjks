#include "cjks/cjks.h"

cjks_ca* cjks_ca_new() {
    return calloc(1, sizeof(cjks_ca));
}

cjks_ca* cjks_ca_from_x509(X509* x) {
    cjks_ca* ca = cjks_ca_new();
    int len = i2d_X509(x, NULL);
    uchar* cacert;
    if (len < 0) {
        cjks_ca_free(ca);
        return NULL;
    }

    ca->cert.buf = malloc(len);
    ca->cert.len = len;
    cacert = ca->cert.buf;
    i2d_X509(x, &cacert);
    ca->cert_type = strdup("X.509");
    return ca;
}

void cjks_ca_free(cjks_ca* ca) {
    cjks_ca* n;
    do {
        n = ca->next;
        free(ca->cert_type);
        cjks_buf_clear(&ca->cert);
        free(ca);
        ca = n;
    } while (ca);
}

int cjks_parse_ca(cjks_io* io, cjks_ca* ca) {
    ca->cert_type = cjks_io_aread_utf(io);
    cjks_io_aread_data(io, &ca->cert);
    return 0;
}

int cjks_write_ca(cjks_io* io, cjks_ca* ca) {
    int r1 = cjks_io_write_utf(io, ca->cert_type, strlen(ca->cert_type));
    if (r1 < 0) {
        return r1;
    }
    int r2 = cjks_io_write_data(io, &ca->cert);
    return r2 < 0 ? r2 : r1 + r2;
}
