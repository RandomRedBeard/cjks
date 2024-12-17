#include "cjks/cjks.h"

cjks_ca* cjks_ca_new() {
    return calloc(1, sizeof(cjks_ca));
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
