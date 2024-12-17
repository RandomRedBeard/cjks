#include "cjks/sha1io.h"

int cjks_io_sha1_read(cjks_io* io, void* v, size_t len) {
    struct cjks_io_sha1_st* sio = (struct cjks_io_sha1_st*)io;
    int i = cjks_io_read(sio->_u, v, len);
    if (i < 0) {
        return i;
    }

    cjks_sha1_cnsm(sio->sh, v, i);
    return i;
}

int cjks_io_sha1_write(cjks_io* io, const void* v, size_t len) {
    struct cjks_io_sha1_st* sio = (struct cjks_io_sha1_st*)io;
    cjks_sha1_cnsm(sio->sh, v, len);

    return cjks_io_write(sio->_u, v, len);
}

cjks_io_vt cjks_io_sha1_vt = { cjks_io_sha1_read, cjks_io_sha1_write, NULL };

cjks_io* cjks_io_sha1_new(cjks_io* _u, cjks_sha1_t* sh) {
    struct cjks_io_sha1_st* sio = calloc(1, sizeof(struct cjks_io_sha1_st));
    sio->_io.vt = &cjks_io_sha1_vt;
    sio->_u = _u;
    if (sh) {
        sio->sh = sh;
    }
    else {
        sio->sh = cjks_sha1_new();
    }

    return &sio->_io;
}

cjks_io* cjks_io_sha1_free(cjks_io* io, int own_sha) {
    struct cjks_io_sha1_st* sio = (struct cjks_io_sha1_st*)io;

    if (own_sha) {
        cjks_sha1_free(sio->sh);
    }

    io = sio->_u;
    free(sio);
    return io;
}
