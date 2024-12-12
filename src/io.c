#include "cjks/io.h"

/**
 * BUF functions
 */
void cjks_buf_clear(const cjks_buf* buf) {
    if (buf->buf) {
        free(buf->buf);
    }
}

/**
 * IO functions
 */

int cjks_io_read(cjks_io *io, void *buf, size_t len) {
    if (io->vt->cjks_io_read_fn)
        return io->vt->cjks_io_read_fn(io, buf, len);
    return -1;
}

int cjks_io_write(cjks_io *io, const void *buf, size_t len) {
    if (io->vt->cjks_io_write_fn)
        return io->vt->cjks_io_write_fn(io, buf, len);
    return -1;
}

int cjks_io_close(cjks_io *io) {
    if (io->vt->cjks_io_close_fn)
        return io->vt->cjks_io_close_fn(io);
    return -1;
}

uint16 cjks_io_read_be2(cjks_io *io) {
    uint16 s = 0;
    cjks_io_read(io, &s, sizeof(s));
    return cjks_ntohs(s);
}

uint32 cjks_io_read_be4(cjks_io *io) {
    uint32 i = 0;
    cjks_io_read(io, &i, sizeof(i));
    return cjks_ntohi(i);
}

uint64 cjks_io_read_be8(cjks_io *io) {
    uint64 l = 0;
    cjks_io_read(io, &l, sizeof(l));
    return cjks_ntohll(l);
}

int cjks_io_write_be2(cjks_io* io, uint16 s) {
    s = cjks_htons(s);
    return cjks_io_write(io, &s, 2);
}

int cjks_io_write_be4(cjks_io* io, uint32 i) {
    i = cjks_htoni(i);
    return cjks_io_write(io, &i, 4);
}

int cjks_io_write_be8(cjks_io* io, uint64 l) {
    l = cjks_htonll(l);
    return cjks_io_write(io, &l, 8);
}

char *cjks_io_aread_utf(cjks_io *io) {
    uint16 s = cjks_io_read_be2(io);
    char *v = malloc(s + 1);
    cjks_io_read(io, v, s);
    *(v + s) = 0;
    return v;
}

int cjks_io_aread_data(cjks_io* io, cjks_buf* buf) {
    uint32 i = cjks_io_read_be4(io);
    buf->buf = malloc(i);
    cjks_io_read(io, buf->buf, i);
    buf->len = i;
    return i;
}

int cjks_io_write_utf(cjks_io* io, const char* utf, size_t len) {
    int i = cjks_io_write_be2(io, (uint16)len);
    i += cjks_io_write(io, utf, len);
    return i;
}

int cjks_io_write_data(cjks_io* io, cjks_buf* buf) {
    int i = cjks_io_write_be4(io, (uint32)buf->len);
    i += cjks_io_write(io, buf->buf, buf->len);
    return i;
}


/**
 * IO IMPL Definitions
 */

int cjks_io_fs_read(cjks_io *io, void *buf, size_t len) {
    struct cjks_io_fs_st *iof = (struct cjks_io_fs_st *)io;
    size_t l = fread(buf, 1, len, iof->fp);
    return (int)l;
}

int cjks_io_fs_write(cjks_io *io, const void *buf, size_t len) {
    struct cjks_io_fs_st *iof = (struct cjks_io_fs_st *)io;
    size_t l = fwrite(buf, 1, len, iof->fp);
    return (int)l;
}

int cjks_io_fs_close(cjks_io *io) {
    struct cjks_io_fs_st *iof = (struct cjks_io_fs_st *)io;
    return fclose(iof->fp);
}

cjks_io_vt cjks_io_fs_vt = { cjks_io_fs_read, cjks_io_fs_write, cjks_io_fs_close };

cjks_io *cjks_io_fs_new(FILE *fp) {
    struct cjks_io_fs_st *io = malloc(sizeof(struct cjks_io_fs_st));
    io->_io.vt = &cjks_io_fs_vt;
    io->fp = fp;
    return &io->_io;
}

void cjks_io_fs_free(cjks_io* io) {
    struct cjks_io_fs_st* iof = (struct cjks_io_fs_st*)io;
    free(iof);
}

int cjks_io_mem_read(cjks_io *io, void *buf, size_t len) {
    struct cjks_io_mem_st *iom = (struct cjks_io_mem_st *)io;
    if (len > iom->buf.len) {
        len = iom->buf.len;
    }
    memcpy(buf, iom->buf.buf, len);
    // Make everyone happy
    iom->buf.buf = (char *)iom->buf.buf + len;
    iom->buf.len -= len;
    return (int)len;
}

int cjks_io_mem_write(cjks_io* io, const void* buf, size_t len) {
    struct cjks_io_mem_st *iom = (struct cjks_io_mem_st *)io;
    if (iom->buf.len < len) {
        return -1;
    }

    iom->buf.buf = (char*)memcpy(iom->buf.buf, buf, len) + len;
    iom->buf.len -= len;

    return (int)len;
}

cjks_io_vt cjks_io_mem_vt = { cjks_io_mem_read, cjks_io_mem_write, NULL };

cjks_io* cjks_io_mem_new(void* buf, size_t len) {
    struct cjks_io_mem_st* io = malloc(sizeof(struct cjks_io_mem_st));
    io->_io.vt = &cjks_io_mem_vt;
    io->buf.buf = buf;
    io->buf.len = len;
    return &io->_io;
}

void cjks_io_mem_free(cjks_io* io) {
    struct cjks_io_mem_st* iom = (struct cjks_io_mem_st*)io;
    free(iom);
}

