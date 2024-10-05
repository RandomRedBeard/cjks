#include "cjks/io.h"

/**
 * BUF functions
 */
int cjks_io_read_all(const char* path, cjks_buf* buf) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    buf->len = ftell(fp);
    buf->buf = malloc(buf->len);

    fseek(fp, 0, SEEK_SET);
    fread(buf->buf, 1, buf->len, fp);
    fclose(fp);
    return 0;
}

void cjks_buf_clear(const cjks_buf* buf) {
    free(buf->buf);
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

unsigned short cjks_io_read_be2(cjks_io *io) {
    unsigned short s = 0;
    cjks_io_read(io, &s, sizeof(s));
    return cjks_buf2be_2(&s);
}

unsigned int cjks_io_read_be4(cjks_io *io) {
    unsigned int i = 0;
    cjks_io_read(io, &i, sizeof(i));
    return cjks_buf2be_4(&i);
}

unsigned long long cjks_io_read_be8(cjks_io *io) {
    unsigned long long l = 0;
    cjks_io_read(io, &l, sizeof(l));
    return cjks_buf2be_8(&l);
}

char *cjks_io_aread_utf(cjks_io *io) {
    unsigned short s = cjks_io_read_be2(io);
    char *v = malloc(s + 1);
    cjks_io_read(io, v, s);
    *(v + s) = 0;
    return v;
}

int cjks_io_aread_data(cjks_io* io, cjks_buf* buf) {
    unsigned int i = cjks_io_read_be4(io);
    buf->buf = malloc(i);
    cjks_io_read(io, buf->buf, i);
    buf->len = i;
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

cjks_io_vt cjks_io_mem_vt = { cjks_io_mem_read, NULL, NULL };

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

