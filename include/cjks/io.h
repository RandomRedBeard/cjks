#ifndef CJKS_IO_H
#define CJKS_IO_H

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include <cjks/bits.h>
#include <cjks/lib.h>

typedef struct cjks_buf_st {
    void* buf;
    size_t len;
} cjks_buf;

#define CJKS_BUF_INIT {0, 0}

CJKS_DLL void cjks_buf_clear(cjks_buf* buf);

typedef struct cjks_io_st {
    struct cjks_io_vt_st* vt;
} cjks_io;

typedef struct cjks_io_vt_st {
    int(*cjks_io_read_fn)(struct cjks_io_st*, void*, size_t);
    int(*cjks_io_write_fn)(struct cjks_io_st*, const void*, size_t);
    int(*cjks_io_close_fn)(struct cjks_io_st*);
} cjks_io_vt;

struct cjks_io_fs_st {
    cjks_io _io;
    FILE* fp;
};

struct cjks_io_mem_st {
    cjks_io _io;
    cjks_buf buf;
};

CJKS_DLL int cjks_io_read(cjks_io* io, void* buf, size_t len);
CJKS_DLL int cjks_io_write(cjks_io* io, const void* buf, size_t len);
CJKS_DLL int cjks_io_close(cjks_io* io);

CJKS_DLL uint16 cjks_io_read_be2(cjks_io* io);
CJKS_DLL uint32 cjks_io_read_be4(cjks_io* io);
CJKS_DLL uint64 cjks_io_read_be8(cjks_io* io);

CJKS_DLL int cjks_io_write_be2(cjks_io* io, uint16 s);
CJKS_DLL int cjks_io_write_be4(cjks_io* io, uint32 i);
CJKS_DLL int cjks_io_write_be8(cjks_io* io, uint64 l);

CJKS_DLL char* cjks_io_aread_utf(cjks_io* io);
CJKS_DLL int cjks_io_aread_data(cjks_io* io, cjks_buf* buf);

CJKS_DLL int cjks_io_write_utf(cjks_io* io, const char* utf, size_t len);
CJKS_DLL int cjks_io_write_data(cjks_io* io, cjks_buf* buf);

CJKS_DLL cjks_io* cjks_io_fs_new(FILE*);
CJKS_DLL void cjks_io_fs_free(cjks_io* io);
CJKS_DLL cjks_io* cjks_io_mem_new(void*, size_t);
CJKS_DLL void cjks_io_mem_free(cjks_io* io);

#endif
