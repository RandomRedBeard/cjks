#ifndef CJKS_SHA1IO_H
#define CJKS_SHA1IO_H

#include <cjks/sha1.h>
#include <cjks/io.h>

struct cjks_io_sha1_st {
    cjks_io _io;
    cjks_io* _u;
    cjks_sha1_t* sh;
};

CJKS_DLL cjks_io* cjks_io_sha1_new(cjks_io*, cjks_sha1_t* sh);

/**
 * @brief Returns underlying io
 * 
 * @param own_sha 
 * @return CJKS_DLL* 
 */
CJKS_DLL cjks_io* cjks_io_sha1_free(cjks_io*, int own_sha);

CJKS_DLL void cjks_io_sha1_cnsm(cjks_io* io, const uchar* b, size_t len);
CJKS_DLL void cjks_io_sha1_cmpl(cjks_io* io, uint32 v[5]);

#endif
