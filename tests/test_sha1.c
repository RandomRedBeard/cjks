#include "test_base.h"
#include <cjks/utl.h>
#include <cjks/io.h>
#include <cjks/sha1.h>
#include <time.h>

#include <openssl/rand.h>
#include "private/debug.h"

void test_sha1_1() {
    FILE* fp = cjks_fp_from_res("/keystore");
    size_t rlen;

    cjks_sha1_t* sh = cjks_sha1_new();
    uchar buf[1024];
    while ((rlen = fread(buf, 1, sizeof(buf), fp)) > 0) {
        cjks_sha1_cnsm(sh, buf, rlen);
    }

    uchar icmp[SHA_DIGEST_LENGTH];
    cjks_sha1_cmpl(sh, (uint32*)icmp);

    cjks_sha1_free(sh);

    cjks_buf buff = CJKS_BUF_INIT;
    cjks_read_from_res("/keystore", &buff);

    uchar ossl_cmp[SHA_DIGEST_LENGTH];
    cjks_sha1(ossl_cmp, 1, buff.buf, buff.len);

    assert(memcmp(icmp, ossl_cmp, SHA_DIGEST_LENGTH) == 0);
}

struct cjks_io_sha1 {
    cjks_io _io;
    cjks_io* wr;
    cjks_sha1_t* sha1;
};

int cjks_io_sha1_read(cjks_io* io, void* v, size_t len) {
    struct cjks_io_sha1* sio = (struct cjks_io_sha1*)io;
    int i = cjks_io_read(sio->wr, v, len);
    if (i < 0) {
        return i;
    }

    cjks_sha1_cnsm(sio->sha1, v, i);
    return i;
}

int cjks_io_sha1_write(cjks_io* io, const void* v, size_t len) {
    struct cjks_io_sha1* sio = (struct cjks_io_sha1*)io;
    cjks_sha1_cnsm(sio->sha1, v, len);

    return cjks_io_write(sio->wr, v, len);
}

cjks_io_vt cjks_io_sha1_vt = { cjks_io_sha1_read, cjks_io_sha1_write, NULL };

void test_sha1_read() {
    FILE* fp = cjks_fp_from_res("/keystore");
    cjks_io* io = cjks_io_fs_new(fp);
    struct cjks_io_sha1* sio = calloc(1, sizeof(struct cjks_io_sha1));

    sio->sha1 = cjks_sha1_new();
    sio->wr = io;
    sio->_io.vt = &cjks_io_sha1_vt;

    uchar buf[1024];
    while (cjks_io_read(&sio->_io, buf, sizeof(buf)) > 0);

    free(sio);
    cjks_io_fs_free(io);

    uchar icmp[SHA_DIGEST_LENGTH];
    cjks_sha1_cmpl(sio->sha1, (uint32*)icmp);

    cjks_buf buff = CJKS_BUF_INIT;
    cjks_read_from_res("/keystore", &buff);

    uchar ossl_cmp[SHA_DIGEST_LENGTH];
    cjks_sha1(ossl_cmp, 1, buff.buf, buff.len);

    assert(memcmp(icmp, ossl_cmp, SHA_DIGEST_LENGTH) == 0);
}

void test_sha1_write() {
    uchar buf[2048];
    cjks_io* io = cjks_io_mem_new(buf, sizeof(buf));
    struct cjks_io_sha1* sio = calloc(1, sizeof(struct cjks_io_sha1));

    sio->sha1 = cjks_sha1_new();
    sio->wr = io;
    sio->_io.vt = &cjks_io_sha1_vt;

    uchar tmp[32];
    for (int i = 0; i < 10; i++) {
        RAND_bytes(tmp, sizeof(tmp));
        cjks_io_write(&sio->_io, tmp, 32);
    }

    uchar icmp[SHA_DIGEST_LENGTH];
    cjks_sha1_cmpl(sio->sha1, (uint32*)icmp);

    uchar ossl_cmp[SHA_DIGEST_LENGTH];
    cjks_sha1(ossl_cmp, 1, buf, 320);

    assert(memcmp(icmp, ossl_cmp, SHA_DIGEST_LENGTH) == 0);
}

CJKS_TESTS_ST
CJKS_TEST(test_sha1_1)
CJKS_TEST(test_sha1_read)
CJKS_TEST(test_sha1_write)
CJKS_TESTS_END