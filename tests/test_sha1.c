#include "test_base.h"
#include <cjks/io.h>
#include <cjks/sha1.h>
#include <cjks/sha1io.h>
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

    fclose(fp);

    uchar icmp[SHA_DIGEST_LENGTH];
    cjks_sha1_cmpl(sh, (uint32*)icmp);

    cjks_sha1_free(sh);

    cjks_buf buff = CJKS_BUF_INIT;
    cjks_read_from_res("/keystore", &buff);

    uchar ossl_cmp[SHA_DIGEST_LENGTH];
    cjks_sha1(ossl_cmp, 1, buff.buf, buff.len);

    assert(memcmp(icmp, ossl_cmp, SHA_DIGEST_LENGTH) == 0);

    cjks_buf_clear(&buff);
}

void test_sha1_read() {
    FILE* fp = cjks_fp_from_res("/keystore");
    cjks_io* io = cjks_io_fs_new(fp);
    cjks_sha1_t* sh = cjks_sha1_new();
    io = cjks_io_sha1_new(io, sh);

    uchar buf[1024];
    while (cjks_io_read(io, buf, sizeof(buf)) > 0);

    uchar icmp[SHA_DIGEST_LENGTH];
    cjks_sha1_cmpl(sh, (uint32*)icmp);

    cjks_buf buff = CJKS_BUF_INIT;
    cjks_read_from_res("/keystore", &buff);

    uchar ossl_cmp[SHA_DIGEST_LENGTH];
    cjks_sha1(ossl_cmp, 1, buff.buf, buff.len);

    assert(memcmp(icmp, ossl_cmp, SHA_DIGEST_LENGTH) == 0);

    io = cjks_io_sha1_free(io, 1);
    cjks_io_close(io);
    cjks_io_fs_free(io);
    cjks_buf_clear(&buff);
}

void test_sha1_write() {
    uchar buf[2048];
    cjks_io* io = cjks_io_mem_new(buf, sizeof(buf));
    cjks_sha1_t* sh = cjks_sha1_new();
    io = cjks_io_sha1_new(io, sh);

    uchar tmp[32];
    for (int i = 0; i < 10; i++) {
        RAND_bytes(tmp, sizeof(tmp));
        cjks_io_write(io, tmp, 32);
    }

    uchar icmp[SHA_DIGEST_LENGTH];
    cjks_sha1_cmpl(sh, (uint32*)icmp);

    uchar ossl_cmp[SHA_DIGEST_LENGTH];
    cjks_sha1(ossl_cmp, 1, buf, 320);

    assert(memcmp(icmp, ossl_cmp, SHA_DIGEST_LENGTH) == 0);
    io = cjks_io_sha1_free(io, 1);
    cjks_io_close(io);
    cjks_io_fs_free(io);
}

CJKS_TESTS_ST
CJKS_TEST(test_sha1_1)
CJKS_TEST(test_sha1_read)
CJKS_TEST(test_sha1_write)
CJKS_TESTS_END