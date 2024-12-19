#include "test_base.h"
#include <cjks/cjks.h>

void test_pk_write() {
    char pth[128] = CJKS_RES_DIR;
    strcat(pth, "/keystore");
    cjks* jks = cjks_parse_ex2(pth, "changeit", sizeof("changeit") - 1, "US-ASCII"), * jptr = jks;
    assert(jks);
    jptr = cjks_get(jks, "mytestkey");
    assert(jptr->tag == CJKS_PRIVATE_KEY_TAG);

    uchar pwd[] = "AGMAaABhAG4AZwBlAGkAdA==";
    int plen = cjks_b64decode(pwd, pwd, sizeof(pwd) - 1);

    uchar pk_buf[4096];
    cjks_io* io = cjks_io_mem_new(pk_buf, sizeof(pk_buf));
    int pk_buf_len = cjks_write_pk(io, jptr->pk, pwd, plen);
    printf("buf %d\n", pk_buf_len);

    assert(pk_buf_len > 0);
    cjks_pkey* cmp = cjks_pk_new();
    cjks_io_mem_free(io);
    io = cjks_io_mem_new(pk_buf, pk_buf_len);
    cjks_parse_pk(io, cmp);

    // Check eber first
    assert(memcmp(cmp->encrypted_ber.buf, jptr->pk->encrypted_ber.buf, cmp->encrypted_ber.len) == 0);

    // ca chain
    assert(cmp->cert_chain);
    cjks_free(jks);
    cjks_pk_free(cmp);
    cjks_io_mem_free(io);
}

CJKS_TESTS_ST
CJKS_TEST(test_pk_write)
CJKS_TESTS_END