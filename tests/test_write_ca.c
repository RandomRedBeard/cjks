#include "test_base.h"
#include <cjks/cjks.h>

void test_ca_write() {
    char pth[128] = CJKS_RES_DIR;
    strcat(pth, "/keystore");
    cjks* jks = cjks_parse_ex2(pth, "changeit", sizeof("changeit") - 1, "US-ASCII"), * jptr = jks;
    assert(jks);
    jptr = cjks_get(jks, "c1cert");
    assert(jptr->tag == CJKS_TRUSTED_CERT_TAG);

    uchar ca_buf[2048];
    cjks_io* io = cjks_io_mem_new(ca_buf, sizeof(ca_buf));
    int ca_buf_len = cjks_write_ca(io, jptr->ca);
    
    cjks_io_mem_free(io);
    io = cjks_io_mem_new(ca_buf, ca_buf_len);

    cjks_ca* cmp = cjks_ca_new();
    cjks_parse_ca(io, cmp);

    assert(strcmp(cmp->cert_type, jptr->ca->cert_type) == 0);
    assert(memcmp(cmp->cert.buf, jptr->ca->cert.buf, cmp->cert.len) == 0);

    cjks_free(jks);
    cjks_ca_free(cmp);
    cjks_io_mem_free(io);
}

CJKS_TESTS_ST
CJKS_TEST(test_ca_write)
CJKS_TESTS_END