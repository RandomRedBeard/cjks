#include "test_base.h"
#include <cjks/cjks.h>

int cjks_io_write_be2(cjks_io* io, unsigned short s) {
    s = cjks_htons(s);
    return cjks_io_write(io, &s, 2);
}

int cjks_io_write_be4(cjks_io* io, unsigned int i) {
    i = cjks_htoni(i);
    return cjks_io_write(io, &i, 4);
}

int cjks_io_write_utf(cjks_io* io, const char* utf, size_t len) {
    int i = cjks_io_write_be2(io, (unsigned short)len);
    i += cjks_io_write(io, utf, len);
    return i;
}

int cjks_io_write_data(cjks_io* io, cjks_buf* buf) {
    int i = cjks_io_write_be4(io, (unsigned int)buf->len);
    i += cjks_io_write(io, buf->buf, buf->len);
    return i;
}

int cjks_write_ca(cjks_ca* ca, unsigned char* buf) {
    cjks_io* io = cjks_io_mem_new(buf, 2048);

    int i = cjks_io_write_utf(io, ca->cert_type, strlen(ca->cert_type));
    i += cjks_io_write_data(io, &ca->cert);
    return i;
}

void test_ca_write() {
    char pth[128] = CJKS_RES_DIR;
    strcat(pth, "/keystore");
    cjks* jks = cjks_parse_ex2(pth, "changeit", sizeof("changeit") - 1, "US-ASCII"), * jptr = jks;
    assert(jks);
    jptr = cjks_get(jks, "c1cert");
    assert(jptr->tag == CJKS_TRUSTED_CERT_TAG);

    unsigned char ca_buf[2048];
    int ca_buf_len = cjks_write_ca(jptr->ca, ca_buf);

    cjks_ca* cmp = cjks_ca_new();
    cjks_io* io = cjks_io_mem_new(ca_buf, ca_buf_len);
    cjks_parse_ca(io, cmp);

    assert(strcmp(cmp->cert_type, jptr->ca->cert_type) == 0);
    assert(memcmp(cmp->cert.buf, jptr->ca->cert.buf, cmp->cert.len) == 0);
}

CJKS_TESTS_ST
CJKS_TEST(test_ca_write)
CJKS_TESTS_END