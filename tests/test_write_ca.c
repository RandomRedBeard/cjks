#include "test_base.h"
#include <cjks/cjks.h>

int cjks_write_ca(cjks_ca* ca, unsigned char* buf) {
    unsigned char* pbuf = buf;
    unsigned short len = (unsigned short)strlen(ca->cert_type);
    unsigned short nlen = cjks_htons(len);
    pbuf = (unsigned char*)memcpy(pbuf, &nlen, 2) + 2;
    pbuf = (unsigned char*)memcpy(pbuf, ca->cert_type, len) + len;

    unsigned int clen = (unsigned int)ca->cert.len;
    clen = cjks_htoni(clen);
    pbuf = (unsigned char*)memcpy(pbuf, &clen, 4) + 4;
    pbuf = (unsigned char*)memcpy(pbuf, ca->cert.buf, ca->cert.len) + ca->cert.len;

    return pbuf - buf;
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
}

CJKS_TESTS_ST
CJKS_TEST(test_ca_write)
CJKS_TESTS_END