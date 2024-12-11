#include "test_base.h"
#include <cjks/cjks.h>

int cjks_write_ca(cjks_io* io, cjks_ca* ca) {
    int i = cjks_io_write_utf(io, ca->cert_type, strlen(ca->cert_type));
    i += cjks_io_write_data(io, &ca->cert);
    return i;
}

int cjks_write_pk(cjks_pkey* pk, unsigned char* buf) {
    // <uint32 eber len><eber><uint32 chain len><uint16 cert type len><cert type><uint32 cert len><cert>...
    cjks_io* io = cjks_io_mem_new(buf, 4096);
    int i = cjks_io_write_data(io, &pk->encrypted_ber);
    // Cheat
    unsigned int clen = 0;
    unsigned char* clenptr = buf + i;
    i += cjks_io_write(io, &clen, 4);

    cjks_ca* ca = pk->cert_chain;
    while (ca) {
        i += cjks_write_ca(io, ca);
        ca = ca->next;
        clen++;
    }

    clen = cjks_htoni(clen);
    memcpy(clenptr, &clen, 4);

    cjks_io_mem_free(io);

    return i;
}

void test_pk_write() {
    char pth[128] = CJKS_RES_DIR;
    strcat(pth, "/keystore");
    cjks* jks = cjks_parse_ex2(pth, "changeit", sizeof("changeit") - 1, "US-ASCII"), * jptr = jks;
    assert(jks);
    jptr = cjks_get(jks, "mytestkey");
    assert(jptr->tag == CJKS_PRIVATE_KEY_TAG);

    unsigned char pk_buf[4096];
    int pk_buf_len = cjks_write_pk(jptr->pk, pk_buf);

    assert(pk_buf_len > 0);
    cjks_pkey* cmp = cjks_pk_new();
    cjks_io* io = cjks_io_mem_new(pk_buf, pk_buf_len);
    cjks_parse_pk(io, cmp);

    // Check eber first
    assert(memcmp(cmp->encrypted_ber.buf, jptr->pk->encrypted_ber.buf, cmp->encrypted_ber.len) == 0);
}

CJKS_TESTS_ST
CJKS_TEST(test_pk_write)
CJKS_TESTS_END