#include "test_base.h"
#include <cjks/cjks.h>
#include <cjks/sha1io.h>

char SIGWHITE[] = "Mighty Aphrodite";

int cjks_write_jks_header(cjks_io* io, cjks* jks) {
    cjks_io_write(io, cjks_jks_magic_number, 4);
    cjks_io_write_be4(io, 2);
    cjks_io_write_be4(io, jks->n);
    return 0;
}

int cjks_write_jks_entry(cjks_io* io, cjks* jks, const char* password, size_t len) {
    cjks_io_write_be4(io, jks->tag);
    cjks_io_write_utf(io, jks->alias, strlen(jks->alias));
    cjks_io_write_be8(io, jks->ts);

    if (jks->tag == CJKS_TRUSTED_CERT_TAG) {
        cjks_write_ca(io, jks->ca);
    }
    else {
        cjks_write_pk(io, jks->pk, password, len);
    }

    return 0;
}

void test_write_cjks_1() {
    // iconv sux
    uchar pwd[] = "AGMAaABhAG4AZwBlAGkAdA==";
    int plen = cjks_b64decode(pwd, pwd, sizeof(pwd) - 1);

    FILE* fp = cjks_fp_from_res("/keystore");
    cjks_io* io = cjks_io_fs_new(fp);
    cjks* jks = cjks_parse_ex(io, "changeit", sizeof("changeit") - 1, "US-ASCII"), * jptr = jks;
    cjks_io_close(io);
    cjks_io_fs_free(io);

    fp = fopen("cjks.jks", "wb");
    io = cjks_io_fs_new(fp);
    cjks_sha1_t* sh = cjks_sha1_new();

    cjks_sha1_cnsm(sh, pwd, plen);
    cjks_sha1_cnsm(sh, (uchar*)SIGWHITE, sizeof(SIGWHITE) - 1);

    io = cjks_io_sha1_new(io, sh);

    cjks_write_jks_header(io, jks);
    while (jptr) {
        cjks_write_jks_entry(io, jptr, pwd, plen);
        jptr = jptr->next;
    }

    uchar hash[SHA_DIGEST_LENGTH];
    cjks_sha1_cmpl(sh, (uint32*)hash);

    io = cjks_io_sha1_free(io, 1);

    cjks_io_write(io, hash, SHA_DIGEST_LENGTH);
    cjks_io_close(io);
    cjks_io_fs_free(io);

    cjks_free(jks);
}

CJKS_TESTS_ST
CJKS_TEST(test_write_cjks_1)
CJKS_TESTS_END
