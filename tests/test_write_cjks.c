#include "test_base.h"
#include <cjks/cjks.h>
#include <cjks/sha1io.h>

char SIGWHITE[] = "Mighty Aphrodite";

int cjks_write_ca(cjks_ca* ca, cjks_io* io) {
    int i = cjks_io_write_utf(io, ca->cert_type, strlen(ca->cert_type));
    i += cjks_io_write_data(io, &ca->cert);
    return i;
}

void test_write_cjks_header() {
    // iconv sux
    uchar pwd[] = "AGMAaABhAG4AZwBlAGkAdA==";
    int plen = cjks_b64decode(pwd, pwd, sizeof(pwd) - 1);

    FILE* fp = fopen("cjks.jks", "wb");
    cjks_io* io = cjks_io_fs_new(fp);
    cjks_sha1_t* sh = cjks_sha1_new();

    cjks_sha1_cnsm(sh, pwd, plen);
    cjks_sha1_cnsm(sh, SIGWHITE, sizeof(SIGWHITE) - 1);

    io = cjks_io_sha1_new(io, sh);

    cjks_io_write(io, cjks_jks_magic_number, 4);
    cjks_io_write_be4(io, 2);
    cjks_io_write_be4(io, 0);

    uchar hash[SHA_DIGEST_LENGTH];
    cjks_sha1_cmpl(sh, hash);

    io = cjks_io_sha1_free(io, 1);

    cjks_io_write(io, hash, SHA_DIGEST_LENGTH);
    cjks_io_close(io);
    cjks_io_fs_free(io);

}

CJKS_TESTS_ST
CJKS_TEST(test_write_cjks_header)
CJKS_TESTS_END
