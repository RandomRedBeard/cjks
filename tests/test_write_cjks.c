#include "test_base.h"
#include <cjks/cjks.h>

char SIGWHITE[] = "Mighty Aphrodite";

void test_write_cjks_header() {
    char buf[1024];
    cjks_io* io = cjks_io_mem_new(buf, sizeof(buf));
    cjks_io_write(io, cjks_jks_magic_number, 4);
    cjks_io_write_be4(io, 2);
    cjks_io_write_be4(io, 0);

    // Write SHA
    // pwd + white + data[:pos]

    // iconv sux
    uchar pwd[] = "AGMAaABhAG4AZwBlAGkAdA==";
    int plen = cjks_b64decode(pwd, pwd, sizeof(pwd) - 1);

    cjks_sha1(buf + 12, 3, pwd, (size_t)plen, SIGWHITE, sizeof(SIGWHITE) - 1, buf, (size_t)12);

    FILE* fp = fopen("cjks.jks", "wb");
    fwrite(buf, 1, 32, fp);
    fclose(fp);
}

CJKS_TESTS_ST
CJKS_TEST(test_write_cjks_header)
CJKS_TESTS_END