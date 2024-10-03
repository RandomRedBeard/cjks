#include <cjks/io.h>
#include "test_base.h"

void test_mem() {
    char buf[] = "this is thomas";
    cjks_io* io = cjks_io_mem_new(buf, sizeof(buf) - 1);
    char tmp[16];
    int i = cjks_io_read(io, tmp, 4);
    *(tmp + i) = 0;
    assert(strcmp(tmp, "this") == 0);

    // Only allocated memory is io
    cjks_io_mem_free(io);
}

void test_fs() {
    FILE* fp = tmpfile();
    cjks_io* io = cjks_io_fs_new(fp);
    cjks_io_write(io, "thomas", sizeof("thomas") - 1);
    rewind(fp);
    char buf[16];
    int i = cjks_io_read(io, buf, 16);
    *(buf + i) = 0;
    assert(strcmp(buf, "thomas") == 0);

    cjks_io_close(io);
    cjks_io_fs_free(io);
}

void test_fs_be2() {
    FILE* fp = tmpfile();
    cjks_io* io = cjks_io_fs_new(fp);
    char be2[] = {0x0, 0x1};
    cjks_io_write(io, be2, 2);
    rewind(fp);
    unsigned short s = cjks_io_read_be2(io);
    assert(s == 1);

    cjks_io_close(io);
    cjks_io_fs_free(io);
}

test_st tests[] = {
    {"mem", test_mem},
    {"fs", test_fs},
    {"fs_be2", test_fs_be2},
    {NULL, NULL}
};

int main() {
    cjks_run_tests(tests);
    return 0;
}