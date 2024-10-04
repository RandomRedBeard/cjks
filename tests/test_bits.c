
#include <cjks/io.h>
#include "test_base.h"

void test_read_be2() {
    char buf[] = { 0x0, 0x1 };
    cjks_io *io = cjks_io_mem_new(buf, 2);
    unsigned short s = cjks_io_read_be2(io);
    assert(s == 1);
    cjks_io_mem_free(io);
}

void test_read_be4() {
    char buf[] = { 0x0, 0x0, 0x0, 0x1 };
    cjks_io *io = cjks_io_mem_new(buf, 4);
    unsigned int i = cjks_io_read_be4(io);
    assert(i == 1);
    cjks_io_mem_free(io);
}

void test_read_be8() {
    char buf[] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1 };
    cjks_io *io = cjks_io_mem_new(buf, 8);
    unsigned long long l = cjks_io_read_be8(io);
    assert(l == 1);
    cjks_io_mem_free(io);
}

test_st tests[] = {
    {"be2", test_read_be2},
    {"be4", test_read_be4},
    {"be8", test_read_be8},
    {NULL, NULL}
};

int main() {
    cjks_run_tests(tests);
    return 0;
}