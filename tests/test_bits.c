
#include <cjks/io.h>
#include "test_base.h"
#include "private/debug.h"

void test_cjks_ntohs() {
    assert(cjks_ntohs(1 << 8) == 1);
}

void test_cjks_ntohi() {
    assert(cjks_ntohi(1 << 24) == 1);
}

void test_cjks_ntohll() {
    assert(cjks_ntohll((long long)1 << 56) == 1);
}

void test_cjks_htoni() {
    assert(cjks_htoni(1 << 24) == 1);
}

void test_read_be2() {
    char buf[] = { 0x0, 0x1 };
    cjks_io* io = cjks_io_mem_new(buf, 2);
    uint16 s = cjks_io_read_be2(io);
    assert(s == 1);
    cjks_io_mem_free(io);
}

void test_read_be4() {
    char buf[] = { 0x0, 0x0, 0x0, 0x1 };
    cjks_io* io = cjks_io_mem_new(buf, 4);
    uint32 i = cjks_io_read_be4(io);
    assert(i == 1);
    cjks_io_mem_free(io);
}

void test_read_be8() {
    char buf[] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1 };
    cjks_io* io = cjks_io_mem_new(buf, 8);
    uint64 l = cjks_io_read_be8(io);
    assert(l == 1);
    cjks_io_mem_free(io);
}

CJKS_TESTS_ST
    CJKS_TEST(test_cjks_ntohs)
    CJKS_TEST(test_cjks_ntohi)
    CJKS_TEST(test_cjks_ntohll)
    CJKS_TEST(test_cjks_htoni)
    CJKS_TEST(test_read_be2)
    CJKS_TEST(test_read_be4)
    CJKS_TEST(test_read_be8)
CJKS_TESTS_END
