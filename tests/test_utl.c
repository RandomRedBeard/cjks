#include <stdlib.h>
#include <string.h>
#include <cjks/utl.h>
#include "test_base.h"

void test_decode() {
    char *buf = "aGVsbG8=";
    char buf2[16];
    int l = cjks_b64decode(buf2, buf, strlen(buf));
    assert(strncmp("hello", buf2, l) == 0);
}

/**
 * Annoying newlines that i am too lazy to deal with
 * Thanks openssl
 */
void test_encode() {
    char buf[sizeof("aGVsbG8=\n")];
    memcpy(buf, "hello", sizeof("hello"));
    int l = cjks_b64encode(buf, buf, strlen(buf));
    puts(buf);
    assert(strcmp("aGVsbG8=\n", buf) == 0);
}

test_st tests[] = {
    {"encode", test_encode},
    {"decode", test_decode},
    {NULL, NULL}
};

int main() {
    cjks_run_tests(tests);
    return 0;
}