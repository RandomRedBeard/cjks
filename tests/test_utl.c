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

void test_sha() {
    char b64sha_cmp1[] = "qqbEQ1PXUq2YLwMl0JBBin9V7m8=";
    char sha_src[] = "this is thomas";

    char sha_cmp2[SHA_DIGEST_LENGTH + 1];
    cjks_sha1(sha_cmp2, 1, sha_src, sizeof(sha_src) - 1);

    char sha_cmp1[SHA_DIGEST_LENGTH + 1];
    cjks_b64decode(sha_cmp1, b64sha_cmp1, sizeof(b64sha_cmp1) - 1);

    assert(memcmp(sha_cmp1, sha_cmp2, SHA_DIGEST_LENGTH) == 0);
    assert(cjks_sha1_cmp(sha_cmp1, 1, sha_src, sizeof(sha_src) - 1));
}

test_st tests[] = {
    {"encode", test_encode},
    {"decode", test_decode},
    {"sha1", test_sha},
    {NULL, NULL}
};

int main() {
    cjks_run_tests(tests);
    return 0;
}