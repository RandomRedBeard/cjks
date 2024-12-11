#include <stdlib.h>
#include <string.h>
#include <cjks/utl.h>
#include "test_base.h"

void test_decode() {
    unsigned char buf[] = "aGVsbG8=";
    unsigned char buf2[16];
    int l = cjks_b64decode(buf2, buf, sizeof(buf) - 1);
    assert(memcmp("hello", buf2, l) == 0);
}

void test_decode_2() {
    char kp[128];
    memcpy(kp, CJKS_RES_DIR, sizeof(CJKS_RES_DIR));
    strcat(kp, "/d.key");
    cjks_buf pk_buf;
    cjks_io_read_all(kp, &pk_buf);
    int i = cjks_b64decode(pk_buf.buf, pk_buf.buf, pk_buf.len);
    cjks_buf_clear(&pk_buf);
    assert(i > 0);
}

/**
 * Annoying newlines that i am too lazy to deal with
 * Thanks openssl
 */
void test_encode() {
    unsigned char buf[sizeof("aGVsbG8=")];
    int l = cjks_b64encode(buf, (unsigned char*)"hello", strlen("hello"));
    puts((char*)buf);
    assert(memcmp("aGVsbG8=", buf, l) == 0);
}

void test_sha() {
    unsigned char b64sha_cmp1[] = "qqbEQ1PXUq2YLwMl0JBBin9V7m8=";
    unsigned char sha_src[] = "this is thomas";

    unsigned char sha_cmp2[SHA_DIGEST_LENGTH];
    cjks_sha1(sha_cmp2, 1, sha_src, sizeof(sha_src) - 1);

    unsigned char sha_cmp1[SHA_DIGEST_LENGTH];
    int i = cjks_b64decode(sha_cmp1, b64sha_cmp1, sizeof(b64sha_cmp1) - 1);
    printf("%d\n", i);

    assert(memcmp(sha_cmp1, sha_cmp2, SHA_DIGEST_LENGTH) == 0);
    assert(cjks_sha1_cmp(sha_cmp1, 1, sha_src, sizeof(sha_src) - 1));
}

test_st tests[] = {
    {"encode", test_encode},
    {"decode", test_decode},
    {"decode2", test_decode_2},
    {"sha1", test_sha},
    {NULL, NULL}
};

int main() {
    cjks_run_tests(tests);
    return 0;
}