#include <stdlib.h>
#include <string.h>
#include <cjks/utl.h>
#include "test_base.h"

void test_decode() {
    uchar buf[] = "aGVsbG8=";
    uchar buf2[16];
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
    uchar buf[sizeof("aGVsbG8=")];
    int l = cjks_b64encode(buf, (uchar*)"hello", strlen("hello"));
    puts((char*)buf);
    assert(memcmp("aGVsbG8=", buf, l) == 0);
}

void test_sha() {
    uchar b64sha_cmp1[] = "qqbEQ1PXUq2YLwMl0JBBin9V7m8=";
    uchar sha_src[] = "this is thomas";

    uchar sha_cmp2[SHA_DIGEST_LENGTH];
    cjks_sha1(sha_cmp2, 1, sha_src, sizeof(sha_src) - 1);

    uchar sha_cmp1[SHA_DIGEST_LENGTH];
    int i = cjks_b64decode(sha_cmp1, b64sha_cmp1, sizeof(b64sha_cmp1) - 1);
    printf("%d\n", i);

    assert(memcmp(sha_cmp1, sha_cmp2, SHA_DIGEST_LENGTH) == 0);
    assert(cjks_sha1_cmp(sha_cmp1, 1, sha_src, sizeof(sha_src) - 1));
}

CJKS_TESTS_ST
    CJKS_TEST(test_encode)
    CJKS_TEST(test_decode)
    CJKS_TEST(test_decode_2)
    CJKS_TEST(test_sha)
CJKS_TESTS_END
