
#include <iconv.h>
#include <cjks/cjks.h>
#include "test_base.h"

void test_load() {
#ifndef CJKS_RES_DIR
#define CJKS_RES_DIR "resources"
#endif
    char ksp[128];
    memcpy(ksp, CJKS_RES_DIR, strlen(CJKS_RES_DIR) + 1);
    strcat(ksp, "/keystore");
    FILE* fp = fopen(ksp, "rb");
    assert(fp);
    cjks_io* io = cjks_io_fs_new(fp);

    char password[] = "changeit", * ptr = password;
    char utf16_password[32], * utf16_ptr = utf16_password;

    size_t pwdlen = sizeof(password) - 1;
    size_t utf_len = sizeof(utf16_password);

    iconv_t cnv = iconv_open("UTF-16BE", "US-ASCII");
    iconv(cnv, NULL, NULL, &utf16_ptr, &utf_len);
    iconv(cnv, &ptr, &pwdlen, &utf16_ptr, &utf_len);
    iconv_close(cnv);

    unsigned int cnt = 0;
    cjks* jks = cjks_parse(io, utf16_password, utf_len), *jptr = jks;
    while (jptr) {
        printf("%d - %s\n", jptr->tag, jptr->alias);
        jptr = jptr->next;
        cnt++;
    }

    assert(cnt == 3);

    cjks* mk = cjks_get(jks, "mytestkey");
    assert(mk);
    assert(mk->tag == CJKS_PRIVATE_KEY_TAG);
    assert(mk->entry.pk->key.len > 0);

    char kp[128];
    memcpy(kp, CJKS_RES_DIR, strlen(CJKS_RES_DIR) + 1);
    strcat(kp, "/d.key");

    cjks_buf dkey = CJKS_BUF_INIT;
    cjks_io_read_all(kp, &dkey);

    unsigned char* mk_key = malloc(2048);
    int mk_key_len = cjks_b64encode(mk_key, mk->entry.pk->key.buf, mk->entry.pk->key.len);

    assert(memcmp(dkey.buf, mk_key, dkey.len) == 0);

    cjks_io_fs_free(io);
    cjks_buf_clear(&dkey);
    cjks_free(jks);
}

test_st tests[] = {
    {"load", test_load},
    {NULL, NULL}
};

int main() {
    cjks_run_tests(tests);
    return 0;
}