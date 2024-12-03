#ifndef CJKS_TEST_BASE_H
#define CJKS_TEST_BASE_H

#ifdef NDEBUG
#undef NDEBUG
#endif

#ifndef CJKS_RES_DIR
#define CJKS_RES_DIR "resources"
#endif

#ifdef _WIN32
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>

#define memcheckinit \
_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE); \
_CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDOUT);

#define memcheckfin     _CrtDumpMemoryLeaks()?assert(0):assert(1);
#else
#define memcheckinit
#define memcheckfin
#endif

#include <assert.h>
#include <stdio.h>

/**
 * @brief Read all bytes from file path into buffer
 * 
 * @param path 
 * @param buf 
 * @return int 
 */
static int cjks_io_read_all(const char* path, cjks_buf* buf) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    buf->len = ftell(fp);
    buf->buf = malloc(buf->len);

    fseek(fp, 0, SEEK_SET);
    fread(buf->buf, 1, buf->len, fp);
    fclose(fp);
    return 0;
}


typedef void(*test_fn)();
typedef struct {
    const char* name;
    test_fn test;
} test_st;

static void cjks_run_tests(test_st* tests) {
    memcheckinit
    while (tests->name) {
        printf("Running test %s\n", tests->name);
        tests->test();
        memcheckfin
        printf("Test completed %s\n", tests->name);
        tests++;
    }
}

#endif