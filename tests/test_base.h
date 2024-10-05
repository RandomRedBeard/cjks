#ifndef CJKS_TEST_BASE_H
#define CJKS_TEST_BASE_H

#ifdef NDEBUG
#undef NDEBUG
#endif

#ifndef CJKS_RES_DIR
#define CJKS_RES_DIR "resources"
#endif

#include <assert.h>
#include <stdio.h>

typedef void(*test_fn)();
typedef struct {
    const char* name;
    test_fn test;
} test_st;

static void cjks_run_tests(test_st* tests) {
    while (tests->name) {
        printf("Running test %s\n", tests->name);
        tests->test();
        printf("Test completed %s\n", tests->name);
        tests++;
    }
}

#endif