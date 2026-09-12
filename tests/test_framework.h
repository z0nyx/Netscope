#ifndef NETSCOPE_TEST_FRAMEWORK_H
#define NETSCOPE_TEST_FRAMEWORK_H

#include <stdio.h>

static int ns_test_failures = 0;
static int ns_test_total = 0;

#define NS_CHECK(cond)                                                                             \
    do {                                                                                           \
        ns_test_total++;                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                      \
            ns_test_failures++;                                                                    \
        }                                                                                          \
    } while (0)

#define NS_RUN(fn)                                                                                 \
    do {                                                                                           \
        int before = ns_test_failures;                                                             \
        fn();                                                                                      \
        printf("[%s] %s\n", (ns_test_failures == before) ? "PASS" : "FAIL", #fn);                  \
    } while (0)

#define NS_TEST_MAIN_BEGIN() int main(void) {
#define NS_TEST_MAIN_END()                                                                         \
    printf("%d checks, %d failed\n", ns_test_total, ns_test_failures);                             \
    return ns_test_failures == 0 ? 0 : 1;                                                          \
    }

#endif
