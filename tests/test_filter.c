#include "netscope/filter.h"

#include <string.h>

#include "test_framework.h"

static void test_no_filters_is_empty(void) {
    ns_filter_spec_t spec = {.port = -1};
    char out[64];
    NS_CHECK(ns_filter_build_bpf(&spec, out, sizeof(out)));
    NS_CHECK(strcmp(out, "") == 0);
}

static void test_single_flag(void) {
    ns_filter_spec_t spec = {.tcp = true, .port = -1};
    char out[64];
    NS_CHECK(ns_filter_build_bpf(&spec, out, sizeof(out)));
    NS_CHECK(strcmp(out, "tcp") == 0);
}

static void test_combined_flags_are_null_terminated(void) {
    char out[64];
    memset(out, 0x7f, sizeof(out));

    ns_filter_spec_t spec = {.tcp = true, .port = 443};
    NS_CHECK(ns_filter_build_bpf(&spec, out, sizeof(out)));
    NS_CHECK(strcmp(out, "tcp and port 443") == 0);
    NS_CHECK(strlen(out) == 16);
}

static void test_host_and_src_dst(void) {
    ns_filter_spec_t spec = {.port = -1, .host = "192.168.1.10"};
    char out[64];
    NS_CHECK(ns_filter_build_bpf(&spec, out, sizeof(out)));
    NS_CHECK(strcmp(out, "host 192.168.1.10") == 0);

    ns_filter_spec_t spec2 = {.port = -1, .src = "10.0.0.1", .dst = "10.0.0.2"};
    NS_CHECK(ns_filter_build_bpf(&spec2, out, sizeof(out)));
    NS_CHECK(strcmp(out, "src host 10.0.0.1 and dst host 10.0.0.2") == 0);
}

static void test_raw_filter_ignores_other_fields(void) {
    ns_filter_spec_t spec = {.tcp = true, .port = -1, .raw = "udp port 53"};
    char out[64];
    NS_CHECK(ns_filter_build_bpf(&spec, out, sizeof(out)));
    NS_CHECK(strcmp(out, "udp port 53") == 0);
}

static void test_buffer_too_small_fails(void) {
    ns_filter_spec_t spec = {.tcp = true, .udp = true, .port = -1};
    char out[5];
    NS_CHECK(!ns_filter_build_bpf(&spec, out, sizeof(out)));
}

NS_TEST_MAIN_BEGIN()
NS_RUN(test_no_filters_is_empty);
NS_RUN(test_single_flag);
NS_RUN(test_combined_flags_are_null_terminated);
NS_RUN(test_host_and_src_dst);
NS_RUN(test_raw_filter_ignores_other_fields);
NS_RUN(test_buffer_too_small_fails);
NS_TEST_MAIN_END()
