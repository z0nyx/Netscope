#include "netscope/config.h"

#include <string.h>

#include "test_framework.h"

static bool parse(int argc, char *const *argv, ns_config_t *out, char *err, size_t err_len) {
    return ns_config_parse(argc, argv, out, err, err_len);
}

static void test_help_flag_short_circuits(void) {
    char *argv[] = {"netscope", "--help"};
    ns_config_t cfg;
    char err[128];
    NS_CHECK(parse(2, argv, &cfg, err, sizeof(err)));
    NS_CHECK(cfg.show_help);
}

static void test_version_flag(void) {
    char *argv[] = {"netscope", "--version"};
    ns_config_t cfg;
    char err[128];
    NS_CHECK(parse(2, argv, &cfg, err, sizeof(err)));
    NS_CHECK(cfg.show_version);
}

static void test_interface_and_read_file_are_exclusive(void) {
    char *argv[] = {"netscope", "-i", "eth0", "-r", "capture.pcap"};
    ns_config_t cfg;
    char err[128];
    NS_CHECK(!parse(5, argv, &cfg, err, sizeof(err)));
    NS_CHECK(strstr(err, "-i and -r") != NULL);
}

static void test_missing_input_is_an_error(void) {
    char *argv[] = {"netscope", "--tcp"};
    ns_config_t cfg;
    char err[128];
    NS_CHECK(!parse(2, argv, &cfg, err, sizeof(err)));
}

static void test_live_capture_basic(void) {
    char *argv[] = {"netscope", "-i", "eth0", "--tcp", "--port", "443"};
    ns_config_t cfg;
    char err[128];
    NS_CHECK(parse(6, argv, &cfg, err, sizeof(err)));
    NS_CHECK(cfg.input_mode == NS_INPUT_LIVE);
    NS_CHECK(strcmp(cfg.interface, "eth0") == 0);
    NS_CHECK(cfg.filter_tcp);
    NS_CHECK(cfg.filter_port == 443);
}

static void test_invalid_port_rejected(void) {
    char *argv[] = {"netscope", "-i", "eth0", "--port", "99999"};
    ns_config_t cfg;
    char err[128];
    NS_CHECK(!parse(5, argv, &cfg, err, sizeof(err)));
}

static void test_negative_port_rejected(void) {
    char *argv[] = {"netscope", "-i", "eth0", "--port", "-1"};
    ns_config_t cfg;
    char err[128];
    NS_CHECK(!parse(5, argv, &cfg, err, sizeof(err)));
}

static void test_non_numeric_port_rejected(void) {
    char *argv[] = {"netscope", "-i", "eth0", "--port", "abc"};
    ns_config_t cfg;
    char err[128];
    NS_CHECK(!parse(5, argv, &cfg, err, sizeof(err)));
}

static void test_overflowing_port_rejected(void) {
    char *argv[] = {"netscope", "-i", "eth0", "--port", "999999999999999999999999"};
    ns_config_t cfg;
    char err[128];
    NS_CHECK(!parse(5, argv, &cfg, err, sizeof(err)));
}

static void test_unrecognized_option_reported_once(void) {
    char *argv[] = {"netscope", "-i", "eth0", "--not-a-real-flag"};
    ns_config_t cfg;
    char err[128] = {0};
    NS_CHECK(!parse(4, argv, &cfg, err, sizeof(err)));
    NS_CHECK(err[0] != '\0');
}

static void test_missing_option_argument_rejected(void) {
    char *argv[] = {"netscope", "-i", "eth0", "--port"};
    ns_config_t cfg;
    char err[128] = {0};
    NS_CHECK(!parse(4, argv, &cfg, err, sizeof(err)));
    NS_CHECK(err[0] != '\0');
}

static void test_raw_filter_conflicts_with_simple_filter(void) {
    char *argv[] = {"netscope", "-i", "eth0", "--tcp", "--filter", "udp"};
    ns_config_t cfg;
    char err[128];
    NS_CHECK(!parse(6, argv, &cfg, err, sizeof(err)));
    NS_CHECK(strstr(err, "--filter") != NULL);
}

static void test_output_requires_json_format(void) {
    char *argv[] = {"netscope", "-i", "eth0", "--output", "out.jsonl"};
    ns_config_t cfg;
    char err[128];
    NS_CHECK(!parse(5, argv, &cfg, err, sizeof(err)));
    NS_CHECK(strstr(err, "--format json") != NULL);
}

static void test_format_json_with_output(void) {
    char *argv[] = {"netscope", "-i", "eth0", "--format", "json", "--output", "out.jsonl"};
    ns_config_t cfg;
    char err[128];
    NS_CHECK(parse(7, argv, &cfg, err, sizeof(err)));
    NS_CHECK(cfg.format == NS_FORMAT_JSON);
    NS_CHECK(strcmp(cfg.output_file, "out.jsonl") == 0);
}

static void test_verbose_short_flags_increase_log_level(void) {
    char *argv[] = {"netscope", "-i", "eth0", "-v", "-v"};
    ns_config_t cfg;
    char err[128];
    NS_CHECK(parse(5, argv, &cfg, err, sizeof(err)));
    NS_CHECK(cfg.log_level == NS_LOG_DEBUG);
}

static void test_read_file_mode(void) {
    char *argv[] = {"netscope", "-r", "capture.pcap", "--stats"};
    ns_config_t cfg;
    char err[128];
    NS_CHECK(parse(4, argv, &cfg, err, sizeof(err)));
    NS_CHECK(cfg.input_mode == NS_INPUT_FILE);
    NS_CHECK(strcmp(cfg.read_file, "capture.pcap") == 0);
    NS_CHECK(cfg.show_stats);
}

NS_TEST_MAIN_BEGIN()
NS_RUN(test_help_flag_short_circuits);
NS_RUN(test_version_flag);
NS_RUN(test_interface_and_read_file_are_exclusive);
NS_RUN(test_missing_input_is_an_error);
NS_RUN(test_live_capture_basic);
NS_RUN(test_invalid_port_rejected);
NS_RUN(test_negative_port_rejected);
NS_RUN(test_non_numeric_port_rejected);
NS_RUN(test_overflowing_port_rejected);
NS_RUN(test_unrecognized_option_reported_once);
NS_RUN(test_missing_option_argument_rejected);
NS_RUN(test_raw_filter_conflicts_with_simple_filter);
NS_RUN(test_output_requires_json_format);
NS_RUN(test_format_json_with_output);
NS_RUN(test_verbose_short_flags_increase_log_level);
NS_RUN(test_read_file_mode);
NS_TEST_MAIN_END()
