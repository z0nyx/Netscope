#ifndef NETSCOPE_CONFIG_H
#define NETSCOPE_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

typedef enum {
    NS_INPUT_NONE = 0,
    NS_INPUT_LIVE,
    NS_INPUT_FILE,
} ns_input_mode_t;

typedef enum {
    NS_FORMAT_TEXT = 0,
    NS_FORMAT_JSON,
} ns_output_format_t;

typedef enum {
    NS_LOG_ERROR = 0,
    NS_LOG_WARN,
    NS_LOG_INFO,
    NS_LOG_DEBUG,
} ns_log_level_t;

#define NS_CONFIG_STR_LEN 256

typedef struct {
    ns_input_mode_t input_mode;
    char interface[NS_CONFIG_STR_LEN];
    char read_file[NS_CONFIG_STR_LEN];
    char write_file[NS_CONFIG_STR_LEN];
    char output_file[NS_CONFIG_STR_LEN];

    bool filter_tcp;
    bool filter_udp;
    bool filter_icmp;
    int filter_port;
    char filter_host[NS_CONFIG_STR_LEN];
    char filter_src[NS_CONFIG_STR_LEN];
    char filter_dst[NS_CONFIG_STR_LEN];
    char raw_filter[NS_CONFIG_STR_LEN];
    bool has_raw_filter;

    bool no_color;
    bool verbose_output;
    bool quiet;
    bool show_stats;
    bool hex_dump;
    ns_output_format_t format;

    ns_log_level_t log_level;

    bool list_interfaces;
    bool show_help;
    bool show_version;
} ns_config_t;

bool ns_config_parse(int argc, char *const *argv, ns_config_t *out, char *err_buf,
                     size_t err_buf_len);

void ns_config_print_help(const char *program_name, FILE *out);
void ns_config_print_version(FILE *out);

#endif
