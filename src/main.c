#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
/* clock_gettime is POSIX, not ISO C. Building with CMAKE_C_EXTENSIONS OFF
 * passes -std=c17 (strict ANSI), which hides it from glibc's <time.h>
 * unless a feature test macro opts back in -- must be defined before that
 * header (or anything pulling it in transitively) is included. */
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <pcap/pcap.h>

#include "netscope/capture.h"
#include "netscope/config.h"
#include "netscope/filter.h"
#include "netscope/log.h"
#include "netscope/output.h"
#include "netscope/signal_handler.h"
#include "netscope/stats.h"
#include "netscope/version.h"

typedef struct {
    ns_stats_t *stats;
    const ns_output_options_t *output_opts;
    FILE *out;
} ns_main_ctx_t;

static void handle_packet(void *ctx_ptr, const ns_packet_t *pkt) {
    ns_main_ctx_t *ctx = (ns_main_ctx_t *) ctx_ptr;
    ns_stats_update(ctx->stats, pkt);
    ns_output_packet(pkt, ctx->output_opts, ctx->out);
}

static double monotonic_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double) ts.tv_sec + (double) ts.tv_nsec / 1e9;
}

static void print_error(const char *program_name, const char *message) {
    fprintf(stderr, "%s: %s\n", program_name, message);
    if (strstr(message, "ermission") != NULL) {
        fprintf(stderr, "hint: try running with elevated capture privileges "
                        "(see README.md for platform-specific guidance)\n");
    }
}

int main(int argc, char **argv) {
    const char *program_name = "netscope";

    ns_config_t config;
    char err_buf[512];
    if (!ns_config_parse(argc, argv, &config, err_buf, sizeof(err_buf))) {
        print_error(program_name, err_buf);
        fprintf(stderr, "Try '%s --help' for usage.\n", program_name);
        return 1;
    }

    if (config.show_help) {
        ns_config_print_help(program_name, stdout);
        return 0;
    }
    if (config.show_version) {
        ns_config_print_version(stdout);
        return 0;
    }

    ns_log_set_level(config.log_level);

    if (config.list_interfaces) {
        char pcap_err[PCAP_ERRBUF_SIZE];
        if (!ns_capture_list_interfaces(stdout, pcap_err, sizeof(pcap_err))) {
            print_error(program_name, pcap_err);
            return 1;
        }
        return 0;
    }

    if (config.input_mode == NS_INPUT_LIVE && !ns_capture_interface_exists(config.interface)) {
        char msg[512];
        snprintf(msg, sizeof(msg), "interface '%s' does not exist", config.interface);
        print_error(program_name, msg);
        return 1;
    }

    ns_filter_spec_t filter_spec = {
        .tcp = config.filter_tcp,
        .udp = config.filter_udp,
        .icmp = config.filter_icmp,
        .port = config.filter_port,
        .host = config.filter_host,
        .src = config.filter_src,
        .dst = config.filter_dst,
        .raw = config.has_raw_filter ? config.raw_filter : NULL,
    };
    char bpf_expr[NS_CONFIG_STR_LEN * 2];
    if (!ns_filter_build_bpf(&filter_spec, bpf_expr, sizeof(bpf_expr))) {
        print_error(program_name, "capture filter expression is too long");
        return 1;
    }

    ns_capture_t cap;
    bool opened;
    if (config.input_mode == NS_INPUT_LIVE) {
        opened = ns_capture_open_live(&cap, config.interface, bpf_expr, err_buf, sizeof(err_buf));
    } else {
        opened =
            ns_capture_open_offline(&cap, config.read_file, bpf_expr, err_buf, sizeof(err_buf));
    }
    if (!opened) {
        print_error(program_name, err_buf);
        return 1;
    }

    if (config.write_file[0] != '\0') {
        if (!ns_capture_open_dump(&cap, config.write_file, err_buf, sizeof(err_buf))) {
            print_error(program_name, err_buf);
            ns_capture_close(&cap);
            return 1;
        }
    }

    FILE *output_stream = stdout;
    if (config.format == NS_FORMAT_JSON && config.output_file[0] != '\0') {
        output_stream = fopen(config.output_file, "w");
        if (output_stream == NULL) {
            char msg[512];
            snprintf(msg, sizeof(msg), "failed to open '%s' for writing", config.output_file);
            print_error(program_name, msg);
            ns_capture_close(&cap);
            return 1;
        }
    }

    ns_output_options_t output_opts = {
        .color = ns_output_should_use_color(config.no_color, output_stream),
        .verbose = config.verbose_output,
        .quiet = config.quiet,
        .hex = config.hex_dump,
        .format = config.format,
    };

    if (config.input_mode == NS_INPUT_LIVE && config.format == NS_FORMAT_TEXT && !config.quiet) {
        printf("%s %s\n", NS_NAME, NS_VERSION_STRING);
        printf("Interface: %s\n", config.interface);
        printf("Capture started. Press Ctrl+C to stop.\n\n");
    }

    ns_stats_t stats;
    ns_stats_init(&stats);

    ns_main_ctx_t ctx = {.stats = &stats, .output_opts = &output_opts, .out = output_stream};

    ns_install_signal_handlers();

    double start_time = monotonic_seconds();
    bool run_ok = ns_capture_run(&cap, handle_packet, &ctx, err_buf, sizeof(err_buf));
    double end_time = monotonic_seconds();

    ns_capture_close(&cap);

    if (output_stream != stdout) {
        fclose(output_stream);
    }

    if (!run_ok) {
        print_error(program_name, err_buf);
        return 1;
    }

    if (config.show_stats || config.input_mode == NS_INPUT_LIVE) {
        ns_stats_print(&stats, end_time - start_time, stdout);
    }

    return 0;
}
