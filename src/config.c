#include "netscope/config.h"

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "netscope/version.h"

enum {
    OPT_VERSION = 1000,
    OPT_LIST_INTERFACES,
    OPT_TCP,
    OPT_UDP,
    OPT_ICMP,
    OPT_PORT,
    OPT_HOST,
    OPT_SRC,
    OPT_DST,
    OPT_FILTER,
    OPT_NO_COLOR,
    OPT_VERBOSE,
    OPT_QUIET,
    OPT_STATS,
    OPT_HEX,
    OPT_WRITE,
    OPT_FORMAT,
    OPT_OUTPUT,
    OPT_DEBUG,
};

static const struct option kLongOptions[] = {
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, OPT_VERSION},
    {"list-interfaces", no_argument, NULL, OPT_LIST_INTERFACES},
    {"interface", required_argument, NULL, 'i'},
    {"read", required_argument, NULL, 'r'},
    {"tcp", no_argument, NULL, OPT_TCP},
    {"udp", no_argument, NULL, OPT_UDP},
    {"icmp", no_argument, NULL, OPT_ICMP},
    {"port", required_argument, NULL, OPT_PORT},
    {"host", required_argument, NULL, OPT_HOST},
    {"src", required_argument, NULL, OPT_SRC},
    {"dst", required_argument, NULL, OPT_DST},
    {"filter", required_argument, NULL, OPT_FILTER},
    {"no-color", no_argument, NULL, OPT_NO_COLOR},
    {"verbose", no_argument, NULL, OPT_VERBOSE},
    {"quiet", no_argument, NULL, OPT_QUIET},
    {"stats", no_argument, NULL, OPT_STATS},
    {"hex", no_argument, NULL, OPT_HEX},
    {"write", required_argument, NULL, OPT_WRITE},
    {"format", required_argument, NULL, OPT_FORMAT},
    {"output", required_argument, NULL, OPT_OUTPUT},
    {"debug", no_argument, NULL, OPT_DEBUG},
    {NULL, 0, NULL, 0},
};

static void copy_str(char *dst, size_t dst_len, const char *src) {
    snprintf(dst, dst_len, "%s", src);
}

/* Returns false (with err_buf set) for anything that isn't a clean 0-65535
 * integer -- including trailing garbage and values strtol() saturated due
 * to overflow, which is why errno is checked alongside the range. */
static bool parse_port(const char *text, int *out_port, char *err_buf, size_t err_buf_len) {
    char *end = NULL;
    errno = 0;
    long port = strtol(text, &end, 10);
    if (end == text || *end != '\0' || errno == ERANGE || port < 0 || port > 65535) {
        snprintf(err_buf, err_buf_len, "invalid port '%s' (expected 0-65535)", text);
        return false;
    }
    *out_port = (int) port;
    return true;
}

bool ns_config_parse(int argc, char *const *argv, ns_config_t *out, char *err_buf,
                     size_t err_buf_len) {
    memset(out, 0, sizeof(*out));
    out->filter_port = -1;
    out->format = NS_FORMAT_TEXT;
    out->log_level = NS_LOG_WARN;

    bool have_interface = false;
    bool have_read_file = false;
    bool any_simple_filter = false;

    /* optind = 1 makes this safe to call more than once per process (every
     * test in tests/test_config.c does); opterr = 0 suppresses getopt's own
     * stderr diagnostic so the caller sees exactly one error message, ours,
     * built below from optopt/argv. */
    optind = 1;
    opterr = 0;
    int c;
    while ((c = getopt_long(argc, argv, "i:r:hv", kLongOptions, NULL)) != -1) {
        switch (c) {
            case 'i':
                copy_str(out->interface, sizeof(out->interface), optarg);
                have_interface = true;
                break;
            case 'r':
                copy_str(out->read_file, sizeof(out->read_file), optarg);
                have_read_file = true;
                break;
            case 'h':
                out->show_help = true;
                break;
            case 'v':
                if (out->log_level < NS_LOG_DEBUG) {
                    out->log_level++;
                }
                break;
            case OPT_VERSION:
                out->show_version = true;
                break;
            case OPT_LIST_INTERFACES:
                out->list_interfaces = true;
                break;
            case OPT_TCP:
                out->filter_tcp = true;
                any_simple_filter = true;
                break;
            case OPT_UDP:
                out->filter_udp = true;
                any_simple_filter = true;
                break;
            case OPT_ICMP:
                out->filter_icmp = true;
                any_simple_filter = true;
                break;
            case OPT_PORT:
                if (!parse_port(optarg, &out->filter_port, err_buf, err_buf_len)) {
                    return false;
                }
                any_simple_filter = true;
                break;
            case OPT_HOST:
                copy_str(out->filter_host, sizeof(out->filter_host), optarg);
                any_simple_filter = true;
                break;
            case OPT_SRC:
                copy_str(out->filter_src, sizeof(out->filter_src), optarg);
                any_simple_filter = true;
                break;
            case OPT_DST:
                copy_str(out->filter_dst, sizeof(out->filter_dst), optarg);
                any_simple_filter = true;
                break;
            case OPT_FILTER:
                copy_str(out->raw_filter, sizeof(out->raw_filter), optarg);
                out->has_raw_filter = true;
                break;
            case OPT_NO_COLOR:
                out->no_color = true;
                break;
            case OPT_VERBOSE:
                out->verbose_output = true;
                break;
            case OPT_QUIET:
                out->quiet = true;
                break;
            case OPT_STATS:
                out->show_stats = true;
                break;
            case OPT_HEX:
                out->hex_dump = true;
                break;
            case OPT_WRITE:
                copy_str(out->write_file, sizeof(out->write_file), optarg);
                break;
            case OPT_FORMAT:
                if (strcmp(optarg, "json") == 0) {
                    out->format = NS_FORMAT_JSON;
                } else if (strcmp(optarg, "text") == 0) {
                    out->format = NS_FORMAT_TEXT;
                } else {
                    snprintf(err_buf, err_buf_len,
                             "unknown --format value '%s' (expected 'text' or 'json')", optarg);
                    return false;
                }
                break;
            case OPT_OUTPUT:
                copy_str(out->output_file, sizeof(out->output_file), optarg);
                break;
            case OPT_DEBUG:
                out->log_level = NS_LOG_DEBUG;
                break;
            case '?':
            default:
                if (optopt != 0) {
                    snprintf(err_buf, err_buf_len, "unrecognized option or missing argument: '-%c'",
                             optopt);
                } else if (optind > 1) {
                    snprintf(err_buf, err_buf_len, "unrecognized option '%s'", argv[optind - 1]);
                } else {
                    snprintf(err_buf, err_buf_len, "unrecognized option");
                }
                return false;
        }
    }

    if (optind < argc) {
        snprintf(err_buf, err_buf_len, "unexpected argument '%s'", argv[optind]);
        return false;
    }

    if (out->show_help || out->show_version) {
        return true;
    }

    if (have_interface && have_read_file) {
        snprintf(err_buf, err_buf_len, "-i and -r cannot be used simultaneously");
        return false;
    }

    if (out->has_raw_filter && any_simple_filter) {
        snprintf(err_buf, err_buf_len,
                 "--filter cannot be combined with --tcp/--udp/--icmp/--port/--host/--src/--dst");
        return false;
    }

    if (out->output_file[0] != '\0' && out->format != NS_FORMAT_JSON) {
        snprintf(err_buf, err_buf_len, "--output requires --format json");
        return false;
    }

    if (out->list_interfaces) {
        return true;
    }

    if (have_interface) {
        out->input_mode = NS_INPUT_LIVE;
    } else if (have_read_file) {
        out->input_mode = NS_INPUT_FILE;
    } else {
        snprintf(err_buf, err_buf_len, "either -i <interface> or -r <file> is required");
        return false;
    }

    return true;
}

void ns_config_print_help(const char *program_name, FILE *out) {
    fprintf(out,
            "%s %s -- capture and analyze network traffic\n"
            "\n"
            "Usage:\n"
            "  %s -i <interface> [options]\n"
            "  %s -r <capture.pcap> [options]\n"
            "  %s --list-interfaces\n"
            "\n"
            "Input:\n"
            "  -i, --interface <name>   capture live from a network interface\n"
            "  -r, --read <file>        read packets from a pcap file\n"
            "      --list-interfaces    list available capture interfaces and exit\n"
            "\n"
            "Filtering (simplified; translated to a BPF expression):\n"
            "      --tcp                only TCP packets\n"
            "      --udp                only UDP packets\n"
            "      --icmp               only ICMP/ICMPv6 packets\n"
            "      --port <n>           only packets on port n\n"
            "      --host <addr>        only packets to/from addr\n"
            "      --src <addr>         only packets from addr\n"
            "      --dst <addr>         only packets to addr\n"
            "      --filter <bpf>       raw BPF expression (mutually exclusive with the above)\n"
            "\n"
            "Output:\n"
            "      --no-color           disable ANSI colors\n"
            "      --verbose            print a detailed field-by-field block per packet\n"
            "      --quiet              suppress per-packet output\n"
            "      --stats              print traffic statistics when capture ends\n"
            "      --hex                print a hex dump of each packet\n"
            "      --format <text|json> output format (default: text)\n"
            "      --output <file>      write --format json output to file instead of stdout\n"
            "      --write <file>       save captured packets to a pcap file\n"
            "\n"
            "Diagnostics:\n"
            "  -v, -vv                  increase internal log verbosity (INFO, DEBUG)\n"
            "      --debug              shorthand for -vv\n"
            "\n"
            "  -h, --help               show this help and exit\n"
            "      --version            show version information and exit\n",
            NS_NAME, NS_VERSION_STRING, program_name, program_name, program_name);
}

void ns_config_print_version(FILE *out) {
    fprintf(out, "%s %s\n", NS_NAME, NS_VERSION_STRING);
}
