#include "netscope/output.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "netscope/protocols/tcp.h"
#include "netscope/util.h"

#if defined(_WIN32)
#include <io.h>
#define ns_isatty _isatty
#define ns_fileno _fileno
#else
#include <unistd.h>
#define ns_isatty isatty
#define ns_fileno fileno
#endif

#define NS_COLOR_TCP "\x1b[36m"
#define NS_COLOR_UDP "\x1b[32m"
#define NS_COLOR_ICMP "\x1b[33m"
#define NS_COLOR_DNS "\x1b[35m"
#define NS_COLOR_ARP "\x1b[36m"
#define NS_COLOR_ERROR "\x1b[31m"
#define NS_COLOR_RESET "\x1b[0m"

bool ns_output_should_use_color(bool no_color_flag, FILE *stream) {
    if (no_color_flag) {
        return false;
    }
    return ns_isatty(ns_fileno(stream)) != 0;
}

static ns_proto_t top_protocol(const ns_packet_t *pkt) {
    if (pkt->has_dns) {
        return NS_PROTO_DNS;
    }
    if (pkt->transport_proto != NS_PROTO_UNKNOWN) {
        return pkt->transport_proto;
    }
    return pkt->network_proto;
}

static const char *protocol_color(ns_proto_t proto) {
    switch (proto) {
        case NS_PROTO_TCP:
            return NS_COLOR_TCP;
        case NS_PROTO_UDP:
            return NS_COLOR_UDP;
        case NS_PROTO_ICMP:
        case NS_PROTO_ICMPV6:
            return NS_COLOR_ICMP;
        case NS_PROTO_DNS:
            return NS_COLOR_DNS;
        case NS_PROTO_ARP:
            return NS_COLOR_ARP;
        default:
            return "";
    }
}

static void format_timestamp(ns_timestamp_t ts, char *buf, size_t buf_len) {
    time_t t = (time_t) ts.seconds;
    struct tm tm_buf;
#if defined(_WIN32)
    /* cppcheck's std.cfg does not model localtime_s() as writing through
     * its first argument, so it incorrectly flags tm_buf as read
     * uninitialized here; this branch is also not exercised on the
     * project's Linux/macOS targets. */
    /* cppcheck-suppress uninitvar */
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    int ms = ts.microseconds / 1000;
    size_t pos = strftime(buf, buf_len, "%H:%M:%S", &tm_buf);
    snprintf(buf + pos, buf_len - pos, ".%03d", ms);
}

static void format_network_addrs(const ns_packet_t *pkt, char *src, size_t src_len, char *dst,
                                 size_t dst_len) {
    if (pkt->network_proto == NS_PROTO_IPV4) {
        ns_format_ipv4(pkt->net.ipv4.source, src, src_len);
        ns_format_ipv4(pkt->net.ipv4.destination, dst, dst_len);
    } else if (pkt->network_proto == NS_PROTO_IPV6) {
        ns_format_ipv6(pkt->net.ipv6.source, src, src_len);
        ns_format_ipv6(pkt->net.ipv6.destination, dst, dst_len);
    } else {
        snprintf(src, src_len, "?");
        snprintf(dst, dst_len, "?");
    }
}

static void print_arp_line(const ns_packet_t *pkt, FILE *out, const char *color,
                           const char *reset) {
    char sender[16], target[16], sender_mac[18];
    ns_format_ipv4(pkt->net.arp.sender_ip, sender, sizeof(sender));
    ns_format_ipv4(pkt->net.arp.target_ip, target, sizeof(target));
    ns_format_mac(pkt->net.arp.sender_mac, sender_mac, sizeof(sender_mac));

    if (pkt->net.arp.operation == NS_ARP_OP_REQUEST) {
        fprintf(out, "%sARP%s   %s -> %s   Who has %s?\n", color, reset, sender, target, target);
    } else if (pkt->net.arp.operation == NS_ARP_OP_REPLY) {
        fprintf(out, "%sARP%s   %s is at %s\n", color, reset, sender, sender_mac);
    } else {
        fprintf(out, "%sARP%s   %s -> %s   operation=%u\n", color, reset, sender, target,
                pkt->net.arp.operation);
    }
}

static void print_text_line(const ns_packet_t *pkt, const ns_output_options_t *opts, FILE *out) {
    const char *color = opts->color ? protocol_color(top_protocol(pkt)) : "";
    const char *reset = opts->color ? NS_COLOR_RESET : "";

    if (pkt->malformed) {
        const char *err_color = opts->color ? NS_COLOR_ERROR : "";
        char ts[16];
        format_timestamp(pkt->timestamp, ts, sizeof(ts));
        fprintf(out, "[%s] %sMALFORMED%s %s (%zu bytes captured)\n", ts, err_color, reset,
                pkt->malformed_reason != NULL ? pkt->malformed_reason : "unknown reason",
                pkt->captured_length);
        return;
    }

    if (pkt->network_proto == NS_PROTO_ARP) {
        char ts[16];
        format_timestamp(pkt->timestamp, ts, sizeof(ts));
        fprintf(out, "[%s] ", ts);
        print_arp_line(pkt, out, color, reset);
        return;
    }

    char ts[16];
    format_timestamp(pkt->timestamp, ts, sizeof(ts));

    char src[46], dst[46];
    format_network_addrs(pkt, src, sizeof(src), dst, sizeof(dst));

    char src_ep[64], dst_ep[64];
    const char *proto_name;
    char extra[128] = "";

    switch (pkt->transport_proto) {
        case NS_PROTO_TCP: {
            proto_name = "TCP";
            snprintf(src_ep, sizeof(src_ep), "%s:%u", src, pkt->transport.tcp.source_port);
            snprintf(dst_ep, sizeof(dst_ep), "%s:%u", dst, pkt->transport.tcp.destination_port);
            char flags[32];
            ns_tcp_flags_to_string(pkt->transport.tcp.flags, flags, sizeof(flags));
            snprintf(extra, sizeof(extra), "[%s]", flags);
            break;
        }
        case NS_PROTO_UDP:
            proto_name = "UDP";
            snprintf(src_ep, sizeof(src_ep), "%s:%u", src, pkt->transport.udp.source_port);
            snprintf(dst_ep, sizeof(dst_ep), "%s:%u", dst, pkt->transport.udp.destination_port);
            if (pkt->has_dns) {
                snprintf(extra, sizeof(extra), "DNS");
            }
            break;
        case NS_PROTO_ICMP:
            proto_name = "ICMP";
            snprintf(src_ep, sizeof(src_ep), "%s", src);
            snprintf(dst_ep, sizeof(dst_ep), "%s", dst);
            if (pkt->transport.icmp.type == NS_ICMP_TYPE_ECHO_REQUEST ||
                pkt->transport.icmp.type == NS_ICMP_TYPE_ECHO_REPLY) {
                snprintf(extra, sizeof(extra), "%s id=%u seq=%u",
                         ns_icmp_type_name(pkt->transport.icmp.type),
                         pkt->transport.icmp.identifier, pkt->transport.icmp.sequence);
            } else {
                snprintf(extra, sizeof(extra), "%s", ns_icmp_type_name(pkt->transport.icmp.type));
            }
            break;
        case NS_PROTO_ICMPV6:
            proto_name = "ICMPv6";
            snprintf(src_ep, sizeof(src_ep), "%s", src);
            snprintf(dst_ep, sizeof(dst_ep), "%s", dst);
            snprintf(extra, sizeof(extra), "%s", ns_icmpv6_type_name(pkt->transport.icmpv6.type));
            break;
        default:
            proto_name = ns_proto_name(pkt->network_proto);
            snprintf(src_ep, sizeof(src_ep), "%s", src);
            snprintf(dst_ep, sizeof(dst_ep), "%s", dst);
            break;
    }

    fprintf(out, "[%s] %s%-6s%s %s -> %s   %s %zu B\n", ts, color, proto_name, reset, src_ep,
            dst_ep, extra, pkt->captured_length);

    if (pkt->has_dns) {
        char type_buf[16];
        if (pkt->dns.is_response && pkt->dns.decoded_answer_count > 0) {
            const ns_dns_record_t *a = &pkt->dns.answers[0];
            fprintf(out, "    Response: %s %s %s\n", a->name,
                    ns_dns_type_name(a->type, type_buf, sizeof(type_buf)), a->rdata_text);
        } else if (!pkt->dns.is_response && pkt->dns.decoded_question_count > 0) {
            const ns_dns_question_t *q = &pkt->dns.questions[0];
            fprintf(out, "    Query: %s %s\n", q->name,
                    ns_dns_type_name(q->type, type_buf, sizeof(type_buf)));
        }
    }
}

static void print_verbose_block(const ns_packet_t *pkt, FILE *out) {
    fprintf(out, "\nPacket #%" PRIu64 "\n", pkt->number);
    char ts[16];
    format_timestamp(pkt->timestamp, ts, sizeof(ts));
    fprintf(out, "Timestamp: %s.%06d\n", ts, pkt->timestamp.microseconds % 1000000);
    fprintf(out, "Captured length: %zu bytes\n\n", pkt->captured_length);

    if (pkt->has_eth) {
        char dst_mac[18], src_mac[18];
        ns_format_mac(pkt->eth.destination, dst_mac, sizeof(dst_mac));
        ns_format_mac(pkt->eth.source, src_mac, sizeof(src_mac));
        fprintf(out, "Ethernet\n");
        fprintf(out, "  Source:      %s\n", src_mac);
        fprintf(out, "  Destination: %s\n", dst_mac);
        fprintf(out, "  Type:        0x%04x\n", pkt->eth.ethertype);
        if (pkt->eth.has_vlan) {
            fprintf(out, "  VLAN:        %u\n", pkt->eth.vlan_id);
        }
        fprintf(out, "\n");
    }

    if (pkt->network_proto == NS_PROTO_IPV4) {
        char src[16], dst[16];
        ns_format_ipv4(pkt->net.ipv4.source, src, sizeof(src));
        ns_format_ipv4(pkt->net.ipv4.destination, dst, sizeof(dst));
        fprintf(out, "IPv4\n");
        fprintf(out, "  Source:      %s\n", src);
        fprintf(out, "  Destination: %s\n", dst);
        fprintf(out, "  TTL:         %u\n", pkt->net.ipv4.ttl);
        fprintf(out, "  Protocol:    %u\n\n", pkt->net.ipv4.protocol);
    } else if (pkt->network_proto == NS_PROTO_IPV6) {
        char src[46], dst[46];
        ns_format_ipv6(pkt->net.ipv6.source, src, sizeof(src));
        ns_format_ipv6(pkt->net.ipv6.destination, dst, sizeof(dst));
        fprintf(out, "IPv6\n");
        fprintf(out, "  Source:      %s\n", src);
        fprintf(out, "  Destination: %s\n", dst);
        fprintf(out, "  Hop limit:   %u\n", pkt->net.ipv6.hop_limit);
        fprintf(out, "  Next header: %u\n\n", pkt->net.ipv6.next_header);
    }

    if (pkt->transport_proto == NS_PROTO_TCP) {
        char flags[32];
        ns_tcp_flags_to_string(pkt->transport.tcp.flags, flags, sizeof(flags));
        fprintf(out, "TCP\n");
        fprintf(out, "  Source port:      %u\n", pkt->transport.tcp.source_port);
        fprintf(out, "  Destination port: %u\n", pkt->transport.tcp.destination_port);
        fprintf(out, "  Sequence:         %u\n", pkt->transport.tcp.sequence_number);
        fprintf(out, "  Ack:              %u\n", pkt->transport.tcp.ack_number);
        fprintf(out, "  Flags:            %s\n", flags);
        fprintf(out, "  Window:           %u\n\n", pkt->transport.tcp.window_size);
    } else if (pkt->transport_proto == NS_PROTO_UDP) {
        fprintf(out, "UDP\n");
        fprintf(out, "  Source port:      %u\n", pkt->transport.udp.source_port);
        fprintf(out, "  Destination port: %u\n", pkt->transport.udp.destination_port);
        fprintf(out, "  Length:           %u\n\n", pkt->transport.udp.length);
    }

    fprintf(out, "Payload: %zu bytes\n", pkt->payload_length);
}

/*
 * DNS labels are arbitrary bytes, not guaranteed-valid UTF-8 or even
 * printable ASCII, and they end up in JSON output (question/rdata names).
 * Escaping everything outside printable ASCII as \u00XX (one escape per
 * raw byte, not a UTF-8 decode) keeps the output always-valid, 7-bit-clean
 * JSON regardless of what a hostile or malformed name contains -- at the
 * cost of not reassembling multi-byte UTF-8 sequences, which is an
 * acceptable trade for input this tool cannot trust in the first place.
 */
static void json_write_escaped(FILE *out, const char *s) {
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *) s; *p != '\0'; p++) {
        switch (*p) {
            case '"':
                fputs("\\\"", out);
                break;
            case '\\':
                fputs("\\\\", out);
                break;
            case '\n':
                fputs("\\n", out);
                break;
            case '\r':
                fputs("\\r", out);
                break;
            case '\t':
                fputs("\\t", out);
                break;
            default:
                if (*p < 0x20 || *p >= 0x7f) {
                    fprintf(out, "\\u%04x", *p);
                } else {
                    fputc((int) *p, out);
                }
        }
    }
    fputc('"', out);
}

static void print_json_line(const ns_packet_t *pkt, FILE *out) {
    char ts_iso[32];
    time_t t = (time_t) pkt->timestamp.seconds;
    struct tm tm_buf;
#if defined(_WIN32)
    gmtime_s(&tm_buf, &t);
#else
    gmtime_r(&t, &tm_buf);
#endif
    size_t pos = strftime(ts_iso, sizeof(ts_iso), "%Y-%m-%dT%H:%M:%S", &tm_buf);
    snprintf(ts_iso + pos, sizeof(ts_iso) - pos, ".%03dZ", pkt->timestamp.microseconds / 1000);

    fprintf(out, "{\"timestamp\":");
    json_write_escaped(out, ts_iso);
    fprintf(out, ",\"captured_length\":%zu,\"malformed\":%s", pkt->captured_length,
            pkt->malformed ? "true" : "false");

    ns_proto_t proto = top_protocol(pkt);
    fprintf(out, ",\"protocol\":");
    json_write_escaped(out, ns_proto_name(proto));

    if (pkt->network_proto == NS_PROTO_IPV4 || pkt->network_proto == NS_PROTO_IPV6) {
        char src[46], dst[46];
        format_network_addrs(pkt, src, sizeof(src), dst, sizeof(dst));

        fprintf(out, ",\"source\":{\"ip\":");
        json_write_escaped(out, src);
        if (pkt->transport_proto == NS_PROTO_TCP || pkt->transport_proto == NS_PROTO_UDP) {
            uint16_t port = pkt->transport_proto == NS_PROTO_TCP ? pkt->transport.tcp.source_port
                                                                 : pkt->transport.udp.source_port;
            fprintf(out, ",\"port\":%u", port);
        }
        fprintf(out, "}");

        fprintf(out, ",\"destination\":{\"ip\":");
        json_write_escaped(out, dst);
        if (pkt->transport_proto == NS_PROTO_TCP || pkt->transport_proto == NS_PROTO_UDP) {
            uint16_t port = pkt->transport_proto == NS_PROTO_TCP
                                ? pkt->transport.tcp.destination_port
                                : pkt->transport.udp.destination_port;
            fprintf(out, ",\"port\":%u", port);
        }
        fprintf(out, "}");
    }

    if (pkt->transport_proto == NS_PROTO_TCP) {
        static const struct {
            uint8_t bit;
            const char *name;
        } kFlags[] = {
            {NS_TCP_FLAG_SYN, "SYN"}, {NS_TCP_FLAG_ACK, "ACK"}, {NS_TCP_FLAG_FIN, "FIN"},
            {NS_TCP_FLAG_RST, "RST"}, {NS_TCP_FLAG_PSH, "PSH"}, {NS_TCP_FLAG_URG, "URG"},
            {NS_TCP_FLAG_ECE, "ECE"}, {NS_TCP_FLAG_CWR, "CWR"},
        };
        fprintf(out, ",\"tcp\":{\"flags\":[");
        bool first = true;
        for (size_t i = 0; i < sizeof(kFlags) / sizeof(kFlags[0]); i++) {
            if (pkt->transport.tcp.flags & kFlags[i].bit) {
                if (!first) {
                    fputc(',', out);
                }
                json_write_escaped(out, kFlags[i].name);
                first = false;
            }
        }
        fprintf(out, "]}");
    }

    if (pkt->has_dns && pkt->dns.decoded_question_count > 0) {
        char type_buf[16];
        fprintf(out, ",\"dns\":{\"question\":");
        json_write_escaped(out, pkt->dns.questions[0].name);
        fprintf(out, ",\"type\":");
        json_write_escaped(
            out, ns_dns_type_name(pkt->dns.questions[0].type, type_buf, sizeof(type_buf)));
        fprintf(out, "}");
    }

    fprintf(out, "}\n");
}

void ns_output_packet(const ns_packet_t *pkt, const ns_output_options_t *opts, FILE *out) {
    if (opts->format == NS_FORMAT_JSON) {
        print_json_line(pkt, out);
        return;
    }

    if (!opts->quiet) {
        print_text_line(pkt, opts, out);
        if (opts->verbose) {
            print_verbose_block(pkt, out);
        }
        if (opts->hex) {
            ns_hex_dump_file(pkt->raw_data, pkt->captured_length, out);
        }
    }
}
