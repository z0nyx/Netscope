#include "netscope/stats.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "netscope/util.h"

void ns_stats_init(ns_stats_t *stats) {
    memset(stats, 0, sizeof(*stats));
}

/* Returns false for anything with no network-layer address pair to key a
 * flow on (e.g. an unhandled ethertype/IP protocol); such packets still
 * count toward the totals in ns_stats_update, just not toward a flow. */
static bool extract_endpoints(const ns_packet_t *pkt, ns_proto_t *proto, char *addr_a,
                              size_t addr_a_len, uint16_t *port_a, char *addr_b, size_t addr_b_len,
                              uint16_t *port_b) {
    *port_a = 0;
    *port_b = 0;

    if (pkt->network_proto == NS_PROTO_ARP) {
        *proto = NS_PROTO_ARP;
        ns_format_ipv4(pkt->net.arp.sender_ip, addr_a, addr_a_len);
        ns_format_ipv4(pkt->net.arp.target_ip, addr_b, addr_b_len);
        return true;
    }

    if (pkt->network_proto == NS_PROTO_IPV4) {
        ns_format_ipv4(pkt->net.ipv4.source, addr_a, addr_a_len);
        ns_format_ipv4(pkt->net.ipv4.destination, addr_b, addr_b_len);
    } else if (pkt->network_proto == NS_PROTO_IPV6) {
        ns_format_ipv6(pkt->net.ipv6.source, addr_a, addr_a_len);
        ns_format_ipv6(pkt->net.ipv6.destination, addr_b, addr_b_len);
    } else {
        return false;
    }

    switch (pkt->transport_proto) {
        case NS_PROTO_TCP:
            *proto = NS_PROTO_TCP;
            *port_a = pkt->transport.tcp.source_port;
            *port_b = pkt->transport.tcp.destination_port;
            return true;
        case NS_PROTO_UDP:
            *proto = NS_PROTO_UDP;
            *port_a = pkt->transport.udp.source_port;
            *port_b = pkt->transport.udp.destination_port;
            return true;
        case NS_PROTO_ICMP:
            *proto = NS_PROTO_ICMP;
            return true;
        case NS_PROTO_ICMPV6:
            *proto = NS_PROTO_ICMPV6;
            return true;
        default:
            return false;
    }
}

static uint32_t hash_flow(ns_proto_t proto, const char *addr_a, uint16_t port_a, const char *addr_b,
                          uint16_t port_b) {
    uint32_t h = 2166136261u;
    const uint8_t *p = (const uint8_t *) &proto;
    for (size_t i = 0; i < sizeof(proto); i++) {
        h = (h ^ p[i]) * 16777619u;
    }
    for (const char *s = addr_a; *s != '\0'; s++) {
        h = (h ^ (uint8_t) *s) * 16777619u;
    }
    for (const char *s = addr_b; *s != '\0'; s++) {
        h = (h ^ (uint8_t) *s) * 16777619u;
    }
    h = (h ^ (uint8_t) (port_a & 0xff)) * 16777619u;
    h = (h ^ (uint8_t) (port_a >> 8)) * 16777619u;
    h = (h ^ (uint8_t) (port_b & 0xff)) * 16777619u;
    h = (h ^ (uint8_t) (port_b >> 8)) * 16777619u;
    return h;
}

static void record_flow(ns_stats_t *stats, ns_proto_t proto, const char *addr_a, uint16_t port_a,
                        const char *addr_b, uint16_t port_b, uint64_t bytes) {
    /* Canonicalize direction so a packet A->B and the reply B->A hash to
     * the same flow entry instead of two separate ones. */
    if (strcmp(addr_a, addr_b) > 0 || (strcmp(addr_a, addr_b) == 0 && port_a > port_b)) {
        const char *tmp_addr = addr_a;
        addr_a = addr_b;
        addr_b = tmp_addr;
        uint16_t tmp_port = port_a;
        port_a = port_b;
        port_b = tmp_port;
    }

    uint32_t start = hash_flow(proto, addr_a, port_a, addr_b, port_b) % NS_MAX_FLOWS;
    for (uint32_t i = 0; i < NS_MAX_FLOWS; i++) {
        uint32_t idx = (start + i) % NS_MAX_FLOWS;
        ns_flow_t *slot = &stats->flows[idx];

        if (slot->in_use && slot->protocol == proto && strcmp(slot->addr_a, addr_a) == 0 &&
            strcmp(slot->addr_b, addr_b) == 0 && slot->port_a == port_a && slot->port_b == port_b) {
            slot->packets++;
            slot->bytes += bytes;
            return;
        }

        if (!slot->in_use) {
            slot->in_use = true;
            slot->protocol = proto;
            snprintf(slot->addr_a, sizeof(slot->addr_a), "%s", addr_a);
            snprintf(slot->addr_b, sizeof(slot->addr_b), "%s", addr_b);
            slot->port_a = port_a;
            slot->port_b = port_b;
            slot->packets = 1;
            slot->bytes = bytes;
            stats->flow_count++;
            return;
        }
    }
    /* Table full: new distinct flows stop being tracked; flows already
     * present keep accumulating. NS_MAX_FLOWS bounds this table's memory
     * instead of growing it without limit. */
}

void ns_stats_update(ns_stats_t *stats, const ns_packet_t *pkt) {
    stats->total_packets++;
    stats->total_captured_bytes += pkt->captured_length;
    stats->total_wire_bytes += pkt->original_length;

    if (pkt->malformed) {
        stats->malformed_packets++;
    }

    switch (pkt->network_proto) {
        case NS_PROTO_IPV4:
            stats->ipv4_packets++;
            break;
        case NS_PROTO_IPV6:
            stats->ipv6_packets++;
            break;
        case NS_PROTO_ARP:
            stats->arp_packets++;
            break;
        default:
            if (pkt->has_eth && !pkt->malformed) {
                stats->unsupported_packets++;
            }
            break;
    }

    switch (pkt->transport_proto) {
        case NS_PROTO_TCP:
            stats->tcp_packets++;
            break;
        case NS_PROTO_UDP:
            stats->udp_packets++;
            break;
        case NS_PROTO_ICMP:
            stats->icmp_packets++;
            break;
        case NS_PROTO_ICMPV6:
            stats->icmpv6_packets++;
            break;
        default:
            break;
    }

    if (pkt->has_dns) {
        stats->dns_packets++;
    }

    ns_proto_t flow_proto;
    char addr_a[46], addr_b[46];
    uint16_t port_a, port_b;
    if (extract_endpoints(pkt, &flow_proto, addr_a, sizeof(addr_a), &port_a, addr_b, sizeof(addr_b),
                          &port_b)) {
        record_flow(stats, flow_proto, addr_a, port_a, addr_b, port_b, pkt->captured_length);
    }
}

static int compare_flow_ptrs_desc(const void *a, const void *b) {
    const ns_flow_t *fa = *(const ns_flow_t *const *) a;
    const ns_flow_t *fb = *(const ns_flow_t *const *) b;
    if (fa->bytes > fb->bytes) {
        return -1;
    }
    if (fa->bytes < fb->bytes) {
        return 1;
    }
    return 0;
}

static void print_protocol_line(FILE *out, const char *name, uint64_t count,
                                uint64_t total_packets) {
    if (count == 0) {
        return;
    }
    double pct = total_packets > 0 ? (100.0 * (double) count / (double) total_packets) : 0.0;
    fprintf(out, "  %-10s %8" PRIu64 "   %5.2f%%\n", name, count, pct);
}

void ns_stats_print(const ns_stats_t *stats, double duration_seconds, FILE *out) {
    char captured_str[32], wire_str[32];
    ns_format_bytes(stats->total_captured_bytes, captured_str, sizeof(captured_str));
    ns_format_bytes(stats->total_wire_bytes, wire_str, sizeof(wire_str));

    fprintf(out, "──────────────────────────────────────\n");
    fprintf(out, "NetScope Capture Statistics\n");
    fprintf(out, "──────────────────────────────────────\n\n");
    fprintf(out, "Duration:              %.2f s\n\n", duration_seconds);
    fprintf(out, "Packets:               %" PRIu64 "\n", stats->total_packets);
    fprintf(out, "Captured traffic:      %s\n", captured_str);
    fprintf(out, "Wire traffic:          %s\n\n", wire_str);

    fprintf(out, "Protocols\n");
    uint64_t other = stats->total_packets - stats->tcp_packets - stats->udp_packets -
                     stats->icmp_packets - stats->icmpv6_packets - stats->arp_packets;
    print_protocol_line(out, "TCP", stats->tcp_packets, stats->total_packets);
    print_protocol_line(out, "UDP", stats->udp_packets, stats->total_packets);
    print_protocol_line(out, "ICMP", stats->icmp_packets, stats->total_packets);
    print_protocol_line(out, "ICMPv6", stats->icmpv6_packets, stats->total_packets);
    print_protocol_line(out, "ARP", stats->arp_packets, stats->total_packets);
    print_protocol_line(out, "Other", other, stats->total_packets);

    fprintf(out, "\nApplication\n");
    fprintf(out, "  DNS        %8" PRIu64 "\n", stats->dns_packets);

    fprintf(out, "\nMalformed              %" PRIu64 "\n", stats->malformed_packets);
    fprintf(out, "──────────────────────────────────────\n");

    if (stats->flow_count == 0) {
        return;
    }

    const ns_flow_t *sorted[NS_MAX_FLOWS];
    size_t n = 0;
    for (size_t i = 0; i < NS_MAX_FLOWS; i++) {
        if (stats->flows[i].in_use) {
            sorted[n++] = &stats->flows[i];
        }
    }
    /* cppcheck flags this as reading uninitialized ns_flow_t fields; that
     * is a false positive from not tracking ns_stats_init()'s memset() of
     * the whole struct combined with record_flow() fully populating a slot
     * in the same statement that sets in_use = true -- every entry sorted
     * here (sorted[0..n)) was pulled from the flows[] array precisely
     * because its in_use flag was true. */
    /* cppcheck-suppress uninitvar */
    qsort((void *) sorted, n, sizeof(sorted[0]), compare_flow_ptrs_desc);

    fprintf(out, "\nTop conversations:\n\n");
    size_t shown = n < 10 ? n : 10;
    for (size_t i = 0; i < shown; i++) {
        const ns_flow_t *f = sorted[i];
        char bytes_str[32];
        ns_format_bytes(f->bytes, bytes_str, sizeof(bytes_str));

        if (f->port_a != 0 || f->port_b != 0) {
            fprintf(out, "%zu. %s:%u <-> %s:%u\n", i + 1, f->addr_a, f->port_a, f->addr_b,
                    f->port_b);
        } else {
            fprintf(out, "%zu. %s <-> %s\n", i + 1, f->addr_a, f->addr_b);
        }
        fprintf(out, "   %s\n", ns_proto_name(f->protocol));
        fprintf(out, "   packets: %" PRIu64 "\n", f->packets);
        fprintf(out, "   traffic: %s\n\n", bytes_str);
    }
}
