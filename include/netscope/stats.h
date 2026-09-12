#ifndef NETSCOPE_STATS_H
#define NETSCOPE_STATS_H

#include <stdint.h>
#include <stdio.h>

#include "netscope/packet.h"

#define NS_MAX_FLOWS 1024u

typedef struct {
    bool in_use;
    ns_proto_t protocol;
    char addr_a[46];
    char addr_b[46];
    uint16_t port_a;
    uint16_t port_b;
    uint64_t packets;
    uint64_t bytes;
} ns_flow_t;

typedef struct {
    uint64_t total_packets;
    uint64_t total_captured_bytes;
    uint64_t total_wire_bytes;

    uint64_t ipv4_packets;
    uint64_t ipv6_packets;
    uint64_t arp_packets;

    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;
    uint64_t icmpv6_packets;

    uint64_t dns_packets;

    uint64_t malformed_packets;
    uint64_t unsupported_packets;

    ns_flow_t flows[NS_MAX_FLOWS];
    size_t flow_count;
} ns_stats_t;

void ns_stats_init(ns_stats_t *stats);

void ns_stats_update(ns_stats_t *stats, const ns_packet_t *pkt);

void ns_stats_print(const ns_stats_t *stats, double duration_seconds, FILE *out);

#endif
