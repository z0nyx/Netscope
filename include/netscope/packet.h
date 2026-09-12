#ifndef NETSCOPE_PACKET_H
#define NETSCOPE_PACKET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "netscope/protocols/arp.h"
#include "netscope/protocols/dns.h"
#include "netscope/protocols/ethernet.h"
#include "netscope/protocols/icmp.h"
#include "netscope/protocols/icmpv6.h"
#include "netscope/protocols/ipv4.h"
#include "netscope/protocols/ipv6.h"
#include "netscope/protocols/tcp.h"
#include "netscope/protocols/udp.h"

typedef struct {
    int64_t seconds;
    int32_t microseconds;
} ns_timestamp_t;

typedef enum {
    NS_LINK_UNKNOWN = 0,
    NS_LINK_ETHERNET,
} ns_link_type_t;

typedef enum {
    NS_PROTO_UNKNOWN = 0,
    NS_PROTO_ARP,
    NS_PROTO_IPV4,
    NS_PROTO_IPV6,
    NS_PROTO_TCP,
    NS_PROTO_UDP,
    NS_PROTO_ICMP,
    NS_PROTO_ICMPV6,
    NS_PROTO_DNS,
} ns_proto_t;

typedef struct {
    uint64_t number;
    ns_timestamp_t timestamp;

    size_t captured_length;
    size_t original_length;

    const uint8_t *raw_data;

    ns_link_type_t link_type;
    bool has_eth;
    ns_eth_info_t eth;

    ns_proto_t network_proto;
    union {
        ns_arp_info_t arp;
        ns_ipv4_info_t ipv4;
        ns_ipv6_info_t ipv6;
    } net;

    ns_proto_t transport_proto;
    union {
        ns_tcp_info_t tcp;
        ns_udp_info_t udp;
        ns_icmp_info_t icmp;
        ns_icmpv6_info_t icmpv6;
    } transport;

    bool has_dns;
    ns_dns_info_t dns;

    const uint8_t *payload;
    size_t payload_length;

    bool malformed;
    const char *malformed_reason;
} ns_packet_t;

void ns_packet_parse(const uint8_t *data, size_t captured_length, size_t original_length,
                     ns_timestamp_t timestamp, uint64_t number, ns_link_type_t link_type,
                     ns_packet_t *out);

const char *ns_proto_name(ns_proto_t proto);

#endif
