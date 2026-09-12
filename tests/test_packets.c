#include "netscope/packet.h"

#include <string.h>

#include "test_framework.h"

static ns_timestamp_t kTs = {1700000000, 0};

static const uint8_t kTcpSyn[] = {
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x08, 0x00,
    0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8,
    0x01, 0x0c, 0x8e, 0xfa, 0x4a, 0x0e, 0xc8, 0x8e, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t kIpv4Fragment[] = {
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x08, 0x00,
    0x45, 0x00, 0x00, 0x1c, 0x00, 0x05, 0x00, 0x64, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8,
    0x01, 0x0c, 0x8e, 0xfa, 0x4a, 0x0e, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
};

static const uint8_t kArpRequest[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x06,
    0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0xc0, 0xa8, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x05,
};

static const uint8_t kIcmpv6EchoRequest[] = {
    0x33, 0x33, 0x00, 0x00, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x86, 0xdd, 0x60, 0x00,
    0x00, 0x00, 0x00, 0x08, 0x3a, 0x40, 0xfe, 0x80, 0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0x01, 0xfe, 0x80, 0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0x02, 0x80, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x01,
};

static const uint8_t kDnsQuery[] = {
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x08, 0x00, 0x45,
    0x00, 0x00, 0x39, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x0c,
    0x08, 0x08, 0x08, 0x08, 0xd0, 0x5d, 0x00, 0x35, 0x00, 0x25, 0x00, 0x00, 0x12, 0x34, 0x01,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 'e',  'x',  'a',  'm',  'p',
    'l',  'e',  0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01,
};

static void test_parse_tcp_syn(void) {
    ns_packet_t pkt;
    ns_packet_parse(kTcpSyn, sizeof(kTcpSyn), sizeof(kTcpSyn), kTs, 1, NS_LINK_ETHERNET, &pkt);

    NS_CHECK(!pkt.malformed);
    NS_CHECK(pkt.has_eth);
    NS_CHECK(pkt.network_proto == NS_PROTO_IPV4);
    NS_CHECK(pkt.transport_proto == NS_PROTO_TCP);
    NS_CHECK(pkt.transport.tcp.destination_port == 443);
    NS_CHECK(pkt.transport.tcp.flags == NS_TCP_FLAG_SYN);
    NS_CHECK(pkt.payload_length == 0);
}

static void test_parse_ipv4_fragment(void) {
    ns_packet_t pkt;
    ns_packet_parse(kIpv4Fragment, sizeof(kIpv4Fragment), sizeof(kIpv4Fragment), kTs, 2,
                    NS_LINK_ETHERNET, &pkt);

    NS_CHECK(!pkt.malformed);
    NS_CHECK(pkt.network_proto == NS_PROTO_IPV4);
    NS_CHECK(pkt.net.ipv4.is_fragment);
    NS_CHECK(!pkt.net.ipv4.is_initial_fragment);

    NS_CHECK(pkt.transport_proto == NS_PROTO_UNKNOWN);
    NS_CHECK(pkt.payload_length == 8);
}

static void test_parse_arp(void) {
    ns_packet_t pkt;
    ns_packet_parse(kArpRequest, sizeof(kArpRequest), sizeof(kArpRequest), kTs, 3, NS_LINK_ETHERNET,
                    &pkt);

    NS_CHECK(!pkt.malformed);
    NS_CHECK(pkt.network_proto == NS_PROTO_ARP);
    NS_CHECK(pkt.net.arp.operation == NS_ARP_OP_REQUEST);
}

static void test_parse_icmpv6(void) {
    ns_packet_t pkt;
    ns_packet_parse(kIcmpv6EchoRequest, sizeof(kIcmpv6EchoRequest), sizeof(kIcmpv6EchoRequest), kTs,
                    4, NS_LINK_ETHERNET, &pkt);

    NS_CHECK(!pkt.malformed);
    NS_CHECK(pkt.network_proto == NS_PROTO_IPV6);
    NS_CHECK(pkt.transport_proto == NS_PROTO_ICMPV6);
    NS_CHECK(pkt.transport.icmpv6.type == NS_ICMPV6_TYPE_ECHO_REQUEST);
}

static void test_parse_dns_over_udp(void) {
    ns_packet_t pkt;
    ns_packet_parse(kDnsQuery, sizeof(kDnsQuery), sizeof(kDnsQuery), kTs, 5, NS_LINK_ETHERNET,
                    &pkt);

    NS_CHECK(!pkt.malformed);
    NS_CHECK(pkt.transport_proto == NS_PROTO_UDP);
    NS_CHECK(pkt.has_dns);
    NS_CHECK(strcmp(pkt.dns.questions[0].name, "example.com") == 0);
}

static void test_parse_truncated_garbage_never_crashes(void) {
    static const uint8_t garbage[] = {0x01, 0x02, 0x03, 0x04, 0x05};

    ns_packet_t pkt;
    ns_packet_parse(garbage, sizeof(garbage), sizeof(garbage), kTs, 6, NS_LINK_ETHERNET, &pkt);

    NS_CHECK(pkt.malformed);
    NS_CHECK(pkt.network_proto == NS_PROTO_UNKNOWN);
}

static void test_parse_unknown_link_type(void) {
    static const uint8_t data[] = {0x00, 0x01, 0x02, 0x03};

    ns_packet_t pkt;
    ns_packet_parse(data, sizeof(data), sizeof(data), kTs, 7, NS_LINK_UNKNOWN, &pkt);

    NS_CHECK(!pkt.malformed);
    NS_CHECK(!pkt.has_eth);
    NS_CHECK(pkt.network_proto == NS_PROTO_UNKNOWN);
}

NS_TEST_MAIN_BEGIN()
NS_RUN(test_parse_tcp_syn);
NS_RUN(test_parse_ipv4_fragment);
NS_RUN(test_parse_arp);
NS_RUN(test_parse_icmpv6);
NS_RUN(test_parse_dns_over_udp);
NS_RUN(test_parse_truncated_garbage_never_crashes);
NS_RUN(test_parse_unknown_link_type);
NS_TEST_MAIN_END()
