#include "netscope/stats.h"

#include <string.h>

#include "test_framework.h"

static ns_timestamp_t kTs = {1700000000, 0};

static void make_tcp_packet(ns_packet_t *pkt, uint32_t src_ip, uint16_t src_port, uint32_t dst_ip,
                            uint16_t dst_port, size_t length) {
    memset(pkt, 0, sizeof(*pkt));
    pkt->timestamp = kTs;
    pkt->captured_length = length;
    pkt->original_length = length;
    pkt->network_proto = NS_PROTO_IPV4;
    pkt->net.ipv4.source = src_ip;
    pkt->net.ipv4.destination = dst_ip;
    pkt->transport_proto = NS_PROTO_TCP;
    pkt->transport.tcp.source_port = src_port;
    pkt->transport.tcp.destination_port = dst_port;
    pkt->transport.tcp.flags = NS_TCP_FLAG_ACK;
}

static void test_counters(void) {
    ns_stats_t stats;
    ns_stats_init(&stats);

    ns_packet_t pkt;
    make_tcp_packet(&pkt, 0x0101a8c0u, 1234, 0x0202a8c0u, 443, 100);
    ns_stats_update(&stats, &pkt);

    NS_CHECK(stats.total_packets == 1);
    NS_CHECK(stats.total_captured_bytes == 100);
    NS_CHECK(stats.ipv4_packets == 1);
    NS_CHECK(stats.tcp_packets == 1);
    NS_CHECK(stats.malformed_packets == 0);
}

static void test_malformed_counted(void) {
    ns_stats_t stats;
    ns_stats_init(&stats);

    ns_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.malformed = true;
    pkt.captured_length = 5;
    ns_stats_update(&stats, &pkt);

    NS_CHECK(stats.malformed_packets == 1);
    NS_CHECK(stats.total_packets == 1);
}

static void test_bidirectional_flow_aggregates(void) {
    ns_stats_t stats;
    ns_stats_init(&stats);

    ns_packet_t a_to_b, b_to_a;
    make_tcp_packet(&a_to_b, 0x0101a8c0u, 51342, 0x0202a8c0u, 443, 100);
    make_tcp_packet(&b_to_a, 0x0202a8c0u, 443, 0x0101a8c0u, 51342, 200);

    ns_stats_update(&stats, &a_to_b);
    ns_stats_update(&stats, &b_to_a);

    NS_CHECK(stats.flow_count == 1);

    size_t found = 0;
    for (size_t i = 0; i < NS_MAX_FLOWS; i++) {
        if (stats.flows[i].in_use) {
            found++;
            NS_CHECK(stats.flows[i].packets == 2);
            NS_CHECK(stats.flows[i].bytes == 300);
        }
    }
    NS_CHECK(found == 1);
}

static void test_distinct_flows_are_separate(void) {
    ns_stats_t stats;
    ns_stats_init(&stats);

    ns_packet_t p1, p2;
    make_tcp_packet(&p1, 0x0101a8c0u, 1111, 0x0202a8c0u, 443, 100);
    make_tcp_packet(&p2, 0x0101a8c0u, 2222, 0x0202a8c0u, 443, 100);

    ns_stats_update(&stats, &p1);
    ns_stats_update(&stats, &p2);

    NS_CHECK(stats.flow_count == 2);
}

static void test_print_does_not_crash(void) {
    ns_stats_t stats;
    ns_stats_init(&stats);

    ns_packet_t pkt;
    make_tcp_packet(&pkt, 0x0101a8c0u, 1234, 0x0202a8c0u, 443, 100);
    ns_stats_update(&stats, &pkt);

    ns_stats_print(&stats, 0.0, stdout);
    ns_stats_print(&stats, 12.5, stdout);
}

NS_TEST_MAIN_BEGIN()
NS_RUN(test_counters);
NS_RUN(test_malformed_counted);
NS_RUN(test_bidirectional_flow_aggregates);
NS_RUN(test_distinct_flows_are_separate);
NS_RUN(test_print_does_not_crash);
NS_TEST_MAIN_END()
