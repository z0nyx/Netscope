#include "netscope/protocols/icmp.h"
#include "netscope/protocols/icmpv6.h"

#include <string.h>

#include "test_framework.h"

static void test_icmp_echo_request(void) {
    static const uint8_t pkt[] = {0x08, 0x00, 0x00, 0x00, 0x01, 0x41, 0x00, 0x08};

    ns_icmp_info_t info;
    ns_parse_status_t status = ns_parse_icmp(pkt, sizeof(pkt), &info);

    NS_CHECK(status == NS_PARSE_OK);
    NS_CHECK(info.type == NS_ICMP_TYPE_ECHO_REQUEST);
    NS_CHECK(info.identifier == 0x0141);
    NS_CHECK(info.sequence == 0x0008);
    NS_CHECK(strcmp(ns_icmp_type_name(info.type), "Echo Request") == 0);
}

static void test_icmp_dest_unreachable(void) {
    static const uint8_t pkt[] = {0x03, 0x01, 0x00, 0x00};

    ns_icmp_info_t info;
    ns_parse_status_t status = ns_parse_icmp(pkt, sizeof(pkt), &info);

    NS_CHECK(status == NS_PARSE_OK);
    NS_CHECK(info.type == NS_ICMP_TYPE_DEST_UNREACHABLE);
    NS_CHECK(strcmp(ns_icmp_type_name(info.type), "Destination Unreachable") == 0);
}

static void test_icmp_truncated(void) {
    static const uint8_t pkt[] = {0x08, 0x00};

    ns_icmp_info_t info;
    ns_parse_status_t status = ns_parse_icmp(pkt, sizeof(pkt), &info);

    NS_CHECK(status == NS_PARSE_TRUNCATED);
}

static void test_icmp_echo_request_truncated(void) {
    static const uint8_t pkt[] = {0x08, 0x00, 0x00, 0x00};

    ns_icmp_info_t info;
    ns_parse_status_t status = ns_parse_icmp(pkt, sizeof(pkt), &info);

    NS_CHECK(status == NS_PARSE_TRUNCATED);
}

static void test_icmpv6_echo_request(void) {
    static const uint8_t pkt[] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x01};

    ns_icmpv6_info_t info;
    ns_parse_status_t status = ns_parse_icmpv6(pkt, sizeof(pkt), &info);

    NS_CHECK(status == NS_PARSE_OK);
    NS_CHECK(info.type == NS_ICMPV6_TYPE_ECHO_REQUEST);
    NS_CHECK(info.identifier == 0x0011);
    NS_CHECK(info.sequence == 0x0001);
    NS_CHECK(strcmp(ns_icmpv6_type_name(info.type), "Echo Request") == 0);
}

static void test_icmpv6_neighbor_solicitation_name(void) {
    NS_CHECK(strcmp(ns_icmpv6_type_name(NS_ICMPV6_TYPE_NEIGHBOR_SOLICITATION),
                    "Neighbor Solicitation") == 0);
}

NS_TEST_MAIN_BEGIN()
NS_RUN(test_icmp_echo_request);
NS_RUN(test_icmp_dest_unreachable);
NS_RUN(test_icmp_truncated);
NS_RUN(test_icmp_echo_request_truncated);
NS_RUN(test_icmpv6_echo_request);
NS_RUN(test_icmpv6_neighbor_solicitation_name);
NS_TEST_MAIN_END()
