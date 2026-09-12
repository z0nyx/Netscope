#include "netscope/protocols/ethernet.h"

#include <string.h>

#include "test_framework.h"

static void test_valid_ethernet(void) {
    static const uint8_t pkt[] = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x08, 0x00,
    };

    ns_eth_info_t info;
    size_t header_len = 0;
    ns_parse_status_t status = ns_parse_ethernet(pkt, sizeof(pkt), &info, &header_len);

    NS_CHECK(status == NS_PARSE_OK);
    NS_CHECK(header_len == 14);
    NS_CHECK(memcmp(info.destination, pkt, 6) == 0);
    NS_CHECK(memcmp(info.source, pkt + 6, 6) == 0);
    NS_CHECK(info.ethertype == NS_ETHERTYPE_IPV4);
    NS_CHECK(!info.has_vlan);
}

static void test_vlan_tagged_ethernet(void) {
    static const uint8_t pkt[] = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x81, 0x00, 0x00, 0x64, 0x08, 0x00,
    };

    ns_eth_info_t info;
    size_t header_len = 0;
    ns_parse_status_t status = ns_parse_ethernet(pkt, sizeof(pkt), &info, &header_len);

    NS_CHECK(status == NS_PARSE_OK);
    NS_CHECK(header_len == 18);
    NS_CHECK(info.has_vlan);
    NS_CHECK(info.vlan_id == 100);
    NS_CHECK(info.ethertype == NS_ETHERTYPE_IPV4);
}

static void test_truncated_ethernet(void) {
    static const uint8_t pkt[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33};

    ns_eth_info_t info;
    size_t header_len = 0;
    ns_parse_status_t status = ns_parse_ethernet(pkt, sizeof(pkt), &info, &header_len);

    NS_CHECK(status == NS_PARSE_TRUNCATED);
}

static void test_truncated_vlan_tag(void) {
    static const uint8_t pkt[] = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x81, 0x00, 0x00, 0x64,
    };

    ns_eth_info_t info;
    size_t header_len = 0;
    ns_parse_status_t status = ns_parse_ethernet(pkt, sizeof(pkt), &info, &header_len);

    NS_CHECK(status == NS_PARSE_TRUNCATED);
}

NS_TEST_MAIN_BEGIN()
NS_RUN(test_valid_ethernet);
NS_RUN(test_vlan_tagged_ethernet);
NS_RUN(test_truncated_ethernet);
NS_RUN(test_truncated_vlan_tag);
NS_TEST_MAIN_END()
