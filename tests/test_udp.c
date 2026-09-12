#include "netscope/protocols/udp.h"

#include "test_framework.h"

static void test_valid_udp(void) {
    static const uint8_t pkt[] = {0xd0, 0x5d, 0x00, 0x35, 0x00, 0x25, 0x00, 0x00};

    ns_udp_info_t info;
    ns_parse_status_t status = ns_parse_udp(pkt, sizeof(pkt), &info);

    NS_CHECK(status == NS_PARSE_OK);
    NS_CHECK(info.source_port == 53341);
    NS_CHECK(info.destination_port == 53);
    NS_CHECK(info.length == 37);
}

static void test_invalid_length(void) {
    static const uint8_t pkt[] = {0xd0, 0x5d, 0x00, 0x35, 0x00, 0x04, 0x00, 0x00};

    ns_udp_info_t info;
    ns_parse_status_t status = ns_parse_udp(pkt, sizeof(pkt), &info);

    NS_CHECK(status == NS_PARSE_MALFORMED);
}

static void test_truncated_udp(void) {
    static const uint8_t pkt[] = {0xd0, 0x5d, 0x00, 0x35};

    ns_udp_info_t info;
    ns_parse_status_t status = ns_parse_udp(pkt, sizeof(pkt), &info);

    NS_CHECK(status == NS_PARSE_TRUNCATED);
}

NS_TEST_MAIN_BEGIN()
NS_RUN(test_valid_udp);
NS_RUN(test_invalid_length);
NS_RUN(test_truncated_udp);
NS_TEST_MAIN_END()
