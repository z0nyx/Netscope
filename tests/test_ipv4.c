#include "netscope/protocols/ipv4.h"

#include "test_framework.h"

static void test_valid_ipv4(void) {
    static const uint8_t pkt[] = {
        0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06,
        0x00, 0x00, 0xc0, 0xa8, 0x01, 0x0c, 0x8e, 0xfa, 0x4a, 0x0e,
    };

    ns_ipv4_info_t info;
    size_t header_len = 0;
    ns_parse_status_t status = ns_parse_ipv4(pkt, sizeof(pkt), &info, &header_len);

    NS_CHECK(status == NS_PARSE_OK);
    NS_CHECK(header_len == 20);
    NS_CHECK(info.version == 4);
    NS_CHECK(info.ihl == 5);
    NS_CHECK(info.total_length == 40);
    NS_CHECK(info.ttl == 64);
    NS_CHECK(info.protocol == 6);
    NS_CHECK(info.flag_df);
    NS_CHECK(!info.flag_mf);
    NS_CHECK(!info.is_fragment);
    NS_CHECK(info.source == 0x0c01a8c0u);
}

static void test_ipv4_with_options(void) {
    static const uint8_t pkt[] = {
        0x46, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x0c, 0x08, 0x08, 0x08, 0x08, 0x00, 0x00, 0x00, 0x00,
    };

    ns_ipv4_info_t info;
    size_t header_len = 0;
    ns_parse_status_t status = ns_parse_ipv4(pkt, sizeof(pkt), &info, &header_len);

    NS_CHECK(status == NS_PARSE_OK);
    NS_CHECK(header_len == 24);
    NS_CHECK(info.ihl == 6);
}

static void test_invalid_version(void) {
    static const uint8_t pkt[] = {
        0x65, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06,
        0x00, 0x00, 0xc0, 0xa8, 0x01, 0x0c, 0x8e, 0xfa, 0x4a, 0x0e,
    };

    ns_ipv4_info_t info;
    size_t header_len = 0;
    ns_parse_status_t status = ns_parse_ipv4(pkt, sizeof(pkt), &info, &header_len);

    NS_CHECK(status == NS_PARSE_MALFORMED);
}

static void test_invalid_ihl(void) {
    static const uint8_t pkt[] = {
        0x44, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06,
        0x00, 0x00, 0xc0, 0xa8, 0x01, 0x0c, 0x8e, 0xfa, 0x4a, 0x0e,
    };

    ns_ipv4_info_t info;
    size_t header_len = 0;
    ns_parse_status_t status = ns_parse_ipv4(pkt, sizeof(pkt), &info, &header_len);

    NS_CHECK(status == NS_PARSE_MALFORMED);
}

static void test_truncated_ipv4(void) {
    static const uint8_t pkt[] = {0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06};

    ns_ipv4_info_t info;
    size_t header_len = 0;
    ns_parse_status_t status = ns_parse_ipv4(pkt, sizeof(pkt), &info, &header_len);

    NS_CHECK(status == NS_PARSE_TRUNCATED);
}

static void test_fragmented_ipv4(void) {
    static const uint8_t pkt[] = {
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x05, 0x00, 0x64, 0x40, 0x06,
        0x00, 0x00, 0xc0, 0xa8, 0x01, 0x0c, 0x8e, 0xfa, 0x4a, 0x0e,
    };

    ns_ipv4_info_t info;
    size_t header_len = 0;
    ns_parse_status_t status = ns_parse_ipv4(pkt, sizeof(pkt), &info, &header_len);

    NS_CHECK(status == NS_PARSE_OK);
    NS_CHECK(info.is_fragment);
    NS_CHECK(!info.is_initial_fragment);
    NS_CHECK(info.fragment_offset == 100);
}

NS_TEST_MAIN_BEGIN()
NS_RUN(test_valid_ipv4);
NS_RUN(test_ipv4_with_options);
NS_RUN(test_invalid_version);
NS_RUN(test_invalid_ihl);
NS_RUN(test_truncated_ipv4);
NS_RUN(test_fragmented_ipv4);
NS_TEST_MAIN_END()
