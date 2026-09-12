#include "netscope/protocols/ipv6.h"

#include <string.h>

#include "test_framework.h"

static void test_valid_ipv6(void) {
    static const uint8_t pkt[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0x40, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    };

    ns_ipv6_info_t info;
    size_t header_len = 0;
    ns_parse_status_t status = ns_parse_ipv6(pkt, sizeof(pkt), &info, &header_len);

    NS_CHECK(status == NS_PARSE_OK);
    NS_CHECK(header_len == NS_IPV6_HEADER_LEN);
    NS_CHECK(info.version == 6);
    NS_CHECK(info.payload_length == 8);
    NS_CHECK(info.next_header == NS_IPV6_NEXT_ICMPV6);
    NS_CHECK(info.hop_limit == 64);
    NS_CHECK(info.source[0] == 0xfe && info.source[1] == 0x80 && info.source[15] == 0x01);
    NS_CHECK(info.destination[15] == 0x02);
}

static void test_truncated_ipv6(void) {
    static const uint8_t pkt[] = {0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0x40};

    ns_ipv6_info_t info;
    size_t header_len = 0;
    ns_parse_status_t status = ns_parse_ipv6(pkt, sizeof(pkt), &info, &header_len);

    NS_CHECK(status == NS_PARSE_TRUNCATED);
}

static void test_invalid_version(void) {
    static const uint8_t pkt[40] = {0x40};

    ns_ipv6_info_t info;
    size_t header_len = 0;
    ns_parse_status_t status = ns_parse_ipv6(pkt, sizeof(pkt), &info, &header_len);

    NS_CHECK(status == NS_PARSE_MALFORMED);
}

static void test_skip_hop_by_hop_extension(void) {
    static const uint8_t ext[] = {0x06, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00};

    size_t offset = 0;
    uint8_t next_header = NS_IPV6_NEXT_HOP_BY_HOP;
    bool ok = ns_ipv6_skip_extension_headers(ext, sizeof(ext), &offset, &next_header);

    NS_CHECK(ok);
    NS_CHECK(offset == 8);
    NS_CHECK(next_header == NS_IPV6_NEXT_TCP);
}

static void test_extension_header_chain_bound(void) {
    uint8_t chain[8 * (NS_IPV6_MAX_EXTENSION_HEADERS + 1)];
    for (int i = 0; i < NS_IPV6_MAX_EXTENSION_HEADERS + 1; i++) {
        uint8_t *hdr = chain + (size_t) i * 8;
        hdr[0] = NS_IPV6_NEXT_HOP_BY_HOP;
        hdr[1] = 0;
        memset(hdr + 2, 0, 6);
    }

    size_t offset = 0;
    uint8_t next_header = NS_IPV6_NEXT_HOP_BY_HOP;
    bool ok = ns_ipv6_skip_extension_headers(chain, sizeof(chain), &offset, &next_header);

    NS_CHECK(!ok);
}

NS_TEST_MAIN_BEGIN()
NS_RUN(test_valid_ipv6);
NS_RUN(test_truncated_ipv6);
NS_RUN(test_invalid_version);
NS_RUN(test_skip_hop_by_hop_extension);
NS_RUN(test_extension_header_chain_bound);
NS_TEST_MAIN_END()
