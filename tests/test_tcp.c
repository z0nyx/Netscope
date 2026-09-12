#include "netscope/protocols/tcp.h"

#include <string.h>

#include "test_framework.h"

static void test_tcp_syn(void) {
    static const uint8_t pkt[] = {
        0xc8, 0x8e, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    ns_tcp_info_t info;
    size_t header_len = 0;
    ns_parse_status_t status = ns_parse_tcp(pkt, sizeof(pkt), &info, &header_len);

    NS_CHECK(status == NS_PARSE_OK);
    NS_CHECK(header_len == 20);
    NS_CHECK(info.source_port == 51342);
    NS_CHECK(info.destination_port == 443);
    NS_CHECK(info.sequence_number == 1);
    NS_CHECK(info.flags == NS_TCP_FLAG_SYN);

    char buf[32];
    NS_CHECK(strcmp(ns_tcp_flags_to_string(info.flags, buf, sizeof(buf)), "SYN") == 0);
}

static void test_tcp_syn_ack(void) {
    uint8_t pkt[] = {
        0xc8, 0x8e, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x01, 0x50, 0x12, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    ns_tcp_info_t info;
    size_t header_len = 0;
    ns_parse_status_t status = ns_parse_tcp(pkt, sizeof(pkt), &info, &header_len);

    NS_CHECK(status == NS_PARSE_OK);
    NS_CHECK((info.flags & NS_TCP_FLAG_SYN) && (info.flags & NS_TCP_FLAG_ACK));

    char buf[32];
    NS_CHECK(strcmp(ns_tcp_flags_to_string(info.flags, buf, sizeof(buf)), "SYN,ACK") == 0);
}

static void test_tcp_invalid_data_offset(void) {
    static const uint8_t pkt[] = {
        0xc8, 0x8e, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x40, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    ns_tcp_info_t info;
    size_t header_len = 0;
    ns_parse_status_t status = ns_parse_tcp(pkt, sizeof(pkt), &info, &header_len);

    NS_CHECK(status == NS_PARSE_MALFORMED);
}

static void test_tcp_truncated(void) {
    static const uint8_t pkt[] = {0xc8, 0x8e, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01};

    ns_tcp_info_t info;
    size_t header_len = 0;
    ns_parse_status_t status = ns_parse_tcp(pkt, sizeof(pkt), &info, &header_len);

    NS_CHECK(status == NS_PARSE_TRUNCATED);
}

static void test_tcp_options_truncated(void) {
    static const uint8_t pkt[] = {
        0xc8, 0x8e, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x60, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    ns_tcp_info_t info;
    size_t header_len = 0;
    ns_parse_status_t status = ns_parse_tcp(pkt, sizeof(pkt), &info, &header_len);

    NS_CHECK(status == NS_PARSE_TRUNCATED);
}

NS_TEST_MAIN_BEGIN()
NS_RUN(test_tcp_syn);
NS_RUN(test_tcp_syn_ack);
NS_RUN(test_tcp_invalid_data_offset);
NS_RUN(test_tcp_truncated);
NS_RUN(test_tcp_options_truncated);
NS_TEST_MAIN_END()
