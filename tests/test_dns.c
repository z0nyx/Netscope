#include "netscope/protocols/dns.h"

#include <string.h>

#include "test_framework.h"

static const uint8_t kQuery[] = {
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 'e',  'x',
    'a',  'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01,
};

static const uint8_t kResponseA[] = {
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 'e',  'x',  'a',
    'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01,

    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0x5d, 0xb8, 0xd8, 0x22,
};

static const uint8_t kResponseCname[] = {
    0x55, 0x66, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,

    0x03, 'w',  'w',  'w',  0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x03, 'c',
    'o',  'm',  0x00, 0x00, 0x05, 0x00, 0x01,

    0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x02, 0xc0, 0x10,
};

static void test_dns_query(void) {
    ns_dns_info_t info;
    ns_parse_status_t status = ns_parse_dns(kQuery, sizeof(kQuery), &info);

    NS_CHECK(status == NS_PARSE_OK);
    NS_CHECK(info.transaction_id == 0x1234);
    NS_CHECK(!info.is_response);
    NS_CHECK(info.question_count == 1);
    NS_CHECK(info.decoded_question_count == 1);
    NS_CHECK(strcmp(info.questions[0].name, "example.com") == 0);
    NS_CHECK(info.questions[0].type == NS_DNS_TYPE_A);
}

static void test_dns_response_a(void) {
    ns_dns_info_t info;
    ns_parse_status_t status = ns_parse_dns(kResponseA, sizeof(kResponseA), &info);

    NS_CHECK(status == NS_PARSE_OK);
    NS_CHECK(info.is_response);
    NS_CHECK(info.decoded_answer_count == 1);
    NS_CHECK(strcmp(info.answers[0].name, "example.com") == 0);
    NS_CHECK(info.answers[0].type == NS_DNS_TYPE_A);
    NS_CHECK(info.answers[0].ttl == 300);
    NS_CHECK(strcmp(info.answers[0].rdata_text, "93.184.216.34") == 0);
}

static void test_dns_compressed_cname(void) {
    ns_dns_info_t info;
    ns_parse_status_t status = ns_parse_dns(kResponseCname, sizeof(kResponseCname), &info);

    NS_CHECK(status == NS_PARSE_OK);
    NS_CHECK(strcmp(info.questions[0].name, "www.example.com") == 0);
    NS_CHECK(info.decoded_answer_count == 1);
    NS_CHECK(strcmp(info.answers[0].name, "www.example.com") == 0);
    NS_CHECK(info.answers[0].type == NS_DNS_TYPE_CNAME);
    NS_CHECK(strcmp(info.answers[0].rdata_text, "example.com") == 0);
}

static void test_dns_truncated_header(void) {
    static const uint8_t pkt[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01};

    ns_dns_info_t info;
    ns_parse_status_t status = ns_parse_dns(pkt, sizeof(pkt), &info);

    NS_CHECK(status == NS_PARSE_TRUNCATED);
}

static void test_dns_truncated_question(void) {
    static const uint8_t pkt[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    ns_dns_info_t info;
    ns_parse_status_t status = ns_parse_dns(pkt, sizeof(pkt), &info);

    NS_CHECK(status == NS_PARSE_TRUNCATED);
    NS_CHECK(info.decoded_question_count == 0);
}

static void test_dns_self_referencing_pointer(void) {
    static const uint8_t pkt[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
    };

    ns_dns_info_t info;
    ns_parse_status_t status = ns_parse_dns(pkt, sizeof(pkt), &info);

    NS_CHECK(status == NS_PARSE_MALFORMED);
}

static void test_dns_reserved_label_type(void) {
    static const uint8_t pkt[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x01, 0x00, 0x01,
    };

    ns_dns_info_t info;
    ns_parse_status_t status = ns_parse_dns(pkt, sizeof(pkt), &info);

    NS_CHECK(status == NS_PARSE_MALFORMED);
}

static void test_dns_name_too_long(void) {
    uint8_t pkt[12 + 5 * 64 + 1 + 4];
    memset(pkt, 0, sizeof(pkt));
    pkt[4] = 0x00;
    pkt[5] = 0x01;

    size_t pos = 12;
    for (int label = 0; label < 5; label++) {
        pkt[pos++] = 63;
        memset(pkt + pos, (char) ('a' + label), 63);
        pos += 63;
    }
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x01;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x01;

    ns_dns_info_t info;
    ns_parse_status_t status = ns_parse_dns(pkt, pos, &info);

    NS_CHECK(status == NS_PARSE_MALFORMED);
}

static void test_dns_type_name(void) {
    NS_CHECK(strcmp(ns_dns_type_name(NS_DNS_TYPE_AAAA, NULL, 0), "AAAA") == 0);
    char buf[16];
    NS_CHECK(strcmp(ns_dns_type_name(999, buf, sizeof(buf)), "TYPE999") == 0);
}

NS_TEST_MAIN_BEGIN()
NS_RUN(test_dns_query);
NS_RUN(test_dns_response_a);
NS_RUN(test_dns_compressed_cname);
NS_RUN(test_dns_truncated_header);
NS_RUN(test_dns_truncated_question);
NS_RUN(test_dns_self_referencing_pointer);
NS_RUN(test_dns_reserved_label_type);
NS_RUN(test_dns_name_too_long);
NS_RUN(test_dns_type_name);
NS_TEST_MAIN_END()
