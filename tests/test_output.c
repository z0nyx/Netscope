#include "netscope/output.h"

#include <string.h>

#include "netscope/packet.h"
#include "test_framework.h"

static ns_timestamp_t kTs = {1700000000, 381000};

static const uint8_t kTcpSyn[] = {
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x08, 0x00,
    0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8,
    0x01, 0x0c, 0x8e, 0xfa, 0x4a, 0x0e, 0xc8, 0x8e, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t kDnsQuery[] = {
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x08, 0x00, 0x45,
    0x00, 0x00, 0x39, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x0c,
    0x08, 0x08, 0x08, 0x08, 0xd0, 0x5d, 0x00, 0x35, 0x00, 0x25, 0x00, 0x00, 0x12, 0x34, 0x01,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 'e',  'x',  'a',  'm',  'p',
    'l',  'e',  0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01,
};

/* Ethernet + IPv4 + UDP + DNS query whose single-byte label is 0xFF: DNS
 * names are arbitrary bytes, not guaranteed ASCII/UTF-8, so JSON output
 * must escape it rather than emit an invalid raw byte. */
static const uint8_t kDnsQueryNonAscii[] = {
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x08,
    0x00, 0x45, 0x00, 0x00, 0x33, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00,
    0xc0, 0xa8, 0x01, 0x0c, 0x08, 0x08, 0x08, 0x08, 0x30, 0x39, 0x00, 0x35, 0x00,
    0x1f, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0xff, 0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01,
};

static char g_buf[4096];

static void run_output(const uint8_t *data, size_t len, const ns_output_options_t *opts) {
    ns_packet_t pkt;
    ns_packet_parse(data, len, len, kTs, 1, NS_LINK_ETHERNET, &pkt);

    FILE *f = tmpfile();
    NS_CHECK(f != NULL);
    if (f == NULL) {
        return;
    }

    ns_output_packet(&pkt, opts, f);

    long size = ftell(f);
    rewind(f);
    size_t n =
        fread(g_buf, 1, (size_t) size < sizeof(g_buf) - 1 ? (size_t) size : sizeof(g_buf) - 1, f);
    g_buf[n] = '\0';
    fclose(f);
}

static void test_text_tcp_line(void) {
    ns_output_options_t opts = {.format = NS_FORMAT_TEXT};
    run_output(kTcpSyn, sizeof(kTcpSyn), &opts);

    NS_CHECK(strstr(g_buf, "TCP") != NULL);
    NS_CHECK(strstr(g_buf, "192.168.1.12:51342") != NULL);
    NS_CHECK(strstr(g_buf, "142.250.74.14:443") != NULL);
    NS_CHECK(strstr(g_buf, "[SYN]") != NULL);
    NS_CHECK(strstr(g_buf, "54 B") != NULL);
}

static void test_text_no_color_has_no_escapes(void) {
    ns_output_options_t opts = {.format = NS_FORMAT_TEXT, .color = false};
    run_output(kTcpSyn, sizeof(kTcpSyn), &opts);
    NS_CHECK(strchr(g_buf, '\x1b') == NULL);
}

static void test_text_color_has_escapes(void) {
    ns_output_options_t opts = {.format = NS_FORMAT_TEXT, .color = true};
    run_output(kTcpSyn, sizeof(kTcpSyn), &opts);
    NS_CHECK(strchr(g_buf, '\x1b') != NULL);
}

static void test_text_quiet_suppresses_output(void) {
    ns_output_options_t opts = {.format = NS_FORMAT_TEXT, .quiet = true};
    run_output(kTcpSyn, sizeof(kTcpSyn), &opts);
    NS_CHECK(g_buf[0] == '\0');
}

static void test_text_dns_query_line(void) {
    ns_output_options_t opts = {.format = NS_FORMAT_TEXT};
    run_output(kDnsQuery, sizeof(kDnsQuery), &opts);

    NS_CHECK(strstr(g_buf, "UDP") != NULL);
    NS_CHECK(strstr(g_buf, "DNS") != NULL);
    NS_CHECK(strstr(g_buf, "Query: example.com A") != NULL);
}

static void test_json_line_fields(void) {
    ns_output_options_t opts = {.format = NS_FORMAT_JSON};
    run_output(kTcpSyn, sizeof(kTcpSyn), &opts);

    NS_CHECK(strstr(g_buf, "\"protocol\":\"TCP\"") != NULL);
    NS_CHECK(strstr(g_buf, "\"ip\":\"192.168.1.12\"") != NULL);
    NS_CHECK(strstr(g_buf, "\"port\":51342") != NULL);
    NS_CHECK(strstr(g_buf, "\"port\":443") != NULL);
    NS_CHECK(strstr(g_buf, "\"flags\":[\"SYN\"]") != NULL);
    NS_CHECK(strstr(g_buf, "\"malformed\":false") != NULL);

    NS_CHECK(strchr(g_buf, '\n') == g_buf + strlen(g_buf) - 1);
}

static void test_json_dns_fields(void) {
    ns_output_options_t opts = {.format = NS_FORMAT_JSON};
    run_output(kDnsQuery, sizeof(kDnsQuery), &opts);

    NS_CHECK(strstr(g_buf, "\"dns\":{\"question\":\"example.com\",\"type\":\"A\"}") != NULL);
}

static bool is_seven_bit_clean(const char *s) {
    for (const unsigned char *p = (const unsigned char *) s; *p != '\0'; p++) {
        if (*p >= 0x80) {
            return false;
        }
    }
    return true;
}

static void test_json_escapes_non_ascii_dns_bytes(void) {
    ns_output_options_t opts = {.format = NS_FORMAT_JSON};
    run_output(kDnsQueryNonAscii, sizeof(kDnsQueryNonAscii), &opts);

    NS_CHECK(strstr(g_buf, "\\u00ff") != NULL);
    NS_CHECK(is_seven_bit_clean(g_buf));
}

static void test_malformed_packet_reported(void) {
    static const uint8_t garbage[] = {0x01, 0x02, 0x03};
    ns_output_options_t opts = {.format = NS_FORMAT_TEXT};
    run_output(garbage, sizeof(garbage), &opts);

    NS_CHECK(strstr(g_buf, "MALFORMED") != NULL);
}

NS_TEST_MAIN_BEGIN()
NS_RUN(test_text_tcp_line);
NS_RUN(test_text_no_color_has_no_escapes);
NS_RUN(test_text_color_has_escapes);
NS_RUN(test_text_quiet_suppresses_output);
NS_RUN(test_text_dns_query_line);
NS_RUN(test_json_line_fields);
NS_RUN(test_json_dns_fields);
NS_RUN(test_json_escapes_non_ascii_dns_bytes);
NS_RUN(test_malformed_packet_reported);
NS_TEST_MAIN_END()
