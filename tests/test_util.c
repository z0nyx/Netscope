#include "netscope/util.h"

#include <string.h>

#include "test_framework.h"

static void test_bounds_check(void) {
    NS_CHECK(ns_bounds_check(10, 0, 10));
    NS_CHECK(ns_bounds_check(10, 5, 5));
    NS_CHECK(!ns_bounds_check(10, 5, 6));
    NS_CHECK(!ns_bounds_check(10, 11, 0));
    NS_CHECK(ns_bounds_check(10, 10, 0));
}

static void test_read_helpers(void) {
    static const uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    uint8_t u8;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;

    NS_CHECK(ns_read_u8(data, sizeof(data), 0, &u8) && u8 == 0x01);
    NS_CHECK(ns_read_u16_be(data, sizeof(data), 0, &u16) && u16 == 0x0102);
    NS_CHECK(ns_read_u32_be(data, sizeof(data), 0, &u32) && u32 == 0x01020304u);
    NS_CHECK(ns_read_u64_be(data, sizeof(data), 0, &u64) && u64 == 0x0102030405060708ull);

    NS_CHECK(!ns_read_u16_be(data, sizeof(data), 7, &u16));
    NS_CHECK(!ns_read_u32_be(data, sizeof(data), 6, &u32));
    NS_CHECK(!ns_read_u64_be(data, sizeof(data), 1, &u64));
}

static void test_format_mac(void) {
    static const uint8_t mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    char buf[18];
    ns_format_mac(mac, buf, sizeof(buf));
    NS_CHECK(strcmp(buf, "aa:bb:cc:dd:ee:ff") == 0);
}

static void test_format_ipv4(void) {
    uint8_t bytes[4] = {192, 168, 1, 12};
    uint32_t addr;
    memcpy(&addr, bytes, 4);

    char buf[16];
    ns_format_ipv4(addr, buf, sizeof(buf));
    NS_CHECK(strcmp(buf, "192.168.1.12") == 0);
}

static void test_format_ipv6(void) {
    uint8_t full[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
    char buf[46];
    ns_format_ipv6(full, buf, sizeof(buf));
    NS_CHECK(strcmp(buf, "fe80::1") == 0);

    uint8_t loopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    ns_format_ipv6(loopback, buf, sizeof(buf));
    NS_CHECK(strcmp(buf, "::1") == 0);

    uint8_t unspecified[16] = {0};
    ns_format_ipv6(unspecified, buf, sizeof(buf));
    NS_CHECK(strcmp(buf, "::") == 0);
}

static void test_format_bytes(void) {
    char buf[32];
    ns_format_bytes(512, buf, sizeof(buf));
    NS_CHECK(strcmp(buf, "512 B") == 0);

    ns_format_bytes(2048, buf, sizeof(buf));
    NS_CHECK(strcmp(buf, "2.00 KB") == 0);

    ns_format_bytes(5ull * 1024 * 1024, buf, sizeof(buf));
    NS_CHECK(strcmp(buf, "5.00 MB") == 0);
}

static bool collect_hex(void *ctx, const char *chunk) {
    char *out = (char *) ctx;
    strcat(out, chunk);
    return true;
}

static void test_hex_dump(void) {
    static const uint8_t data[] = {0x47, 0x45, 0x54, 0x20, 0x2f};
    char out[256] = {0};
    bool ok = ns_hex_dump(data, sizeof(data), collect_hex, out);

    NS_CHECK(ok);
    NS_CHECK(strstr(out, "0000") != NULL);
    NS_CHECK(strstr(out, "47 45 54 20 2f") != NULL);
    NS_CHECK(strstr(out, "GET /") != NULL);
}

static void test_hex_dump_empty_input(void) {
    char out[16] = {0};
    bool ok = ns_hex_dump(NULL, 0, collect_hex, out);
    NS_CHECK(ok);
    NS_CHECK(out[0] == '\0');
}

static void test_hex_dump_large_buffer(void) {
    /* Exercises multiple full 16-byte rows plus a partial last row, and an
     * offset past 4 hex digits (0x100 = 256), with every byte value
     * present so both the printable and non-printable ('.') ASCII paths
     * run. Regression coverage for the snprintf-return-value clamping in
     * ns_hex_dump/append_line (see util.c). */
    static uint8_t data[300];
    for (size_t i = 0; i < sizeof(data); i++) {
        data[i] = (uint8_t) i;
    }

    static char out[300 * 5];
    out[0] = '\0';
    bool ok = ns_hex_dump(data, sizeof(data), collect_hex, out);

    NS_CHECK(ok);
    NS_CHECK(strstr(out, "0100  ") != NULL);
    size_t newline_count = 0;
    for (const char *p = out; *p != '\0'; p++) {
        if (*p == '\n') {
            newline_count++;
        }
    }
    NS_CHECK(newline_count == (sizeof(data) + 15) / 16);
}

NS_TEST_MAIN_BEGIN()
NS_RUN(test_bounds_check);
NS_RUN(test_read_helpers);
NS_RUN(test_format_mac);
NS_RUN(test_format_ipv4);
NS_RUN(test_format_ipv6);
NS_RUN(test_format_bytes);
NS_RUN(test_hex_dump);
NS_RUN(test_hex_dump_empty_input);
NS_RUN(test_hex_dump_large_buffer);
NS_TEST_MAIN_END()
