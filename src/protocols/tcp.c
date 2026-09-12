#include "netscope/protocols/tcp.h"

#include <stdio.h>
#include <string.h>

#include "netscope/util.h"

#define NS_TCP_MIN_HEADER_LEN 20u

ns_parse_status_t ns_parse_tcp(const uint8_t *data, size_t length, ns_tcp_info_t *out,
                               size_t *header_len) {
    if (!ns_bounds_check(length, 0, NS_TCP_MIN_HEADER_LEN)) {
        return NS_PARSE_TRUNCATED;
    }

    uint16_t src_port, dst_port, window, checksum, urgent;
    uint32_t seq, ack;
    uint8_t data_offset_reserved, flags;

    ns_read_u16_be(data, length, 0, &src_port);
    ns_read_u16_be(data, length, 2, &dst_port);
    ns_read_u32_be(data, length, 4, &seq);
    ns_read_u32_be(data, length, 8, &ack);
    ns_read_u8(data, length, 12, &data_offset_reserved);
    ns_read_u8(data, length, 13, &flags);
    ns_read_u16_be(data, length, 14, &window);
    ns_read_u16_be(data, length, 16, &checksum);
    ns_read_u16_be(data, length, 18, &urgent);

    uint8_t data_offset = (uint8_t) (data_offset_reserved >> 4);
    if (data_offset < 5) {
        return NS_PARSE_MALFORMED;
    }

    size_t hdr_len = (size_t) data_offset * 4u;
    if (!ns_bounds_check(length, 0, hdr_len)) {
        return NS_PARSE_TRUNCATED;
    }

    memset(out, 0, sizeof(*out));
    out->source_port = src_port;
    out->destination_port = dst_port;
    out->sequence_number = seq;
    out->ack_number = ack;
    out->data_offset = data_offset;
    out->flags = flags;
    out->window_size = window;
    out->checksum = checksum;
    out->urgent_pointer = urgent;
    out->header_length = hdr_len;

    *header_len = hdr_len;
    return NS_PARSE_OK;
}

const char *ns_tcp_flags_to_string(uint8_t flags, char *buf, size_t buf_len) {
    static const struct {
        uint8_t bit;
        const char *name;
    } kFlags[] = {
        {NS_TCP_FLAG_SYN, "SYN"}, {NS_TCP_FLAG_ACK, "ACK"}, {NS_TCP_FLAG_FIN, "FIN"},
        {NS_TCP_FLAG_RST, "RST"}, {NS_TCP_FLAG_PSH, "PSH"}, {NS_TCP_FLAG_URG, "URG"},
        {NS_TCP_FLAG_ECE, "ECE"}, {NS_TCP_FLAG_CWR, "CWR"},
    };

    buf[0] = '\0';
    size_t pos = 0;
    bool first = true;
    for (size_t i = 0; i < sizeof(kFlags) / sizeof(kFlags[0]); i++) {
        if (!(flags & kFlags[i].bit)) {
            continue;
        }
        int written = snprintf(buf + pos, buf_len - pos, "%s%s", first ? "" : ",", kFlags[i].name);
        if (written < 0 || (size_t) written >= buf_len - pos) {
            break;
        }
        pos += (size_t) written;
        first = false;
    }
    if (pos == 0) {
        snprintf(buf, buf_len, "-");
    }
    return buf;
}
