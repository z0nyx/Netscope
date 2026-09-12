#include "netscope/protocols/udp.h"

#include <string.h>

#include "netscope/util.h"

ns_parse_status_t ns_parse_udp(const uint8_t *data, size_t length, ns_udp_info_t *out) {
    if (!ns_bounds_check(length, 0, NS_UDP_HEADER_LEN)) {
        return NS_PARSE_TRUNCATED;
    }

    uint16_t src_port, dst_port, udp_length, checksum;
    ns_read_u16_be(data, length, 0, &src_port);
    ns_read_u16_be(data, length, 2, &dst_port);
    ns_read_u16_be(data, length, 4, &udp_length);
    ns_read_u16_be(data, length, 6, &checksum);

    /* udp_length is the sender's claim and is only checked for internal
     * consistency (it can't be smaller than the header that carries it),
     * never compared against the captured length: a capture legitimately
     * shorter than udp_length just means the snaplen cut the packet off
     * mid-payload, which is not malformed. Nothing below ever indexes past
     * `length`/captured bytes regardless of what udp_length claims. */
    if (udp_length < NS_UDP_HEADER_LEN) {
        return NS_PARSE_MALFORMED;
    }

    memset(out, 0, sizeof(*out));
    out->source_port = src_port;
    out->destination_port = dst_port;
    out->length = udp_length;
    out->checksum = checksum;
    return NS_PARSE_OK;
}
