#include "netscope/protocols/ipv4.h"

#include <string.h>

#include "netscope/util.h"

#define NS_IPV4_MIN_HEADER_LEN 20u

ns_parse_status_t ns_parse_ipv4(const uint8_t *data, size_t length, ns_ipv4_info_t *out,
                                size_t *header_len) {
    if (!ns_bounds_check(length, 0, NS_IPV4_MIN_HEADER_LEN)) {
        return NS_PARSE_TRUNCATED;
    }

    uint8_t version_ihl;
    ns_read_u8(data, length, 0, &version_ihl);

    uint8_t version = (uint8_t) (version_ihl >> 4);
    uint8_t ihl = (uint8_t) (version_ihl & 0x0Fu);

    if (version != 4) {
        return NS_PARSE_MALFORMED;
    }
    if (ihl < 5) {
        return NS_PARSE_MALFORMED;
    }

    size_t hdr_len = (size_t) ihl * 4u;
    if (!ns_bounds_check(length, 0, hdr_len)) {
        return NS_PARSE_TRUNCATED;
    }

    uint8_t dscp_ecn;
    uint16_t total_length, identification, flags_frag, checksum;
    uint8_t ttl, protocol;
    uint32_t src, dst;

    ns_read_u8(data, length, 1, &dscp_ecn);
    ns_read_u16_be(data, length, 2, &total_length);
    ns_read_u16_be(data, length, 4, &identification);
    ns_read_u16_be(data, length, 6, &flags_frag);
    ns_read_u8(data, length, 8, &ttl);
    ns_read_u8(data, length, 9, &protocol);
    ns_read_u16_be(data, length, 10, &checksum);
    memcpy(&src, data + 12, 4);
    memcpy(&dst, data + 16, 4);

    /* total_length must at least cover the header just validated above --
     * that's an internal inconsistency, not a capture artifact. It is not
     * compared against `length` (the captured bytes): total_length can
     * legitimately exceed what was captured when snaplen truncated the
     * packet, which is not malformed. Downstream code always bounds itself
     * against the captured length, never against total_length. */
    if (total_length < hdr_len) {
        return NS_PARSE_MALFORMED;
    }

    memset(out, 0, sizeof(*out));
    out->version = version;
    out->ihl = ihl;
    out->dscp = (uint8_t) (dscp_ecn >> 2);
    out->ecn = (uint8_t) (dscp_ecn & 0x03u);
    out->total_length = total_length;
    out->identification = identification;
    out->flag_df = (flags_frag & 0x4000u) != 0;
    out->flag_mf = (flags_frag & 0x2000u) != 0;
    out->fragment_offset = (uint16_t) (flags_frag & 0x1FFFu);
    out->ttl = ttl;
    out->protocol = protocol;
    out->header_checksum = checksum;
    out->source = src;
    out->destination = dst;
    out->header_length = hdr_len;
    out->is_fragment = out->flag_mf || out->fragment_offset != 0;
    out->is_initial_fragment = out->is_fragment && out->fragment_offset == 0;

    *header_len = hdr_len;
    return NS_PARSE_OK;
}
