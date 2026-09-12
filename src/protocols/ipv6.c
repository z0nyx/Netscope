#include "netscope/protocols/ipv6.h"

#include <string.h>

#include "netscope/util.h"

ns_parse_status_t ns_parse_ipv6(const uint8_t *data, size_t length, ns_ipv6_info_t *out,
                                size_t *header_len) {
    if (!ns_bounds_check(length, 0, NS_IPV6_HEADER_LEN)) {
        return NS_PARSE_TRUNCATED;
    }

    uint32_t first_word;
    ns_read_u32_be(data, length, 0, &first_word);

    uint8_t version = (uint8_t) (first_word >> 28);
    if (version != 6) {
        return NS_PARSE_MALFORMED;
    }

    uint16_t payload_length;
    uint8_t next_header, hop_limit;
    ns_read_u16_be(data, length, 4, &payload_length);
    ns_read_u8(data, length, 6, &next_header);
    ns_read_u8(data, length, 7, &hop_limit);

    memset(out, 0, sizeof(*out));
    out->version = version;
    out->traffic_class = (uint8_t) ((first_word >> 20) & 0xFFu);
    out->flow_label = first_word & 0x000FFFFFu;
    out->payload_length = payload_length;
    out->next_header = next_header;
    out->hop_limit = hop_limit;
    memcpy(out->source, data + 8, NS_IPV6_ADDR_LEN);
    memcpy(out->destination, data + 24, NS_IPV6_ADDR_LEN);
    out->header_length = NS_IPV6_HEADER_LEN;

    *header_len = NS_IPV6_HEADER_LEN;
    return NS_PARSE_OK;
}

/*
 * Walks Hop-by-Hop, Routing, Destination Options, and Fragment extension
 * headers, advancing offset and next_header past each one until an
 * upper-layer protocol (or NS_IPV6_NEXT_NONE) is reached. Bounded by
 * NS_IPV6_MAX_EXTENSION_HEADERS so a header claiming to chain into another
 * of the same kind indefinitely cannot loop forever.
 */
bool ns_ipv6_skip_extension_headers(const uint8_t *data, size_t length, size_t *offset,
                                    uint8_t *next_header) {
    for (int i = 0; i < NS_IPV6_MAX_EXTENSION_HEADERS; i++) {
        switch (*next_header) {
            case NS_IPV6_NEXT_HOP_BY_HOP:
            case NS_IPV6_NEXT_ROUTING:
            case NS_IPV6_NEXT_DEST_OPTS: {
                if (!ns_bounds_check(length, *offset, 2)) {
                    return false;
                }
                uint8_t next, ext_len_units;
                ns_read_u8(data, length, *offset, &next);
                ns_read_u8(data, length, *offset + 1, &ext_len_units);

                size_t ext_len = ((size_t) ext_len_units + 1u) * 8u;
                if (!ns_bounds_check(length, *offset, ext_len)) {
                    return false;
                }
                *offset += ext_len;
                *next_header = next;
                continue;
            }
            case NS_IPV6_NEXT_FRAGMENT: {
                /* Fixed 8-byte header regardless of any length field. */
                uint8_t next;
                if (!ns_read_u8(data, length, *offset, &next) ||
                    !ns_bounds_check(length, *offset, 8)) {
                    return false;
                }
                *offset += 8;
                *next_header = next;
                continue;
            }
            default:
                return true;
        }
    }

    /* Exhausted the jump budget without reaching an upper-layer protocol:
     * treat as malformed rather than parse an unbounded chain. */
    return false;
}
