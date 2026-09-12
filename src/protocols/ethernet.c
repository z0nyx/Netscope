#include "netscope/protocols/ethernet.h"

#include <string.h>

#include "netscope/util.h"

ns_parse_status_t ns_parse_ethernet(const uint8_t *data, size_t length, ns_eth_info_t *out,
                                    size_t *header_len) {
    if (!ns_bounds_check(length, 0, NS_ETH_HEADER_LEN)) {
        return NS_PARSE_TRUNCATED;
    }

    memset(out, 0, sizeof(*out));
    memcpy(out->destination, data, NS_ETH_ADDR_LEN);
    memcpy(out->source, data + NS_ETH_ADDR_LEN, NS_ETH_ADDR_LEN);

    uint16_t ethertype;
    if (!ns_read_u16_be(data, length, 2 * NS_ETH_ADDR_LEN, &ethertype)) {
        return NS_PARSE_TRUNCATED;
    }

    size_t consumed = NS_ETH_HEADER_LEN;

    if (ethertype == NS_ETHERTYPE_VLAN) {
        if (!ns_bounds_check(length, 0, NS_ETH_HEADER_LEN + NS_VLAN_TAG_LEN)) {
            return NS_PARSE_TRUNCATED;
        }

        uint16_t vlan_field;
        uint16_t inner_type;
        ns_read_u16_be(data, length, 2 * NS_ETH_ADDR_LEN + 2, &vlan_field);
        ns_read_u16_be(data, length, 2 * NS_ETH_ADDR_LEN + 4, &inner_type);

        out->has_vlan = true;
        out->vlan_id = (uint16_t) (vlan_field & 0x0FFFu);
        ethertype = inner_type;
        consumed = NS_ETH_HEADER_LEN + NS_VLAN_TAG_LEN;
    }

    out->ethertype = ethertype;
    *header_len = consumed;
    return NS_PARSE_OK;
}
