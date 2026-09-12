#include "netscope/protocols/arp.h"

#include <string.h>

#include "netscope/util.h"

#define NS_ARP_HTYPE_ETHERNET 1u
#define NS_ARP_PTYPE_IPV4 0x0800u
#define NS_ARP_HEADER_LEN 8u

ns_parse_status_t ns_parse_arp(const uint8_t *data, size_t length, ns_arp_info_t *out) {
    if (!ns_bounds_check(length, 0, NS_ARP_HEADER_LEN)) {
        return NS_PARSE_TRUNCATED;
    }

    uint16_t htype, ptype, operation;
    uint8_t hlen, plen;
    ns_read_u16_be(data, length, 0, &htype);
    ns_read_u16_be(data, length, 2, &ptype);
    ns_read_u8(data, length, 4, &hlen);
    ns_read_u8(data, length, 5, &plen);
    ns_read_u16_be(data, length, 6, &operation);

    /* Only the common Ethernet/IPv4 case is decoded; other hardware/protocol
     * address sizes are reported as unsupported rather than guessed at. */
    if (htype != NS_ARP_HTYPE_ETHERNET || ptype != NS_ARP_PTYPE_IPV4 || hlen != NS_ETH_ADDR_LEN ||
        plen != 4) {
        return NS_PARSE_UNSUPPORTED;
    }

    size_t body_len = (size_t) (2u * hlen + 2u * plen);
    if (!ns_bounds_check(length, NS_ARP_HEADER_LEN, body_len)) {
        return NS_PARSE_TRUNCATED;
    }

    memset(out, 0, sizeof(*out));
    out->operation = operation;

    size_t off = NS_ARP_HEADER_LEN;
    memcpy(out->sender_mac, data + off, NS_ETH_ADDR_LEN);
    off += NS_ETH_ADDR_LEN;
    memcpy(&out->sender_ip, data + off, 4);
    off += 4;
    memcpy(out->target_mac, data + off, NS_ETH_ADDR_LEN);
    off += NS_ETH_ADDR_LEN;
    memcpy(&out->target_ip, data + off, 4);

    return NS_PARSE_OK;
}
