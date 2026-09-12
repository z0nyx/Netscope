#ifndef NETSCOPE_PROTOCOLS_ETHERNET_H
#define NETSCOPE_PROTOCOLS_ETHERNET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "netscope/protocols/proto_common.h"

#define NS_ETH_ADDR_LEN 6u
#define NS_ETH_HEADER_LEN 14u
#define NS_VLAN_TAG_LEN 4u

#define NS_ETHERTYPE_IPV4 0x0800u
#define NS_ETHERTYPE_ARP 0x0806u
#define NS_ETHERTYPE_IPV6 0x86DDu
#define NS_ETHERTYPE_VLAN 0x8100u

typedef struct {
    uint8_t destination[NS_ETH_ADDR_LEN];
    uint8_t source[NS_ETH_ADDR_LEN];
    uint16_t ethertype;
    bool has_vlan;
    uint16_t vlan_id;
} ns_eth_info_t;

ns_parse_status_t ns_parse_ethernet(const uint8_t *data, size_t length, ns_eth_info_t *out,
                                    size_t *header_len);

#endif
