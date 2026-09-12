#ifndef NETSCOPE_PROTOCOLS_ARP_H
#define NETSCOPE_PROTOCOLS_ARP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "netscope/protocols/ethernet.h"
#include "netscope/protocols/proto_common.h"

#define NS_ARP_OP_REQUEST 1u
#define NS_ARP_OP_REPLY 2u

typedef struct {
    uint16_t operation;
    uint8_t sender_mac[NS_ETH_ADDR_LEN];
    uint32_t sender_ip;
    uint8_t target_mac[NS_ETH_ADDR_LEN];
    uint32_t target_ip;
} ns_arp_info_t;

ns_parse_status_t ns_parse_arp(const uint8_t *data, size_t length, ns_arp_info_t *out);

#endif
