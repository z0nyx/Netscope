#ifndef NETSCOPE_PROTOCOLS_IPV6_H
#define NETSCOPE_PROTOCOLS_IPV6_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "netscope/protocols/proto_common.h"

#define NS_IPV6_ADDR_LEN 16u
#define NS_IPV6_HEADER_LEN 40u

#define NS_IPV6_NEXT_HOP_BY_HOP 0u
#define NS_IPV6_NEXT_TCP 6u
#define NS_IPV6_NEXT_UDP 17u
#define NS_IPV6_NEXT_ROUTING 43u
#define NS_IPV6_NEXT_FRAGMENT 44u
#define NS_IPV6_NEXT_ICMPV6 58u
#define NS_IPV6_NEXT_NONE 59u
#define NS_IPV6_NEXT_DEST_OPTS 60u

typedef struct {
    uint8_t version;
    uint8_t traffic_class;
    uint32_t flow_label;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t source[NS_IPV6_ADDR_LEN];
    uint8_t destination[NS_IPV6_ADDR_LEN];

    size_t header_length;
} ns_ipv6_info_t;

ns_parse_status_t ns_parse_ipv6(const uint8_t *data, size_t length, ns_ipv6_info_t *out,
                                size_t *header_len);

#define NS_IPV6_MAX_EXTENSION_HEADERS 8

bool ns_ipv6_skip_extension_headers(const uint8_t *data, size_t length, size_t *offset,
                                    uint8_t *next_header);

#endif
