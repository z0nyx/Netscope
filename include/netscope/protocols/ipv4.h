#ifndef NETSCOPE_PROTOCOLS_IPV4_H
#define NETSCOPE_PROTOCOLS_IPV4_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "netscope/protocols/proto_common.h"

typedef struct {
    uint8_t version;
    uint8_t ihl;
    uint8_t dscp;
    uint8_t ecn;
    uint16_t total_length;
    uint16_t identification;
    bool flag_df;
    bool flag_mf;
    uint16_t fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t source;
    uint32_t destination;

    size_t header_length;
    bool is_fragment;
    bool is_initial_fragment;
} ns_ipv4_info_t;

ns_parse_status_t ns_parse_ipv4(const uint8_t *data, size_t length, ns_ipv4_info_t *out,
                                size_t *header_len);

#endif
