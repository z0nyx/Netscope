#ifndef NETSCOPE_PROTOCOLS_UDP_H
#define NETSCOPE_PROTOCOLS_UDP_H

#include <stddef.h>
#include <stdint.h>

#include "netscope/protocols/proto_common.h"

#define NS_UDP_HEADER_LEN 8u

typedef struct {
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;
} ns_udp_info_t;

ns_parse_status_t ns_parse_udp(const uint8_t *data, size_t length, ns_udp_info_t *out);

#endif
