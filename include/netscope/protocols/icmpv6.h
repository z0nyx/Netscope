#ifndef NETSCOPE_PROTOCOLS_ICMPV6_H
#define NETSCOPE_PROTOCOLS_ICMPV6_H

#include <stddef.h>
#include <stdint.h>

#include "netscope/protocols/proto_common.h"

#define NS_ICMPV6_TYPE_DEST_UNREACHABLE 1u
#define NS_ICMPV6_TYPE_PACKET_TOO_BIG 2u
#define NS_ICMPV6_TYPE_TIME_EXCEEDED 3u
#define NS_ICMPV6_TYPE_ECHO_REQUEST 128u
#define NS_ICMPV6_TYPE_ECHO_REPLY 129u
#define NS_ICMPV6_TYPE_NEIGHBOR_SOLICITATION 135u
#define NS_ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT 136u

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;

    uint16_t identifier;
    uint16_t sequence;
} ns_icmpv6_info_t;

ns_parse_status_t ns_parse_icmpv6(const uint8_t *data, size_t length, ns_icmpv6_info_t *out);

const char *ns_icmpv6_type_name(uint8_t type);

#endif
