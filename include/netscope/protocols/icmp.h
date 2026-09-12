#ifndef NETSCOPE_PROTOCOLS_ICMP_H
#define NETSCOPE_PROTOCOLS_ICMP_H

#include <stddef.h>
#include <stdint.h>

#include "netscope/protocols/proto_common.h"

#define NS_ICMP_TYPE_ECHO_REPLY 0u
#define NS_ICMP_TYPE_DEST_UNREACHABLE 3u
#define NS_ICMP_TYPE_REDIRECT 5u
#define NS_ICMP_TYPE_ECHO_REQUEST 8u
#define NS_ICMP_TYPE_TIME_EXCEEDED 11u

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;

    uint16_t identifier;
    uint16_t sequence;
} ns_icmp_info_t;

ns_parse_status_t ns_parse_icmp(const uint8_t *data, size_t length, ns_icmp_info_t *out);

const char *ns_icmp_type_name(uint8_t type);

#endif
