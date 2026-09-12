#ifndef NETSCOPE_PROTOCOLS_TCP_H
#define NETSCOPE_PROTOCOLS_TCP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "netscope/protocols/proto_common.h"

#define NS_TCP_FLAG_FIN 0x01u
#define NS_TCP_FLAG_SYN 0x02u
#define NS_TCP_FLAG_RST 0x04u
#define NS_TCP_FLAG_PSH 0x08u
#define NS_TCP_FLAG_ACK 0x10u
#define NS_TCP_FLAG_URG 0x20u
#define NS_TCP_FLAG_ECE 0x40u
#define NS_TCP_FLAG_CWR 0x80u

typedef struct {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence_number;
    uint32_t ack_number;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;

    size_t header_length;
} ns_tcp_info_t;

ns_parse_status_t ns_parse_tcp(const uint8_t *data, size_t length, ns_tcp_info_t *out,
                               size_t *header_len);

const char *ns_tcp_flags_to_string(uint8_t flags, char *buf, size_t buf_len);

#endif
