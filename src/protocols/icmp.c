#include "netscope/protocols/icmp.h"

#include <string.h>

#include "netscope/util.h"

#define NS_ICMP_HEADER_LEN 8u

ns_parse_status_t ns_parse_icmp(const uint8_t *data, size_t length, ns_icmp_info_t *out) {
    if (!ns_bounds_check(length, 0, 4)) {
        return NS_PARSE_TRUNCATED;
    }

    uint8_t type, code;
    uint16_t checksum;
    ns_read_u8(data, length, 0, &type);
    ns_read_u8(data, length, 1, &code);
    ns_read_u16_be(data, length, 2, &checksum);

    memset(out, 0, sizeof(*out));
    out->type = type;
    out->code = code;
    out->checksum = checksum;

    if (type == NS_ICMP_TYPE_ECHO_REQUEST || type == NS_ICMP_TYPE_ECHO_REPLY) {
        if (!ns_bounds_check(length, 0, NS_ICMP_HEADER_LEN)) {
            return NS_PARSE_TRUNCATED;
        }
        uint16_t id, seq;
        ns_read_u16_be(data, length, 4, &id);
        ns_read_u16_be(data, length, 6, &seq);
        out->identifier = id;
        out->sequence = seq;
    }

    return NS_PARSE_OK;
}

const char *ns_icmp_type_name(uint8_t type) {
    switch (type) {
        case NS_ICMP_TYPE_ECHO_REPLY:
            return "Echo Reply";
        case NS_ICMP_TYPE_DEST_UNREACHABLE:
            return "Destination Unreachable";
        case NS_ICMP_TYPE_REDIRECT:
            return "Redirect";
        case NS_ICMP_TYPE_ECHO_REQUEST:
            return "Echo Request";
        case NS_ICMP_TYPE_TIME_EXCEEDED:
            return "Time Exceeded";
        default:
            return "Unknown";
    }
}
