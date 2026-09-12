#include "netscope/packet.h"

#include <string.h>

static void ns_packet_parse_transport(ns_packet_t *out, const uint8_t *data, size_t length,
                                      size_t offset, uint8_t proto);

static void ns_packet_mark_malformed(ns_packet_t *out, const char *reason) {
    out->malformed = true;
    out->malformed_reason = reason;
}

static void ns_packet_set_payload(ns_packet_t *out, const uint8_t *data, size_t length,
                                  size_t offset) {
    if (offset > length) {
        out->payload = NULL;
        out->payload_length = 0;
        return;
    }
    out->payload = data + offset;
    out->payload_length = length - offset;
}

static void ns_packet_parse_dns_if_applicable(ns_packet_t *out, const uint8_t *data, size_t length,
                                              size_t offset, uint16_t src_port, uint16_t dst_port) {
    if (src_port != 53 && dst_port != 53) {
        return;
    }
    if (offset > length) {
        return;
    }
    ns_parse_status_t status = ns_parse_dns(data + offset, length - offset, &out->dns);
    if (status == NS_PARSE_OK) {
        out->has_dns = true;
    }
    /* A malformed/truncated DNS payload does not retroactively invalidate
     * the UDP/TCP header already decoded above; DNS just stays absent. */
}

static void ns_packet_parse_ipv4(ns_packet_t *out, const uint8_t *data, size_t length,
                                 size_t offset) {
    size_t header_len;
    ns_parse_status_t status =
        ns_parse_ipv4(data + offset, length - offset, &out->net.ipv4, &header_len);

    if (status == NS_PARSE_TRUNCATED) {
        ns_packet_mark_malformed(out, "IPv4 header truncated");
        return;
    }
    if (status != NS_PARSE_OK) {
        ns_packet_mark_malformed(out, "IPv4 header inconsistent");
        return;
    }

    out->network_proto = NS_PROTO_IPV4;
    size_t transport_offset = offset + header_len;
    ns_packet_set_payload(out, data, length, transport_offset);

    if (out->net.ipv4.is_fragment && !out->net.ipv4.is_initial_fragment) {
        /* Only the initial fragment carries a transport header; parsing one
         * out of a later fragment would misread arbitrary payload bytes as
         * ports/flags. */
        return;
    }

    ns_packet_parse_transport(out, data, length, transport_offset, out->net.ipv4.protocol);
}

static void ns_packet_parse_ipv6(ns_packet_t *out, const uint8_t *data, size_t length,
                                 size_t offset) {
    size_t header_len;
    ns_parse_status_t status =
        ns_parse_ipv6(data + offset, length - offset, &out->net.ipv6, &header_len);

    if (status == NS_PARSE_TRUNCATED) {
        ns_packet_mark_malformed(out, "IPv6 header truncated");
        return;
    }
    if (status != NS_PARSE_OK) {
        ns_packet_mark_malformed(out, "IPv6 header inconsistent");
        return;
    }

    out->network_proto = NS_PROTO_IPV6;

    size_t ext_offset = offset + header_len;
    uint8_t next_header = out->net.ipv6.next_header;
    if (!ns_ipv6_skip_extension_headers(data, length, &ext_offset, &next_header)) {
        ns_packet_mark_malformed(out, "IPv6 extension header chain invalid");
        ns_packet_set_payload(out, data, length, ext_offset);
        return;
    }

    ns_packet_set_payload(out, data, length, ext_offset);
    ns_packet_parse_transport(out, data, length, ext_offset, next_header);
}

static void ns_packet_parse_arp(ns_packet_t *out, const uint8_t *data, size_t length,
                                size_t offset) {
    ns_parse_status_t status = ns_parse_arp(data + offset, length - offset, &out->net.arp);
    if (status == NS_PARSE_OK) {
        out->network_proto = NS_PROTO_ARP;
    } else if (status == NS_PARSE_TRUNCATED) {
        ns_packet_mark_malformed(out, "ARP packet truncated");
    }

    ns_packet_set_payload(out, data, length, offset);
}

#define NS_IP_PROTO_ICMP 1u
#define NS_IP_PROTO_TCP 6u
#define NS_IP_PROTO_UDP 17u
#define NS_IP_PROTO_ICMPV6 58u

static void ns_packet_parse_transport(ns_packet_t *out, const uint8_t *data, size_t length,
                                      size_t offset, uint8_t proto) {
    switch (proto) {
        case NS_IP_PROTO_TCP: {
            size_t header_len;
            ns_parse_status_t status =
                ns_parse_tcp(data + offset, length - offset, &out->transport.tcp, &header_len);
            if (status == NS_PARSE_OK) {
                out->transport_proto = NS_PROTO_TCP;
                ns_packet_set_payload(out, data, length, offset + header_len);
                ns_packet_parse_dns_if_applicable(out, data, length, offset + header_len,
                                                  out->transport.tcp.source_port,
                                                  out->transport.tcp.destination_port);
            } else if (status == NS_PARSE_TRUNCATED) {
                ns_packet_mark_malformed(out, "TCP header truncated");
            } else {
                ns_packet_mark_malformed(out, "TCP header inconsistent");
            }
            break;
        }
        case NS_IP_PROTO_UDP: {
            ns_parse_status_t status =
                ns_parse_udp(data + offset, length - offset, &out->transport.udp);
            if (status == NS_PARSE_OK) {
                out->transport_proto = NS_PROTO_UDP;
                size_t app_offset = offset + 8;
                ns_packet_set_payload(out, data, length, app_offset);
                ns_packet_parse_dns_if_applicable(out, data, length, app_offset,
                                                  out->transport.udp.source_port,
                                                  out->transport.udp.destination_port);
            } else if (status == NS_PARSE_TRUNCATED) {
                ns_packet_mark_malformed(out, "UDP header truncated");
            } else {
                ns_packet_mark_malformed(out, "UDP header inconsistent");
            }
            break;
        }
        case NS_IP_PROTO_ICMP: {
            ns_parse_status_t status =
                ns_parse_icmp(data + offset, length - offset, &out->transport.icmp);
            if (status == NS_PARSE_OK) {
                out->transport_proto = NS_PROTO_ICMP;
            } else {
                ns_packet_mark_malformed(out, "ICMP header truncated");
            }
            break;
        }
        case NS_IP_PROTO_ICMPV6: {
            ns_parse_status_t status =
                ns_parse_icmpv6(data + offset, length - offset, &out->transport.icmpv6);
            if (status == NS_PARSE_OK) {
                out->transport_proto = NS_PROTO_ICMPV6;
            } else {
                ns_packet_mark_malformed(out, "ICMPv6 header truncated");
            }
            break;
        }
        default:
            /* Unhandled IP protocol (e.g. GRE, ESP): leave transport_proto
             * at NS_PROTO_UNKNOWN. Not malformed, just out of scope. */
            break;
    }
}

void ns_packet_parse(const uint8_t *data, size_t captured_length, size_t original_length,
                     ns_timestamp_t timestamp, uint64_t number, ns_link_type_t link_type,
                     ns_packet_t *out) {
    memset(out, 0, sizeof(*out));
    out->number = number;
    out->timestamp = timestamp;
    out->captured_length = captured_length;
    out->original_length = original_length;
    out->raw_data = data;
    out->link_type = link_type;
    out->payload = data;
    out->payload_length = captured_length;

    if (link_type != NS_LINK_ETHERNET) {
        /* Unsupported datalink types are rejected earlier, at the capture
         * layer, so this packet simply carries no decoded layers. */
        return;
    }

    size_t offset;
    ns_parse_status_t status = ns_parse_ethernet(data, captured_length, &out->eth, &offset);
    if (status != NS_PARSE_OK) {
        ns_packet_mark_malformed(out, "Ethernet header truncated");
        return;
    }
    out->has_eth = true;
    ns_packet_set_payload(out, data, captured_length, offset);

    switch (out->eth.ethertype) {
        case NS_ETHERTYPE_IPV4:
            ns_packet_parse_ipv4(out, data, captured_length, offset);
            break;
        case NS_ETHERTYPE_IPV6:
            ns_packet_parse_ipv6(out, data, captured_length, offset);
            break;
        case NS_ETHERTYPE_ARP:
            ns_packet_parse_arp(out, data, captured_length, offset);
            break;
        default:
            /* Unknown/unsupported ethertype: leave network_proto UNKNOWN. */
            break;
    }
}

const char *ns_proto_name(ns_proto_t proto) {
    switch (proto) {
        case NS_PROTO_ARP:
            return "ARP";
        case NS_PROTO_IPV4:
            return "IPv4";
        case NS_PROTO_IPV6:
            return "IPv6";
        case NS_PROTO_TCP:
            return "TCP";
        case NS_PROTO_UDP:
            return "UDP";
        case NS_PROTO_ICMP:
            return "ICMP";
        case NS_PROTO_ICMPV6:
            return "ICMPv6";
        case NS_PROTO_DNS:
            return "DNS";
        case NS_PROTO_UNKNOWN:
        default:
            return "Unknown";
    }
}
