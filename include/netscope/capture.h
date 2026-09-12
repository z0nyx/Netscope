#ifndef NETSCOPE_CAPTURE_H
#define NETSCOPE_CAPTURE_H

#include <stdbool.h>
#include <stdio.h>

#include <pcap/pcap.h>

#include "netscope/packet.h"

#define NS_CAPTURE_DEFAULT_SNAPLEN 262144
#define NS_CAPTURE_TIMEOUT_MS 1000

typedef void (*ns_capture_packet_fn)(void *ctx, const ns_packet_t *pkt);

typedef struct {
    pcap_t *handle;
    ns_link_type_t link_type;
    pcap_dumper_t *dumper;
    uint64_t next_packet_number;
} ns_capture_t;

bool ns_capture_list_interfaces(FILE *out, char *err_buf, size_t err_buf_len);

bool ns_capture_interface_exists(const char *name);

bool ns_capture_open_live(ns_capture_t *cap, const char *interface, const char *bpf_filter,
                          char *err_buf, size_t err_buf_len);

bool ns_capture_open_offline(ns_capture_t *cap, const char *path, const char *bpf_filter,
                             char *err_buf, size_t err_buf_len);

bool ns_capture_open_dump(ns_capture_t *cap, const char *path, char *err_buf, size_t err_buf_len);

bool ns_capture_run(ns_capture_t *cap, ns_capture_packet_fn on_packet, void *ctx, char *err_buf,
                    size_t err_buf_len);

void ns_capture_close(ns_capture_t *cap);

#endif
