#ifndef NETSCOPE_FILTER_H
#define NETSCOPE_FILTER_H

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    bool tcp;
    bool udp;
    bool icmp;
    int port;
    const char *host;
    const char *src;
    const char *dst;
    const char *raw;
} ns_filter_spec_t;

bool ns_filter_build_bpf(const ns_filter_spec_t *spec, char *out, size_t out_len);

#endif
