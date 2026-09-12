#ifndef NETSCOPE_OUTPUT_H
#define NETSCOPE_OUTPUT_H

#include <stdbool.h>
#include <stdio.h>

#include "netscope/config.h"
#include "netscope/packet.h"

typedef struct {
    bool color;
    bool verbose;
    bool quiet;
    bool hex;
    ns_output_format_t format;
} ns_output_options_t;

void ns_output_packet(const ns_packet_t *pkt, const ns_output_options_t *opts, FILE *out);

bool ns_output_should_use_color(bool no_color_flag, FILE *stream);

#endif
