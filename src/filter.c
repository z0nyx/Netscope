#include "netscope/filter.h"

#include <stdio.h>
#include <string.h>

static bool append(char *out, size_t out_len, size_t *pos, const char *piece) {
    size_t piece_len = strlen(piece);
    if (*pos != 0) {
        if (*pos + 4 >= out_len) {
            return false;
        }
        memcpy(out + *pos, " and ", 5);
        *pos += 5;
    }
    if (*pos + piece_len >= out_len) {
        return false;
    }
    memcpy(out + *pos, piece, piece_len);
    *pos += piece_len;
    out[*pos] = '\0';
    return true;
}

bool ns_filter_build_bpf(const ns_filter_spec_t *spec, char *out, size_t out_len) {
    if (out_len == 0) {
        return false;
    }
    out[0] = '\0';

    if (spec->raw != NULL && spec->raw[0] != '\0') {
        if (strlen(spec->raw) >= out_len) {
            return false;
        }
        strcpy(out, spec->raw);
        return true;
    }

    size_t pos = 0;
    char piece[128];

    if (spec->tcp && !append(out, out_len, &pos, "tcp")) {
        return false;
    }
    if (spec->udp && !append(out, out_len, &pos, "udp")) {
        return false;
    }
    if (spec->icmp && !append(out, out_len, &pos, "icmp")) {
        return false;
    }
    if (spec->port >= 0) {
        snprintf(piece, sizeof(piece), "port %d", spec->port);
        if (!append(out, out_len, &pos, piece)) {
            return false;
        }
    }
    if (spec->host != NULL && spec->host[0] != '\0') {
        snprintf(piece, sizeof(piece), "host %s", spec->host);
        if (!append(out, out_len, &pos, piece)) {
            return false;
        }
    }
    if (spec->src != NULL && spec->src[0] != '\0') {
        snprintf(piece, sizeof(piece), "src host %s", spec->src);
        if (!append(out, out_len, &pos, piece)) {
            return false;
        }
    }
    if (spec->dst != NULL && spec->dst[0] != '\0') {
        snprintf(piece, sizeof(piece), "dst host %s", spec->dst);
        if (!append(out, out_len, &pos, piece)) {
            return false;
        }
    }

    return true;
}
