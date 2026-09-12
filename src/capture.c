#include "netscope/capture.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

#include "netscope/log.h"
#include "netscope/signal_handler.h"

static void print_device_addresses(FILE *out, const pcap_addr_t *addr) {
    for (; addr != NULL; addr = addr->next) {
        if (addr->addr == NULL) {
            continue;
        }
        char buf[INET6_ADDRSTRLEN];
        if (addr->addr->sa_family == AF_INET) {
            const struct sockaddr_in *sin = (const struct sockaddr_in *) (const void *) addr->addr;
            if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) != NULL) {
                fprintf(out, "     IPv4: %s\n", buf);
            }
        } else if (addr->addr->sa_family == AF_INET6) {
            const struct sockaddr_in6 *sin6 =
                (const struct sockaddr_in6 *) (const void *) addr->addr;
            if (inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf)) != NULL) {
                fprintf(out, "     IPv6: %s\n", buf);
            }
        }
    }
}

bool ns_capture_list_interfaces(FILE *out, char *err_buf, size_t err_buf_len) {
    /* pcap_findalldevs() writes directly into err_buf, which must be at
     * least PCAP_ERRBUF_SIZE bytes; that's documented on the declaration in
     * capture.h, not enforced here. */
    (void) err_buf_len;

    pcap_if_t *devices;
    if (pcap_findalldevs(&devices, err_buf) != 0) {
        return false;
    }

    if (devices == NULL) {
        fprintf(out, "No capture interfaces found.\n");
        fprintf(out, "hint: capturing usually requires elevated privileges; see README.md\n");
        return true;
    }

    fprintf(out, "Available interfaces:\n\n");
    int index = 1;
    for (pcap_if_t *dev = devices; dev != NULL; dev = dev->next, index++) {
        fprintf(out, "%d. %s\n", index, dev->name);
        if (dev->description != NULL) {
            fprintf(out, "   %s\n", dev->description);
        }
        if (dev->addresses != NULL) {
            fprintf(out, "   addresses:\n");
            print_device_addresses(out, dev->addresses);
        }
        fprintf(out, "\n");
    }

    pcap_freealldevs(devices);
    return true;
}

bool ns_capture_interface_exists(const char *name) {
    pcap_if_t *devices;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&devices, errbuf) != 0) {
        return false;
    }

    bool found = false;
    for (pcap_if_t *dev = devices; dev != NULL; dev = dev->next) {
        if (strcmp(dev->name, name) == 0) {
            found = true;
            break;
        }
    }

    pcap_freealldevs(devices);
    return found;
}

static bool apply_filter(pcap_t *handle, const char *bpf_filter, char *err_buf,
                         size_t err_buf_len) {
    if (bpf_filter == NULL || bpf_filter[0] == '\0') {
        return true;
    }

    struct bpf_program program;
    if (pcap_compile(handle, &program, bpf_filter, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        snprintf(err_buf, err_buf_len, "invalid capture filter '%s': %s", bpf_filter,
                 pcap_geterr(handle));
        return false;
    }

    int result = pcap_setfilter(handle, &program);
    pcap_freecode(&program);

    if (result != 0) {
        snprintf(err_buf, err_buf_len, "failed to apply capture filter: %s", pcap_geterr(handle));
        return false;
    }

    return true;
}

/* Only Ethernet framing is parsed; every other datalink type (Linux cooked
 * capture, raw IP, ...) is rejected here rather than fed to the Ethernet
 * parser, which would silently misinterpret its bytes. */
static bool resolve_link_type(pcap_t *handle, ns_link_type_t *link_type, char *err_buf,
                              size_t err_buf_len) {
    int dlt = pcap_datalink(handle);
    ns_log_debug("pcap datalink: %s", pcap_datalink_val_to_name(dlt));

    if (dlt != DLT_EN10MB) {
        const char *name = pcap_datalink_val_to_name(dlt);
        snprintf(err_buf, err_buf_len, "unsupported datalink type: %s",
                 name != NULL ? name : "unknown");
        return false;
    }

    *link_type = NS_LINK_ETHERNET;
    return true;
}

bool ns_capture_open_live(ns_capture_t *cap, const char *interface, const char *bpf_filter,
                          char *err_buf, size_t err_buf_len) {
    memset(cap, 0, sizeof(*cap));

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_create(interface, errbuf);
    if (handle == NULL) {
        snprintf(err_buf, err_buf_len, "failed to open interface '%s': %s", interface, errbuf);
        return false;
    }

    pcap_set_snaplen(handle, NS_CAPTURE_DEFAULT_SNAPLEN);
    pcap_set_promisc(handle, 1);
    pcap_set_timeout(handle, NS_CAPTURE_TIMEOUT_MS);

    int activate_result = pcap_activate(handle);
    if (activate_result < 0) {
        snprintf(err_buf, err_buf_len, "failed to activate capture on '%s': %s", interface,
                 pcap_geterr(handle));
        pcap_close(handle);
        return false;
    }
    if (activate_result > 0) {
        ns_log_warn("pcap_activate warning on '%s': %s", interface,
                    pcap_statustostr(activate_result));
    }

    ns_link_type_t link_type;
    if (!resolve_link_type(handle, &link_type, err_buf, err_buf_len)) {
        pcap_close(handle);
        return false;
    }

    if (!apply_filter(handle, bpf_filter, err_buf, err_buf_len)) {
        pcap_close(handle);
        return false;
    }

    cap->handle = handle;
    cap->link_type = link_type;
    return true;
}

bool ns_capture_open_offline(ns_capture_t *cap, const char *path, const char *bpf_filter,
                             char *err_buf, size_t err_buf_len) {
    memset(cap, 0, sizeof(*cap));

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(path, errbuf);
    if (handle == NULL) {
        snprintf(err_buf, err_buf_len, "failed to open capture file '%s': %s", path, errbuf);
        return false;
    }

    ns_link_type_t link_type;
    if (!resolve_link_type(handle, &link_type, err_buf, err_buf_len)) {
        pcap_close(handle);
        return false;
    }

    if (!apply_filter(handle, bpf_filter, err_buf, err_buf_len)) {
        pcap_close(handle);
        return false;
    }

    cap->handle = handle;
    cap->link_type = link_type;
    return true;
}

bool ns_capture_open_dump(ns_capture_t *cap, const char *path, char *err_buf, size_t err_buf_len) {
    pcap_dumper_t *dumper = pcap_dump_open(cap->handle, path);
    if (dumper == NULL) {
        snprintf(err_buf, err_buf_len, "failed to open '%s' for writing: %s", path,
                 pcap_geterr(cap->handle));
        return false;
    }
    cap->dumper = dumper;
    return true;
}

typedef struct {
    ns_capture_t *cap;
    ns_capture_packet_fn on_packet;
    void *ctx;
} ns_capture_loop_ctx_t;

static void pcap_packet_callback(u_char *user, const struct pcap_pkthdr *header,
                                 const u_char *data) {
    ns_capture_loop_ctx_t *loop_ctx = (ns_capture_loop_ctx_t *) (void *) user;
    ns_capture_t *cap = loop_ctx->cap;

    if (cap->dumper != NULL) {
        pcap_dump((u_char *) cap->dumper, header, data);
    }

    ns_timestamp_t ts = {
        .seconds = (int64_t) header->ts.tv_sec,
        .microseconds = (int32_t) header->ts.tv_usec,
    };

    /* caplen is how many bytes of `data` actually exist and is what every
     * parser bounds-checks against; len is the original on-wire length and
     * may be larger for a packet libpcap truncated to the snaplen. Passing
     * len where caplen belongs would let a parser read past the buffer. */
    ns_packet_t pkt;
    ns_packet_parse(data, header->caplen, header->len, ts, ++cap->next_packet_number,
                    cap->link_type, &pkt);

    loop_ctx->on_packet(loop_ctx->ctx, &pkt);
}

bool ns_capture_run(ns_capture_t *cap, ns_capture_packet_fn on_packet, void *ctx, char *err_buf,
                    size_t err_buf_len) {
    ns_capture_loop_ctx_t loop_ctx = {.cap = cap, .on_packet = on_packet, .ctx = ctx};

    ns_signal_set_capture_handle(cap->handle);
    int result = pcap_loop(cap->handle, -1, pcap_packet_callback, (u_char *) (void *) &loop_ctx);
    ns_signal_set_capture_handle(NULL);

    if (result == -1) {
        snprintf(err_buf, err_buf_len, "capture loop failed: %s", pcap_geterr(cap->handle));
        return false;
    }

    /* 0 (offline EOF) and -2 (pcap_breakloop() called, e.g. from Ctrl+C)
     * are both clean stops, not errors. */
    return true;
}

void ns_capture_close(ns_capture_t *cap) {
    if (cap->dumper != NULL) {
        pcap_dump_close(cap->dumper);
        cap->dumper = NULL;
    }
    if (cap->handle != NULL) {
        pcap_close(cap->handle);
        cap->handle = NULL;
    }
}
