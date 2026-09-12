#include "netscope/signal_handler.h"

#include <stddef.h>

volatile sig_atomic_t ns_stop_requested = 0;

static pcap_t *g_capture_handle = NULL;

static void handle_signal(int signum) {
    (void) signum;
    ns_stop_requested = 1;
    if (g_capture_handle != NULL) {
        pcap_breakloop(g_capture_handle);
    }
}

void ns_signal_set_capture_handle(pcap_t *handle) {
    g_capture_handle = handle;
}

void ns_install_signal_handlers(void) {
    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}
