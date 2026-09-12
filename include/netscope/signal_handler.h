#ifndef NETSCOPE_SIGNAL_HANDLER_H
#define NETSCOPE_SIGNAL_HANDLER_H

#include <signal.h>

#include <pcap/pcap.h>

extern volatile sig_atomic_t ns_stop_requested;

void ns_install_signal_handlers(void);

void ns_signal_set_capture_handle(pcap_t *handle);

#endif
