#ifndef NETSCOPE_LOG_H
#define NETSCOPE_LOG_H

#include "netscope/config.h"

void ns_log_set_level(ns_log_level_t level);

void ns_log(ns_log_level_t level, const char *fmt, ...)
#if defined(__clang__)
    /* Clang only accepts the gnu_printf archetype for GNU-libc targets, not
     * Darwin/MinGW, and its own "printf" archetype already recognizes %z on
     * every target, so plain "printf" is the portable choice. */
    __attribute__((format(printf, 2, 3)))
#elif defined(__GNUC__)
    /* gnu_printf, not plain "printf": on an MS-CRT target GCC's "printf"
     * archetype does not recognize %z, which some call sites use. */
    __attribute__((format(gnu_printf, 2, 3)))
#endif
    ;

#define ns_log_error(...) ns_log(NS_LOG_ERROR, __VA_ARGS__)
#define ns_log_warn(...) ns_log(NS_LOG_WARN, __VA_ARGS__)
#define ns_log_info(...) ns_log(NS_LOG_INFO, __VA_ARGS__)
#define ns_log_debug(...) ns_log(NS_LOG_DEBUG, __VA_ARGS__)

#endif
