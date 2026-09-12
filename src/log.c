#include "netscope/log.h"

#include <stdarg.h>
#include <stdio.h>

static ns_log_level_t g_log_level = NS_LOG_WARN;

void ns_log_set_level(ns_log_level_t level) {
    g_log_level = level;
}

static const char *level_name(ns_log_level_t level) {
    switch (level) {
        case NS_LOG_ERROR:
            return "ERROR";
        case NS_LOG_WARN:
            return "WARN";
        case NS_LOG_INFO:
            return "INFO";
        case NS_LOG_DEBUG:
            return "DEBUG";
        default:
            return "?";
    }
}

void ns_log(ns_log_level_t level, const char *fmt, ...) {
    if (level > g_log_level) {
        return;
    }

    fprintf(stderr, "[%s] ", level_name(level));

    va_list args;
    va_start(args, fmt);
#if defined(__GNUC__) || defined(__clang__)
    /* fmt is forwarded from ns_log's own format-checked parameter, so this
     * indirection is intentional -- Wformat-nonliteral has no way to know
     * that and would otherwise fire on every printf-style wrapper. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
    vfprintf(stderr, fmt, args);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
    va_end(args);

    fputc('\n', stderr);
}
