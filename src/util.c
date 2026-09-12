#include "netscope/util.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/*
 * Every protocol parser in this codebase routes its bounds checking
 * through here. The check is deliberately `size <= length - offset`
 * rather than the more obvious `offset + size > length`: once
 * `offset <= length` is established, `length - offset` cannot underflow,
 * whereas `offset + size` can overflow size_t for a large enough
 * (attacker-controlled) size, which would make an out-of-bounds access
 * pass the check.
 */
bool ns_bounds_check(size_t length, size_t offset, size_t size) {
    if (offset > length) {
        return false;
    }

    return size <= length - offset;
}

bool ns_read_u8(const uint8_t *data, size_t length, size_t offset, uint8_t *value) {
    if (!ns_bounds_check(length, offset, sizeof(*value))) {
        return false;
    }
    *value = data[offset];
    return true;
}

bool ns_read_u16_be(const uint8_t *data, size_t length, size_t offset, uint16_t *value) {
    if (!ns_bounds_check(length, offset, sizeof(*value))) {
        return false;
    }
    *value = (uint16_t) ((uint16_t) data[offset] << 8 | (uint16_t) data[offset + 1]);
    return true;
}

bool ns_read_u32_be(const uint8_t *data, size_t length, size_t offset, uint32_t *value) {
    if (!ns_bounds_check(length, offset, sizeof(*value))) {
        return false;
    }
    *value = (uint32_t) data[offset] << 24 | (uint32_t) data[offset + 1] << 16 |
             (uint32_t) data[offset + 2] << 8 | (uint32_t) data[offset + 3];
    return true;
}

bool ns_read_u64_be(const uint8_t *data, size_t length, size_t offset, uint64_t *value) {
    if (!ns_bounds_check(length, offset, sizeof(*value))) {
        return false;
    }
    uint64_t v = 0;
    for (size_t i = 0; i < sizeof(*value); i++) {
        v = (v << 8) | data[offset + i];
    }
    *value = v;
    return true;
}

void ns_format_mac(const uint8_t mac[6], char *buf, size_t buf_len) {
    snprintf(buf, buf_len, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4],
             mac[5]);
}

void ns_format_ipv4(uint32_t addr_be, char *buf, size_t buf_len) {
    const uint8_t *b = (const uint8_t *) &addr_be;
    snprintf(buf, buf_len, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

void ns_format_ipv6(const uint8_t addr[16], char *buf, size_t buf_len) {
    uint16_t groups[8];
    for (size_t i = 0; i < 8; i++) {
        groups[i] = (uint16_t) (((uint16_t) addr[i * 2] << 8) | addr[i * 2 + 1]);
    }

    int best_start = -1;
    int best_len = 0;
    int cur_start = -1;
    int cur_len = 0;
    for (int i = 0; i < 8; i++) {
        if (groups[i] == 0) {
            if (cur_start < 0) {
                cur_start = i;
            }
            cur_len++;
            if (cur_len > best_len) {
                best_len = cur_len;
                best_start = cur_start;
            }
        } else {
            cur_start = -1;
            cur_len = 0;
        }
    }
    if (best_len < 2) {
        best_start = -1;
        best_len = 0;
    }

    char tmp[46];
    size_t pos = 0;
    for (int i = 0; i < 8;) {
        if (i == best_start) {
            tmp[pos++] = ':';
            tmp[pos++] = ':';
            i += best_len;
            continue;
        }
        if (i != 0 && i != best_start + best_len) {
            tmp[pos++] = ':';
        }
        pos += (size_t) snprintf(tmp + pos, sizeof(tmp) - pos, "%x", groups[i]);
        i++;
    }
    if (pos == 0) {
        tmp[pos++] = ':';
        tmp[pos++] = ':';
    }
    tmp[pos] = '\0';

    snprintf(buf, buf_len, "%s", tmp);
}

void ns_format_bytes(uint64_t bytes, char *buf, size_t buf_len) {
    static const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    double value = (double) bytes;
    size_t unit = 0;
    while (value >= 1024.0 && unit < (sizeof(units) / sizeof(units[0])) - 1) {
        value /= 1024.0;
        unit++;
    }
    if (unit == 0) {
        snprintf(buf, buf_len, "%" PRIu64 " %s", bytes, units[unit]);
    } else {
        snprintf(buf, buf_len, "%.2f %s", value, units[unit]);
    }
}

/*
 * snprintf()'s return value is how many bytes it *would* write given
 * enough room, not how many it actually wrote -- treating it as the
 * latter and feeding it straight back in as the next call's write offset
 * (`pos += snprintf(...)`) lets pos run past buf_len after a truncated
 * call, and every following `buf_len - pos` then underflows to a huge
 * size_t. Clamping here keeps pos <= buf_len unconditionally, so that
 * class of bug can't happen even if a future change makes a line grow
 * to hit the buffer's limit.
 */
static size_t append_line(char *buf, size_t buf_len, size_t pos, const char *fmt, ...)
#if defined(__GNUC__) || defined(__clang__)
    /* gnu_printf (not plain "printf") so %zx/%zu are recognized even when
     * targeting an MS CRT, where GCC's default "printf" archetype does
     * not know that conversion. */
    __attribute__((format(gnu_printf, 4, 5)))
#endif
    ;

static size_t append_line(char *buf, size_t buf_len, size_t pos, const char *fmt, ...) {
    if (pos >= buf_len) {
        return pos;
    }
    va_list args;
    va_start(args, fmt);
    int written = vsnprintf(buf + pos, buf_len - pos, fmt, args);
    va_end(args);
    if (written <= 0) {
        return pos;
    }
    size_t remaining = buf_len - pos;
    size_t actual = (size_t) written < remaining ? (size_t) written : remaining - 1;
    return pos + actual;
}

bool ns_hex_dump(const uint8_t *data, size_t length, ns_dump_write_fn write, void *ctx) {
    /* One line is offset(<=16 hex digits) + "  " + 16*"XX " + " " + " " +
     * 16 ASCII chars + "\n\0": comfortably under 128 bytes even for a
     * maximal 64-bit offset, and append_line() clamps regardless. */
    char line[128];
    for (size_t offset = 0; offset < length; offset += 16) {
        size_t chunk = length - offset < 16 ? length - offset : 16;

        size_t pos = append_line(line, sizeof(line), 0, "%04zx  ", offset);

        for (size_t i = 0; i < 16; i++) {
            if (i < chunk) {
                pos = append_line(line, sizeof(line), pos, "%02x ", data[offset + i]);
            } else {
                pos = append_line(line, sizeof(line), pos, "   ");
            }
            if (i == 7) {
                pos = append_line(line, sizeof(line), pos, " ");
            }
        }

        pos = append_line(line, sizeof(line), pos, " ");
        for (size_t i = 0; i < chunk && pos + 1 < sizeof(line); i++) {
            uint8_t c = data[offset + i];
            line[pos++] = (c >= 0x20 && c < 0x7f) ? (char) c : '.';
        }
        if (pos + 1 < sizeof(line)) {
            line[pos++] = '\n';
        }
        line[pos] = '\0';

        if (!write(ctx, line)) {
            return false;
        }
    }
    return true;
}

static bool ns_hex_dump_file_write(void *ctx, const char *chunk) {
    FILE *out = (FILE *) ctx;
    return fputs(chunk, out) >= 0;
}

void ns_hex_dump_file(const uint8_t *data, size_t length, FILE *out) {
    ns_hex_dump(data, length, ns_hex_dump_file_write, out);
}
