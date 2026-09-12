#ifndef NETSCOPE_UTIL_H
#define NETSCOPE_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* True when [offset, offset + size) lies entirely within [0, length).
 * Every bounds check in this codebase -- protocol parsers included --
 * goes through this function; see the comment on its definition in
 * util.c for why it is written the way it is. */
bool ns_bounds_check(size_t length, size_t offset, size_t size);

/*
 * Bounds-checked big-endian readers. Every protocol parser receives a raw
 * buffer plus its available length and must never read past it, even when
 * a length or offset field inside the packet claims otherwise. These
 * return false (leaving *value untouched) when [offset, offset+size) does
 * not fit inside [0, length).
 */
bool ns_read_u8(const uint8_t *data, size_t length, size_t offset, uint8_t *value);
bool ns_read_u16_be(const uint8_t *data, size_t length, size_t offset, uint16_t *value);
bool ns_read_u32_be(const uint8_t *data, size_t length, size_t offset, uint32_t *value);
bool ns_read_u64_be(const uint8_t *data, size_t length, size_t offset, uint64_t *value);

/* Formats a 6-byte MAC address as "aa:bb:cc:dd:ee:ff" into buf (>= 18 bytes). */
void ns_format_mac(const uint8_t mac[6], char *buf, size_t buf_len);

/* Formats an IPv4 address (network byte order, as in a struct in_addr) into
 * buf (>= 16 bytes). */
void ns_format_ipv4(uint32_t addr_be, char *buf, size_t buf_len);

/* Formats a 16-byte IPv6 address into buf (>= 46 bytes). */
void ns_format_ipv6(const uint8_t addr[16], char *buf, size_t buf_len);

/* Formats a byte count using human-friendly units (B, KB, MB, GB) into buf. */
void ns_format_bytes(uint64_t bytes, char *buf, size_t buf_len);

/*
 * Writes a hex dump of data (canonical 16-bytes-per-line, offset + hex +
 * ASCII gutter) by calling write() once per line. Returns false only if a
 * write callback fails.
 */
typedef bool (*ns_dump_write_fn)(void *ctx, const char *chunk);
bool ns_hex_dump(const uint8_t *data, size_t length, ns_dump_write_fn write, void *ctx);

/* Convenience wrapper that renders the hex dump into a caller-owned FILE*. */
void ns_hex_dump_file(const uint8_t *data, size_t length, FILE *out);

#endif
