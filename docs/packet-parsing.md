# Packet parsing notes

This document is for anyone modifying or reviewing a parser in
`src/protocols/`. It covers the recurring patterns and the specific edge
cases NetScope defends against.

## Network byte order

Every multi-byte field on the wire is big-endian ("network byte order").
NetScope never relies on `ntohs`/`ntohl` plus a struct-cast; instead
`ns_read_u16_be()`/`ns_read_u32_be()`/`ns_read_u64_be()` (`src/util.c`)
assemble the value byte-by-byte from an explicit offset:

```c
*value = (uint16_t)((uint16_t)data[offset] << 8 | (uint16_t)data[offset + 1]);
```

This sidesteps alignment (no cast to `uint16_t *`, which would be undefined
behavior on an unaligned offset) and keeps the byte order explicit at the
call site rather than implicit in a struct layout.

## Bounds checking

Every read function takes `(data, length, offset[, size])` and checks
`ns_bounds_check()` before touching memory:

```c
bool ns_bounds_check(size_t length, size_t offset, size_t size) {
    if (offset > length) {
        return false;
    }
    return size <= length - offset; /* no overflow: offset <= length here */
}
```

The `length - offset` order (rather than `offset + size > length`) matters:
`offset + size` can overflow `size_t` for a maliciously large `size`, while
`length - offset` cannot, since the preceding check guarantees
`offset <= length`. Every parser is written against `length` = the number
of bytes actually captured, never a length field taken from inside the
packet -- a packet's own `total_length`/`rdlength`/etc. is a claim to be
verified, not a fact to trust.

## Ethernet framing

A frame is destination MAC (6) + source MAC (6) + EtherType (2), optionally
followed by a 4-byte 802.1Q VLAN tag before the *real* EtherType. NetScope
detects the tag (EtherType `0x8100`) and re-reads the EtherType after it,
reporting both the VLAN ID and the inner EtherType in `ns_eth_info_t`.

## IPv4: variable header length

The header length is `IHL * 4` bytes, where `IHL` (a 4-bit field) must be
at least 5 (20 bytes; `IHL < 5` is rejected as malformed) and can be up to
15 (60 bytes, with up to 40 bytes of options). NetScope reads `IHL` first,
computes the real header length, bounds-checks *that* against the captured
buffer, and only then reads the rest of the header -- so a packet claiming
a 60-byte header that was captured with only 30 bytes is reported as
truncated rather than read past its end.

Fragmentation: a non-zero `fragment_offset` or a set `MF` (more fragments)
flag marks a packet as part of a fragment train. Only the *initial*
fragment (`fragment_offset == 0`) carries a transport-layer header; later
fragments carry a raw continuation of the IP payload. Attempting to parse a
TCP/UDP/ICMP header out of a non-initial fragment would misinterpret
arbitrary payload bytes as port numbers and flags, so `ns_packet_parse()`
stops at the IP layer for those. Full fragment reassembly is out of scope
for v0.1 (see the roadmap).

## TCP: variable header length

Same shape as IPv4's IHL: a 4-bit `data offset` field counts 32-bit words
(minimum 5 / 20 bytes), giving up to 40 bytes of options. NetScope
validates `data_offset >= 5` and bounds-checks the full header length
before trusting anything past the fixed 20-byte portion.

## DNS name compression

This is the parser with the most attack surface, because DNS names are
compressed: a label sequence can end early with a 2-byte *pointer*
(top two bits `11`) to another offset in the message where the name
continues, instead of a zero terminator. This lets a message reuse a
common suffix (like a domain) across many records without repeating it.

`ns_dns_decode_name()` (`src/protocols/dns.c`) walks label-by-label,
following pointers as needed, with three independent defenses:

1. **Jump limit.** Every pointer followed increments a counter capped at
   `NS_DNS_MAX_JUMPS` (32). A pointer that jumps to itself, or a cycle of
   pointers, would otherwise loop forever; the counter makes that
   terminate in bounded time regardless of packet content.
2. **Bounds-checked reads.** Every label length byte and pointer is read
   through the same `ns_read_*` helpers as every other protocol, so a
   pointer or label claiming to extend past the captured buffer is
   rejected rather than read out of bounds.
3. **Output length limit.** The decoded (decompressed) name is written into
   a fixed `NS_DNS_MAX_NAME + 1` (256) byte buffer; a legally-encoded chain
   of labels whose *decompressed* text would not fit is rejected as
   malformed rather than silently truncated or overflowed.

A label length byte's top two bits select its meaning: `00` = a literal
label of up to 63 bytes (the remaining 6 bits), `11` = a pointer, and `01`
or `10` are reserved and rejected outright. Because a literal label's
length is only 6 bits, "a label larger than 63 bytes" cannot actually be
encoded as a literal label at all -- the encoding itself makes that case
impossible, and any length byte that looks like it might mean something
larger is one of the reserved patterns instead, caught by the same check.

Compression pointers are also used inside record *rdata* for the name-typed
records (CNAME, NS, PTR, and the second half of MX) -- `ns_dns_decode_name`
is reused there with the same protections, since a pointer inside rdata can
jump anywhere in the message, including into the middle of another name
(NetScope's tests exercise this: a CNAME's rdata pointer that lands
mid-way through the question's own encoded name).
