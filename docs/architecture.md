# Architecture

NetScope is split into two pieces:

* **`netscope_core`** -- a static library with no dependency on libpcap.
  It owns the packet model, every protocol parser, the BPF filter-string
  builder, statistics/flow tracking, and text/JSON/hex output formatting.
* **`netscope`** -- the CLI executable. It links `netscope_core` and adds
  the libpcap-backed capture layer, signal handling, and `main()`.

This split exists so the parsing/formatting logic -- the part with the most
interesting bugs and the part worth fuzzing -- can be built, unit tested,
and fuzzed on any machine with a C compiler, independent of whether libpcap
is installed or whether the caller has capture privileges. `tests/`
links only against `netscope_core`.

## Pipeline

```
capture buffer (live pcap_loop callback, or offline pcap_next_ex)
    |
    v
ns_packet_parse()               (packet.c)
    |
    +-- ns_parse_ethernet()     (protocols/ethernet.c)
    |       |
    |       +-- ns_parse_ipv4() / ns_parse_ipv6() / ns_parse_arp()
    |               |
    |               +-- ns_parse_tcp() / ns_parse_udp() / ns_parse_icmp() / ns_parse_icmpv6()
    |                       |
    |                       +-- ns_parse_dns()   (only for UDP/TCP port 53)
    |
    v
ns_packet_t                      (one fully-decoded packet, stack-allocated)
    |
    +--> ns_stats_update()       (stats.c: counters + flow table)
    +--> ns_output_packet()      (output.c: text / JSON line / hex dump)
```

Both live capture (`-i`) and offline reading (`-r`) call the same
`ns_capture_run()` function in `capture.c`, which wraps `pcap_loop()`. The
only difference is how the underlying `pcap_t` was opened
(`pcap_create()`+`pcap_activate()` vs. `pcap_open_offline()`). Every packet,
live or from a file, is decoded by the same `ns_packet_parse()` call and
rendered by the same `ns_output_packet()` call -- there is exactly one
parsing/formatting code path, per requirement.

## The packet model

`ns_packet_t` (`include/netscope/packet.h`) is a fixed-size, stack-allocated
struct produced by `ns_packet_parse()`. It never allocates memory: network-
and transport-layer info are stored in a `union` selected by
`network_proto`/`transport_proto`, and `payload`/`raw_data` are *views* into
the capture buffer the caller owns (see "Ownership" below), not copies.

Parsing never fails outright. A packet that is truncated or internally
inconsistent comes back with whatever layers *could* be decoded populated,
`malformed = true`, and a static string in `malformed_reason`. This mirrors
how a real analyzer behaves: a corrupt packet is data worth reporting (and
counting in statistics), not a reason to abort the run.

## Ownership

`ns_packet_parse()` takes `data` by pointer and never copies it.
`ns_packet_t::raw_data` and `::payload` point into that same buffer.
Callers (the pcap callback in `capture.c`, or a test) must keep the buffer
alive for as long as they use the resulting `ns_packet_t` -- which in
NetScope's design is always just the duration of one callback invocation,
since a packet is parsed, counted, and printed before `pcap_loop()` hands
the next one over. Nothing retains an `ns_packet_t` (or a pointer derived
from it) past that point.

`ns_dns_info_t` is the one exception with owned storage: decoded names and
rdata text live in fixed-size arrays inside the struct itself (see
`docs/packet-parsing.md`), not as pointers into the packet buffer, since DNS
compression means a name's bytes may be scattered non-contiguously across
the message.

## Statistics and flow tracking

`ns_stats_t` (`stats.c`) is a plain counter struct plus a fixed-capacity
(1024-entry) open-addressing hash table keyed on
`(protocol, addr_a, port_a, addr_b, port_b)`, canonicalized so a flow is
counted the same way regardless of which direction a given packet travels.
It is intentionally not a general-purpose data structure: once full,
additional distinct flows stop being tracked (existing ones keep
accumulating), which is an acceptable trade-off for a "top conversations"
summary rather than a monitoring backend.

## Why not cast raw buffers into protocol structs?

An earlier, simpler design would `#pragma pack` a `struct ns_ipv4_header`
and cast the capture buffer directly to it. NetScope avoids this:

* The buffer is not guaranteed to be aligned for every field's natural
  alignment on every architecture.
* Nothing stops a cast from reading past the end of a short/truncated
  capture.
* Endianness conversion still has to happen somewhere for every multi-byte
  field, so the cast does not actually save work.

Instead, every parser reads through `ns_read_u8/u16_be/u32_be/u64_be()`
(`util.c`), which take an explicit `(buffer, length, offset)` and refuse to
read past `length`. This is slightly more verbose than a struct cast and
is, deliberately, the only way any parser in this codebase touches packet
bytes.
