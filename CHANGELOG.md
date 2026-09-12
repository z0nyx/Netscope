# Changelog

All notable changes to this project are documented in this file.

## [0.1.0] - Unreleased

Initial release.

### Added
- Live capture (`-i`) and offline `.pcap` reading (`-r`) sharing one parsing
  and output pipeline, via libpcap.
- Manual, bounds-checked protocol parsers: Ethernet (with 802.1Q VLAN),
  ARP, IPv4 (with fragmentation awareness), IPv6 (with extension header
  walking), TCP, UDP, ICMP, ICMPv6, and DNS (with compression-pointer-safe
  name decoding).
- CLI filtering (`--tcp`/`--udp`/`--icmp`/`--port`/`--host`/`--src`/`--dst`)
  translated to BPF, plus a raw `--filter` escape hatch.
- Text, JSON Lines (`--format json`), verbose (`--verbose`), and hex
  (`--hex`) output modes.
- Traffic statistics and a "top conversations" flow summary, printed at
  the end of a run (`--stats`, or always for live capture).
- Saving captured traffic to a `.pcap` file (`--write`).
- `--list-interfaces` using libpcap device enumeration.
- Clean shutdown on `Ctrl+C` / `SIGTERM`.
- Unit tests covering every parser against synthetic packets, including
  truncated and malformed input.
- CMake build with optional ASan/UBSan (`NETSCOPE_ENABLE_ASAN`/`_UBSAN`)
  and `-Werror` (`NETSCOPE_WARNINGS_AS_ERRORS`) configurations, and a
  GitHub Actions CI matrix (Ubuntu/GCC, Ubuntu/Clang, macOS/Clang, a
  sanitizer job, and a clang-format check).
