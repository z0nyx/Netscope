# NetScope

<!-- Replace z0nyx below with the actual GitHub username/org once this repo is pushed. -->

[![CI](https://github.com/z0nyx/netscope/actions/workflows/ci.yml/badge.svg)](https://github.com/z0nyx/netscope/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![C17](https://img.shields.io/badge/C-17-blue.svg)](https://en.cppreference.com/w/c/17)
[![Platforms](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg)](#installation)

A small packet analyzer written in C17. libpcap supplies the captured
bytes; everything from the Ethernet header up -- ARP, IPv4/IPv6, TCP/UDP,
ICMP/ICMPv6, DNS -- is decoded by hand, field by field, with explicit
bounds checks against what was actually captured rather than trusting a
length byte from inside the packet. It exists to work through what "safe"
binary parsing over untrusted, possibly truncated input actually takes in
C, not to replace Wireshark.

## Features

- Live capture (`-i`) and offline `.pcap` reading (`-r`) through one
  shared parsing/output pipeline
- BPF-based filtering, from simple flags (`--tcp`, `--port 443`, ...) or a
  raw expression
- Compact colored terminal output, a verbose per-packet detail view, and a
  hex+ASCII dump mode
- JSON Lines output for scripting
- Traffic statistics and a "top conversations" flow summary
- Saving captured traffic back to a `.pcap` file
- Clean shutdown on `Ctrl+C`, with a statistics summary printed on exit

## Example output

```text
$ sudo netscope -i en0
NetScope 0.1.0
Interface: en0
Capture started. Press Ctrl+C to stop.

[14:28:31.381] TCP    192.168.1.12:53122 -> 142.250.74.14:443   [SYN] 74 B
[14:28:31.402] UDP    192.168.1.12:53341 -> 8.8.8.8:53              DNS 72 B
    Query: github.com A
[14:28:32.019] TCP    104.18.32.47:443 -> 192.168.1.12:53122   [PSH,ACK] 842 B
[14:28:32.225] ICMP   192.168.1.12 -> 1.1.1.1                  Echo Request id=321 seq=8 64 B
^C
──────────────────────────────────────
NetScope Capture Statistics
──────────────────────────────────────

Duration:              4.71 s

Packets:               6
Captured traffic:      1.02 KB
Wire traffic:          1.02 KB

Protocols
  TCP               2    33.33%
  UDP               1    16.67%
  ICMP              1    16.67%

Application
  DNS               1

Malformed              0
──────────────────────────────────────
```

## Architecture

```text
capture (libpcap, live or -r file)
              |
        Ethernet (+ VLAN)
              |
        +-----+------+
        |            |
       ARP      IPv4 / IPv6
                      |
              TCP / UDP / ICMP
                      |
                     DNS
                      |
               stats + output
```

The protocol-parsing core (`netscope_core`) has no dependency on libpcap
and is built and unit tested independently of the capture layer -- live
capture and `-r <file>` both end up decoded by the same
`ns_packet_parse()` call. See [`docs/architecture.md`](docs/architecture.md)
for the reasoning behind that split, and
[`docs/packet-parsing.md`](docs/packet-parsing.md) for the byte-level
parsing and bounds-checking approach, including DNS compression pointer
handling.

## Supported protocols

| Layer       | Protocols                              |
|-------------|-----------------------------------------|
| Link        | Ethernet II, 802.1Q VLAN tags           |
| Network     | ARP, IPv4 (with fragmentation awareness), IPv6 (with extension headers) |
| Transport   | TCP, UDP, ICMP, ICMPv6                  |
| Application | DNS (A, AAAA, CNAME, NS, PTR, MX, TXT)  |

## Installation

### Linux

```bash
sudo apt install libpcap-dev cmake build-essential   # Debian/Ubuntu
sudo dnf install libpcap-devel cmake gcc              # Fedora
```

### macOS

libpcap headers ship with the system; only CMake is needed:

```bash
brew install cmake
```

### Building from source

```bash
git clone https://github.com/z0nyx/netscope.git
cd netscope
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
sudo cmake --install build   # optional
```

The `netscope` executable is skipped (with a warning) if libpcap
development headers are not found; `netscope_core` and its tests still
build. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full build/test
workflow, including sanitizer and warnings-as-errors builds.

## Usage

```bash
sudo netscope -i en0            # macOS
sudo netscope -i eth0           # Linux
netscope -r capture.pcap        # read a capture file
netscope --list-interfaces
netscope --help
```

See [`docs/usage.md`](docs/usage.md) for the full set of examples,
including filters, JSON output, and reading/writing `.pcap` files. A quick
sample:

```bash
netscope -i en0 --tcp --port 443 --verbose
netscope -i en0 --format json --output packets.json
netscope -r capture.pcap --stats
```

## Permissions

Live capture opens a raw socket, which the OS restricts:

- **Linux:** run as root, or grant the binary capture capabilities once
  instead of using `sudo` every time:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip $(command -v netscope)
  ```
- **macOS:** run with `sudo`, or add your user to the `access_bpf` group
  (varies by macOS version) to read from `/dev/bpf*` without root.

Reading (`-r`) or writing (`--write`) `.pcap` files needs no special
privileges.

## Development

```bash
cmake -S . -B build -DNETSCOPE_WARNINGS_AS_ERRORS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

Sanitizer build:

```bash
cmake -S . -B build-san -DNETSCOPE_ENABLE_ASAN=ON -DNETSCOPE_ENABLE_UBSAN=ON
cmake --build build-san
ctest --test-dir build-san --output-on-failure
```

Full details, including `clang-format`/`clang-tidy` usage and guidance for
adding a protocol parser, are in [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Roadmap

Not implemented, but reasonable next steps: IP fragment reassembly, TCP
stream tracking, Linux cooked capture (SLL), PCAPNG, and an optional
`--tui` mode.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Security

NetScope is a passive analyzer only -- see [`SECURITY.md`](SECURITY.md)
for the project's security scope, intent, and vulnerability reporting
process.

## License

[MIT](LICENSE)
