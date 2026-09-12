# Security Policy

## Scope and intent

NetScope is a **passive** network traffic analyzer intended for learning,
diagnostics, and analyzing traffic on networks you own or are authorized to
monitor. It does not include, and will not accept contributions adding,
active attack functionality (ARP spoofing, packet injection, deauthentication,
credential capture, exploit delivery, MITM tooling, etc.). See `README.md`
for the full statement of intent.

## Attack surface

The realistic attack surface is **untrusted packet bytes**: a malicious or
malformed packet -- captured live, or read from a `.pcap` file -- that
triggers a memory-safety bug (out-of-bounds read, integer overflow, a crash
via a malformed length or DNS compression pointer, etc.) while being parsed.
`docs/packet-parsing.md` documents the specific defenses in place
(bounds-checked reads, DNS compression pointer/jump limits, fragment
handling) precisely because this is the code path most worth auditing.

## Reporting a vulnerability

Please report suspected vulnerabilities (a crash, memory-safety bug, or
hang triggerable by a crafted packet or capture file) via GitHub's private
[Security Advisories](../../security/advisories) for this repository,
rather than a public issue. Include:

* the input that triggers it (a minimal `.pcap` or byte sequence, if
  possible),
* the command line used,
* build configuration (OS, compiler, whether sanitizers were enabled).

There is no bug bounty; this is a portfolio/educational project maintained
on a best-effort basis. Reports are still appreciated and will be credited
in `CHANGELOG.md` once fixed, unless you'd prefer otherwise.

## What is *not* a security issue here

Live capture typically requiring elevated privileges (root, or
`cap_net_raw`/`cap_net_admin` on Linux) is expected libpcap behavior, not a
NetScope vulnerability -- see the Permissions section of `README.md`.
