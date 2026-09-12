# Usage

## Live capture

```bash
sudo netscope -i en0        # macOS
sudo netscope -i eth0       # Linux
```

Live capture almost always needs elevated privileges to open a raw socket;
see [Permissions](../README.md#permissions) in the README for
alternatives to running as root.

Press `Ctrl+C` to stop. NetScope stops the capture, flushes any open output
file, closes libpcap handles, prints a statistics summary, and exits with
status 0.

## Reading a capture file

```bash
netscope -r capture.pcap
```

Reading a file uses the exact same parsing and output code as live capture
(see `docs/architecture.md`), so every filter and output option below works
identically with `-r` as with `-i`.

## Listing interfaces

```bash
netscope --list-interfaces
```

## Filtering

Simplified flags are translated into a BPF expression and applied at the
capture level (via `pcap_setfilter`), so filtered-out packets are never
even handed to the parser:

```bash
netscope -i en0 --tcp
netscope -i en0 --udp
netscope -i en0 --icmp
netscope -i en0 --port 443
netscope -i en0 --host 192.168.1.10
netscope -i en0 --src 192.168.1.10
netscope -i en0 --dst 8.8.8.8
```

Multiple simplified flags combine with AND (e.g. `--tcp --port 443` means
"TCP *and* port 443"). For anything the simplified flags cannot express,
pass a raw BPF expression instead -- it is mutually exclusive with the
simplified flags, to avoid ambiguity about how they would combine:

```bash
netscope -i en0 --filter "tcp port 443 and host 1.1.1.1"
```

## Output controls

```bash
netscope -i en0 --no-color   # disable ANSI colors (auto-disabled on non-TTY output too)
netscope -i en0 --verbose    # print a field-by-field block after each packet's summary line
netscope -i en0 --quiet      # suppress per-packet output (e.g. when only --stats is wanted)
netscope -i en0 --stats      # print the traffic-statistics summary when capture ends
netscope -i en0 --hex        # print a hex+ASCII dump of each packet
```

## Diagnostics vs. packet detail

`--verbose` (above) and `-v`/`-vv`/`--debug` are unrelated, on purpose:
`--verbose` controls how much detail is printed *per packet* (the compact
line vs. the field-by-field block), while `-v`/`-vv`/`--debug` raise
NetScope's own internal log level (`WARN` by default, then `INFO`, then
`DEBUG`) for diagnostics like the interface's detected datalink type --
independent of whether `--verbose` is set.

```bash
netscope -i en0 -vv          # or --debug: internal diagnostics on stderr
```

## JSON output

NetScope supports two ways to get JSON that could seem ambiguous together
(`--json` vs. `--json <file>`), so it instead uses one explicit pair of
flags:

```bash
netscope -i en0 --format json                       # JSON Lines to stdout
netscope -i en0 --format json --output packets.json  # JSON Lines to a file
```

Output is [JSON Lines](https://jsonlines.org/) -- one compact JSON object
per packet -- rather than a single JSON array, so NetScope never has to
hold the whole capture in memory to produce valid output.

## Saving a capture

```bash
netscope -i en0 --write output.pcap
```

Writes every packet (after filtering) to a standard pcap file via
libpcap's dump API, readable by Wireshark or tcpdump.

## Combining flags

```bash
netscope -r capture.pcap --tcp --port 443 --format json --output packets.json
```
