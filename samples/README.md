# Samples

This directory is intentionally empty of `.pcap` files.

NetScope's automated tests (`tests/`) exercise every protocol parser
against synthetic byte arrays defined directly in the test source, not
against committed capture files -- see `docs/packet-parsing.md` and the
`tests/test_*.c` files for the specific packets used.

If you want to generate a local `.pcap` fixture for manual testing (e.g.
with `netscope -r`), create one with synthetic traffic only:

```bash
# Capture a few packets of your own loopback DNS traffic:
sudo tcpdump -i lo0 -w samples/local-dns.pcap port 53 -c 20

# Or synthesize one entirely offline with scapy, no live traffic involved.
```

Do not commit real network captures here -- they can contain private
addresses, hostnames, or payload data. `samples/*.pcap` is ignored by
`.gitignore` for exactly this reason.
