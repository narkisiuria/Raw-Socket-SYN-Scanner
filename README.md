# Raw Socket SYN Scanner

A TCP SYN port scanner built entirely from raw sockets. No scapy, no external packet libraries.

Every byte of the IP and TCP headers — including checksums — is hand-built with `struct.pack`, following RFC 791 (IP) and RFC 793 (TCP). Packets are sent and sniffed directly off the network interface.

## Why raw sockets

Most scanners either call `socket.connect()` (which lets the OS handle everything) or use a library like scapy (which builds and sends packets for you). This project skips both. The goal was to actually understand what a SYN scan does at the byte level — not just call a function that does it.

Building this required:
- Manually packing IP and TCP headers with `struct`
- Implementing the IP/TCP checksum algorithm (16-bit one's complement sum with carry wraparound)
- Building a TCP pseudo-header for checksum calculation
- Using `IP_HDRINCL` to bypass the OS's own header construction
- Reading raw reply bytes and parsing TCP flags manually to tell open, closed, and filtered ports apart

## How a SYN scan works

1. Send a TCP packet with only the SYN flag set (no full handshake)
2. `SYN-ACK` reply → port is **open**
3. `RST` reply → port is **closed**
4. No reply (timeout) → port is likely **filtered**

This is the same technique behind `nmap -sS`. Since the handshake never completes, it's harder to log than a full connection.

## Project structure

```
checksum_func.py     # IP/TCP checksum algorithm
build_IP_header.py   # Hand-packed IPv4 header
build_TCP_header.py  # Hand-packed TCP header + pseudo-header checksum
send_SYN_request.py  # Raw socket send logic (IP_HDRINCL)
main.py              # Scan orchestration
```

## Requirements

- Python 3
- Root/admin privileges (raw sockets require elevated permissions)
- Run only against systems you own or have explicit permission to test

## Status

Work in progress — sending is implemented. Reply sniffing and port-range scanning are in progress.
