# Raw Socket SYN Scanner

A TCP SYN scanner I built from scratch using raw sockets. No scapy, no packet libraries.

Every byte of the IP and TCP headers is packed by hand with `struct`, checksums included. I wanted to actually understand what a SYN scan is doing on the wire, not just call a function that does it for me.

## Why raw sockets instead of scapy

Scapy builds and sends packets for you. `socket.connect()` lets the OS handle everything. Both hide the actual protocol from you.

This project skips that. I had to:
- Pack IP and TCP headers manually
- Write the actual checksum algorithm (16-bit sum, wraparound, one's complement)
- Build a TCP pseudo-header just for the checksum
- Turn off the OS's own IP header with `IP_HDRINCL`
- Read raw bytes back and check the TCP flags myself

## How the scan works

A SYN scan never finishes the handshake. It just sends a SYN and reads what comes back:

- `SYN-ACK` back = port open
- `RST` back = port closed
- nothing back = probably filtered

This is basically what `nmap -sS` does under the hood.

## Files

- `checksum_func.py` — checksum algorithm
- `build_IP_header.py` — IP header
- `build_TCP_header.py` — TCP header + pseudo-header
- `send_SYN_request.py` — sends the packet over a raw socket
- `main.py` — runs the scan

## Requirements

Python 3, and root/admin (raw sockets need it). Only run this against machines you own or have permission to test.

## Status

Sending works. Still working on reading replies and scanning full port ranges.
