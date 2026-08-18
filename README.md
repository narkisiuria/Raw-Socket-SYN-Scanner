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
- `build_sniffer.py` — listens for the reply
- `port_state_byte_checker.py` — parses the reply and figures out open/closed/filtered
- `main.py` — runs the scan across a port range with worker threads

## Requirements

Python 3, and root/admin (raw sockets need it). Only run this against machines you own or have permission to test.

Note: raw sockets don't work reliably through WSL2, even in mirrored networking mode — replies from outside the host often never make it back to WSL. Run this from a real Linux machine or a VM with a bridged network adapter.

## Known limitation

Scanning runs on multiple threads for speed, but each thread opens its own listening socket without filtering by source port until the reply comes back. Under high thread counts, it's possible for one thread to pick up another thread's reply. Results have been consistent in testing, but this hasn't been formally fixed.

## Status

Working end to end. Verified against a real target — correctly identified open ports (53, 80) and closed ports (135, 139, 137) matching nmap's results.
