# Build Log

Notes on how this scanner actually got built, including the parts that broke.

## 1. Checksum

The IP/TCP checksum is a 16-bit one's complement sum. Bytes get grouped into 16-bit chunks, added together, overflow gets wrapped back into the low 16 bits, then the whole thing gets bit-flipped at the end.

## 2. IP header

20 bytes, packed with `struct.pack('!BBHHHBBH4s4s', ...)`. Built once with checksum set to 0, ran the checksum function on that, then packed again with the real checksum.

## 3. TCP header

Same idea, but the checksum needs a "pseudo header" first — a throwaway combo of source IP, dest IP, protocol, and TCP length, glued in front of the real TCP header just for the checksum math, then discarded.

## 4. Sending

Raw socket with `IP_HDRINCL` set, so the OS doesn't try to build its own IP header on top of the one already built by hand.

## 5. Listening

A second raw socket, no `IP_HDRINCL` needed since it's just reading. Added a timeout so a non-responsive port doesn't hang the scanner forever — timeout gets treated as "filtered."

## 6. Parsing the reply

Slice out the TCP header from the reply, unpack it, check the flags byte for SYN+ACK (open) or RST (closed).

## 7. Debugging: everything showed "filtered"

This took the longest. In order, ruled out:

- **Timing bug** — the sniffer socket was being opened *after* `send_syn()` returned. On localhost, replies come back faster than Python could open a new socket, so the reply was missed entirely. Fixed by opening the sniffer socket before sending.
- **Windows Firewall** — tested with it fully off. No change, ruled out.
- **WSL2 mirrored networking** — confirmed with `tcpdump` that outgoing SYN packets were leaving correctly, but no replies were ever arriving at the OS level, not just in Python. This turned out to be a real WSL2 limitation — even in mirrored networking mode, unsolicited replies from outside the host often don't get forwarded down into WSL's virtual network stack.
- **Fix** — moved to a Kali VM with a bridged network adapter instead of host-only or NAT. Bridged gives the VM a real IP on the actual LAN, no virtualization layer sitting in between.

## 8. Sniffing your own outgoing packet

On a shared interface, the raw listening socket sees all TCP traffic, including the SYN you just sent yourself. Fixed by checking that the reply's source port matches the port that was actually scanned, and looping the read again if not.

## 9. Threading

Added a queue + worker threads to scan multiple ports at once instead of one at a time. Known open issue: each thread's listening socket isn't isolated by source port until a reply comes in, so under heavy thread counts there's a theoretical chance one thread grabs another thread's reply. Testing at various thread counts hasn't produced a wrong result so far, but this hasn't been formally fixed.
