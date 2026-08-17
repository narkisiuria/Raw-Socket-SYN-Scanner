import struct
from checksum_func import get_checksum
import socket

def build_tcp_header(src_port, dest_port, src_ip, dest_ip):
    network_bytes_packed = struct.pack('!HHIIBBHHH', src_port, dest_port, 0, 0, 80, 2, 8192, 0, 0)
    pseudo_header = struct.pack("!4s4sBBH", socket.inet_aton(src_ip), socket.inet_aton(dest_ip), 0, 6, 20)
    combined = pseudo_header + network_bytes_packed
    checksum = get_checksum(combined)
    network_bytes_packed = struct.pack('!HHIIBBHHH', src_port, dest_port, 0, 0, 80, 2, 8192, checksum, 0,)
    return 