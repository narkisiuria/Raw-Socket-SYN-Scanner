import struct
from src.checksum_func import get_checksum
import socket

def build_ip_header(src_ip, dest_ip):
    network_bytes_packed = struct.pack('!BBHHHBBH4s4s', 69, 0, 40, 54321, 0, 64, 6, 0, socket.inet_aton(src_ip), socket.inet_aton(dest_ip))
    checksum = get_checksum(network_bytes_packed)
    network_bytes_packed = struct.pack('!BBHHHBBH4s4s', 69, 0, 40, 54321, 0, 64, 6, checksum, socket.inet_aton(src_ip), socket.inet_aton(dest_ip))
    return network_bytes_packed