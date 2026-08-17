import socket
import struct
from send_SYN_request import send_syn
from build_IP_header import build_ip_header
from build_TCP_header import build_tcp_header
from checksum_func import get_checksum

def get_checksum(raw_bytes: bytes):
    if len(raw_bytes) % 2 != 0:
        raw_bytes += b'\x00'
    
    total = 0
    for i in range(0, len(raw_bytes), 2):
        byte1 = raw_bytes[i]
        byte2 = raw_bytes[i+1]
        
        combined = (byte1 << 8) + byte2
        total += combined
        if total > 0xFFFF:
            total = (total & 0xFFFF) + (total >> 16)

    checksum = ~total & 0xFFFF
    
    return checksum

def build_ip_header(src_ip, dest_ip):
    network_bytes_packed = struct.pack('!BBHHHBBH4s4s', 69, 0, 40, 54321, 0, 64, 6, 0, socket.inet_aton(src_ip), socket.inet_aton(dest_ip))
    checksum = get_checksum(network_bytes_packed)
    network_bytes_packed = struct.pack('!BBHHHBBH4s4s', 69, 0, 40, 54321, 0, 64, 6, checksum, socket.inet_aton(src_ip), socket.inet_aton(dest_ip))
    return network_bytes_packed

def build_tcp_header(src_port, dest_port, src_ip, dest_ip):
    network_bytes_packed = struct.pack('!HHIIBBHHH', src_port, dest_port, 0, 0, 80, 2, 8192, 0, 0)
    pseudo_header = struct.pack("!4s4sBBH", socket.inet_aton(src_ip), socket.inet_aton(dest_ip), 0, 6, 20)
    combined = pseudo_header + network_bytes_packed
    checksum = get_checksum(combined)
    network_bytes_packed = struct.pack('!HHIIBBHHH', src_port, dest_port, 0, 0, 80, 2, 8192, checksum, 0,)
    return network_bytes_packed

def send_syn(src_ip, dest_ip, src_port, dest_port):
    # On the IP layer, turn on the setting called IP_HDRINCL.
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    # IP_HDRINCL tells the OS: Don't build your own IP header
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    ip_header = build_ip_header(src_ip, dest_ip)
    tcp_header = build_tcp_header(src_port, dest_port, src_ip=src_ip, dest_ip=dest_ip)   
     
    packet = ip_header + tcp_header
    send_sock.sendto(packet, (dest_ip, 0))