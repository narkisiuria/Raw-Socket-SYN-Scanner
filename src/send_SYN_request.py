import struct
from src.checksum_func import get_checksum
import socket
from src.build_TCP_header import build_tcp_header
from src.build_IP_header import build_ip_header

def send_syn(src_ip, dest_ip, src_port, dest_port):
    # On the IP layer, turn on the setting called IP_HDRINCL.
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    # IP_HDRINCL tells the OS: Don't build your own IP header
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    ip_header = build_ip_header(src_ip, dest_ip)
    tcp_header = build_tcp_header(src_port, dest_port, src_ip=src_ip, dest_ip=dest_ip)   
     
    packet = ip_header + tcp_header
    send_sock.sendto(packet, (dest_ip, 0))