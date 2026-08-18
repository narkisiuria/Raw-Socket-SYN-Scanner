import socket

def sniffer_response(sock):    
    try:
        data, addr = sock.recvfrom(65535)
    except socket.timeout:
        return "filtered"
    
    return data