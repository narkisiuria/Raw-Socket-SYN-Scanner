import struct

def get_port_state(data, expected_port):
    if data == "filtered":
        return "filtered"
    
    tcp_header = data[20:40]
    tcp_header = struct.unpack("!HHIIBBHHH", tcp_header)
    
    if tcp_header[0] != expected_port:
        return "unexpected port"
    
    if tcp_header[5] & 0x12 == 0x12:
        return "open"
    
    if tcp_header[5] & 0x04 == 0x04:
        return "closed"

    return "unknown"