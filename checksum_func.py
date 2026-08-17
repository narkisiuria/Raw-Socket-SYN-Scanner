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