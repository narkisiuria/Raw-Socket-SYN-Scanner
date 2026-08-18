import socket
import struct
import threading
import queue  

from send_SYN_request import send_syn
from build_IP_header import build_ip_header
from build_TCP_header import build_tcp_header
from checksum_func import get_checksum
from build_sniffer import sniffer_response
from port_state_byte_checker import get_port_state

port_queue = queue.Queue()
print_lock = threading.Lock()

def worker_scan(target_ip):
    while not port_queue.empty():
        try:
            port = port_queue.get_nowait()
        except queue.Empty:
            break
        
        sniff_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sniff_sock.settimeout(2)
        
        send_syn("192.168.7.10", target_ip, 4444, port)

        port_state = "unexpected port"
        while port_state == "unexpected port":            
            sniffer_sock_data = sniffer_response(sniff_sock)
            
            port_state = get_port_state(sniffer_sock_data, port)
        

        with print_lock:
            if port_state == "open":
                print(f"port {port}: OPEN") 
            elif port_state == "filtered":
                print(f"port {port}: FILTERED") 
            elif port_state == "closed":
                print(f"port {port}: CLOSED") 
            else:
                print(f"port {port}: UNKNOWN OR PORT ERROR") 
        
        port_queue.task_done()

def run():
    target_host = "192.168.56.104"

    for port in range(1, 500):
        port_queue.put(port)

    max_workers = 10
    threads = []
    
    for _ in range(max_workers):
        thread = threading.Thread(target=worker_scan, args=(target_host,))
        threads.append(thread)
        thread.start()  

    print(f"Main thread: {max_workers} worker threads deployed. Scanning...")

    for thread in threads:
        thread.join()  

    print("Main thread: All workers completed.")

if __name__ == "__main__":
    run()
