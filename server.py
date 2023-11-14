import socket
import time
import sys
from ipaddress import ip_address, IPv4Address, IPv6Address
import os

SRC_IP_ADDRESS = sys.argv[1]
SRC_PORT = int(sys.argv[2])
DST_IP_ADDRESS = sys.argv[3]
DST_PORT = int(sys.argv[4])

def validate_ip(ip: str):
    try:
        ip = ip_address(str(sys.argv[1]))
        if isinstance(ip, IPv4Address):
            ip_address_family = "IPv4"
        elif isinstance(ip, IPv6Address):
            ip_address_family = "IPv6"
        else:
            return False
    except Exception as e:
        return False
        
if len(sys.argv) != 5:
    print(
        "Usage: python3 server.py <source ipv4_addr or ipv6_addr> <source port> <destination ipv4_addr or ipv6_addr> <destination port>"
    )
    sys.exit(1)
if validate_ip(sys.argv[1]) is False or validate_ip(sys.argv[3]) is False:
    print("Invalid IP address")
    sys.exit(1)
if sys.argv[2].isnumeric() is False or sys.argv[4].isnumeric() is False:
    print("Port number must be numeric")
    sys.exit(1)
if (int(sys.argv[2]) < 1024) or (int(sys.argv[2]) > 65535) or (int(sys.argv[4]) < 1024) or (int(sys.argv[4]) > 65535):
    print("Port number must be between 1024 and 65535")
    sys.exit(1)

# Decode data
def decode(data, type):
    if type == "utf-8":
        return data.decode("utf-8")
    if type == "big-endian":
        return int.from_bytes(data, "big")
    else:
        assert False, "Unknown data type"

# Extract data
def extract(data: bytes, size: int):
    print("Extracting data...")
    if data is None:
        print("No data to extract")
    if size is None:
        print("No size to extract")
    extracted_data = data[:size]
    remaining_data = b""
    if len(data) > size:
        remaining_data = data[size:]
    return extracted_data, remaining_data
    
def server():
    
    # Define local variables
    ip_address_family = ""
    current_ack = 0
    decoded_data = ""
    
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_sock:
        server_sock.bind((SRC_IP_ADDRESS, SRC_PORT))
        
        while True:
            data, addr = server_sock.recvfrom(1024)
            ack, data = extract(data, 4)
            ack = decode(ack, "big-endian")
            print(ack)
            if ack > current_ack and ack + current_ack < 1024:
                current_ack = ack
                decoded_data += decode(data, "utf-8")
            print(f"Server received: {data.decode()}")
            # Sending ACK back to the client through the proxy
            server_sock.sendto(ack.to_bytes(4, byteorder="big"), (DST_IP_ADDRESS, DST_PORT))
            
if __name__ == "__main__":
    server()