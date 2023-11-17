import socket
import time
import sys
from ipaddress import ip_address, IPv4Address, IPv6Address
import os
import fileinput

MAX_MESSAGE_SIZE = 4294967295
SRC_IP_ADDRESS = sys.argv[1]
SRC_PORT = sys.argv[2]
DST_IP_ADDRESS = sys.argv[3]
DST_PORT = sys.argv[4]
CLIENT_TIMEOUT = 1
MAX_WINDOW_SIZE = 5
STATIC_ACK = 0

class Client:
    
    def __init__(self):
        self.ip_address_family = ""
        self.check_args()
        self.client_socket = socket.socket()
        self.receiving_socket = socket.socket()
        self.timeout = 0
        self.user_input = ""
        self.window_base = 0
        self.ack_num = 0
        self.chunks = []
        self.source_port = int(SRC_PORT)
        self.destination_port = int(DST_PORT)
        self.full_message_size = 0
    
    def validate_ip(self, ip: str):
        try:
            ip = ip_address(str(sys.argv[1]))
            if isinstance(ip, IPv4Address):
                self.ip_address_family = socket.AF_INET
            elif isinstance(ip, IPv6Address):
                self.ip_address_family = socket.AF_INET6
            else:
                return False
        except Exception as e:
            return False
            
    def check_args(self):
        if len(sys.argv) != 5:
            print(
                "Usage: python3 server.py <source ipv4_addr or ipv6_addr> <source port> <destination ipv4_addr or ipv6_addr> <destination port>"
            )
            sys.exit(1)
        if self.validate_ip(SRC_IP_ADDRESS) is False or self.validate_ip(DST_IP_ADDRESS) is False:
            print("Invalid IP address")
            sys.exit(1)
        if SRC_PORT.isnumeric() is False or DST_PORT.isnumeric() is False:
            print("Port number must be numeric")
            sys.exit(1)
        if (int(SRC_PORT) < 1024) or (int(SRC_PORT) > 65535) or (int(DST_PORT) < 1024) or (int(DST_PORT) > 65535):
            print("Port number must be between 1024 and 65535")
            sys.exit(1)

    def create_client_socket(self):
        # Create the client socket
        self.client_socket = socket.socket(self.ip_address_family, socket.SOCK_DGRAM)
    
    def bind_client_socket(self):
        # Set the client socket to 
        self.client_socket.bind((SRC_IP_ADDRESS, int(SRC_PORT)))
        
    def start_timeout(self):
        self.client_socket.settimeout(CLIENT_TIMEOUT)
    
    def wait_for_timeout(self):
        while time.time() - self.timeout < CLIENT_TIMEOUT:
            pass
    
    def take_user_input(self):
        for line in sys.stdin:
            self.user_input += line
        
    def create_header(self, seq_num: int, ack_num: int):
        size_of_data = len(self.chunks[seq_num])
        # Header is 20 bytes long. 2 bytes for source port, 2 bytes for destination port, 2 bytes for size of data, 2 bytes for window size, 4 bytes for sequence number, 4 bytes for ack number, and 4 bytes for message size
        header = self.source_port.to_bytes(2, "big") + self.destination_port.to_bytes(2, "big") + size_of_data.to_bytes(2, "big") + MAX_WINDOW_SIZE.to_bytes(2, "big") + seq_num.to_bytes(4, "big") + ack_num.to_bytes(4, "big") + self.full_message_size.to_bytes(4, "big")
        return header

    def start_client(self):
        
        # Create the client socket
        self.create_client_socket()
        
        # Bind the client socket to the source IP address and port
        self.bind_client_socket()
        
        # Take user input
        self.take_user_input()
        
        # Encode user input into bytes
        data_in_bytes = self.user_input.encode("utf-8")
        
        # Check if message size is too large
        if len(data_in_bytes) > MAX_MESSAGE_SIZE:
            print("Message size is too large")
            sys.exit(1)
        else:
            self.full_message_size = len(data_in_bytes)
            print(f"Message size is {len(data_in_bytes)} bytes")
            
        # Split data into 1004 byte chunks
        self.chunks = [data_in_bytes[i:i+1004] for i in range(0, len(data_in_bytes), 1004)]

        # While there are still chunks to send
        while self.window_base < len(self.chunks):
            try:
                # For each chunk in the current window
                for i in range(self.window_base, self.window_base + MAX_WINDOW_SIZE):
                    # Check if we have reached the end of the message (the last chunk has been sent from the current window)
                    if i < len(self.chunks):
                        # Create sequence number
                        seq_num = i
                        # Create ack number
                        ack_num = STATIC_ACK
                        # Create protocol header
                        header = self.create_header(seq_num, ack_num)
                        # Create packet
                        packet = header + self.chunks[i]
                        # Send packet
                        self.client_socket.sendto(packet, (DST_IP_ADDRESS, int(DST_PORT)))
                        # Log packet sent
                        print(f"Client sent chunk with seq num {seq_num}")
                
                # Start timeout
                self.start_timeout()
                
                while True:
                    
                    # Wait for ACK
                    packet, addr = self.client_socket.recvfrom(20)
                    
                    if packet is None:
                        continue
                    
                    # If ACK received, stop timeout
                    self.client_socket.settimeout(None)
                    
                    # Print packet
                    print(len(packet))
                    
                    # Extract ACK number from header
                    source_port = int.from_bytes(packet[0:2], "big")
                    destination_port = int.from_bytes(packet[2:4], "big")
                    size_of_data = int.from_bytes(packet[4:6], "big")
                    window_size = int.from_bytes(packet[6:8], "big")
                    ack_num = int.from_bytes(packet[8:12], "big")
                    seq_num = int.from_bytes(packet[12:16], "big")
                    message_size = int.from_bytes(packet[16:20], "big")
                    
                    # Log packet details
                    print(f"Source port: {source_port}\nDestination port: {destination_port}\nSize of data: {size_of_data}\nWindow size: {window_size}\nSequence number: {seq_num}\nACK number: {ack_num}\nMessage size: {message_size}")
                    
                    # Check if the ACK received is higher than the current window base
                    if ack_num > self.window_base:
                        # Slide window up to the ACK received
                        self.window_base = ack_num
                        print(f"Window base is {self.window_base}")
                        break
                    else:
                        # If the ACK received is not the ACK for the highest sequence number received in the current window, start timeout again
                        self.start_timeout()
                    
                    # Log window base
                    print(f"Window base is {self.window_base}")
                    
            # If timeout occurs, resend all packets in the current window
            except socket.timeout:
                
                # Log timeout
                print("Timeout occurred")
                
        # Finish sending all chunks
        print("Client finished sending all chunks") 

if __name__ == "__main__":
    client = Client()
    client.start_client()