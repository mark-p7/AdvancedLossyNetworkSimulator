import socket
import time
import sys
from ipaddress import ip_address, IPv4Address, IPv6Address
import os
import fileinput

SRC_IP_ADDRESS = sys.argv[1]
SRC_PORT = sys.argv[2]
DST_IP_ADDRESS = sys.argv[3]
DST_PORT = sys.argv[4]
CLIENT_TIMEOUT = 1
MAX_WINDOW_SIZE = 5
STATIC_ACK = 0

class Client:
    
    def __init__(self):
        self.client_socket = socket.socket()
        self.receiving_socket = socket.socket()
        self.ip_address_family = ""
        self.timeout = 0
        self.user_input = ""
        self.window_base = 0
        self.ack_num = 0
        self.chunks = []
        self.check_args()
    
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
        self.timeout = time.time()
    
    def wait_for_timeout(self):
        while time.time() - self.timeout < CLIENT_TIMEOUT:
            pass
    
    def take_user_input(self):
        self.user_input = input("Please enter the message:\n")
        print("done")
        
    def create_header(self, seq_num, ack_num):
        size_of_data = len(self.chunks[seq_num])
        # Header is 12 bytes long. The first 2 bytes is the size of data, the second 2 bytes is the window size, the next 4 bytes is the seq num, and the last 4 bytes is the ACK num
        header = size_of_data.to_bytes(2, "big") + MAX_WINDOW_SIZE.to_bytes(2, "big") + seq_num.to_bytes(4, "big") + ack_num.to_bytes(4, "big")
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
        
        # Split data into 12 byte chunks
        self.chunks = [data_in_bytes[i:i+12] for i in range(0, len(data_in_bytes), 12)]
        # self.chunks = [data_in_bytes[i:i+1012] for i in range(0, len(data_in_bytes), 1012)]

        # While there are still chunks to send
        while self.window_base < len(self.chunks):
            # For each chunk in the current window
            for i in range(self.window_base, self.window_base + MAX_WINDOW_SIZE):
                # Check if we have reached the end of the message (the last chunk has been sent from the current window)
                if i < len(self.chunks):
                    # Create sequence number
                    seq_num = i * 12
                    # Create ack number
                    ack_num = STATIC_ACK
                    # Create protocol header
                    header = self.create_header(seq_num, ack_num)
                    # Create packet
                    packet = header + self.chunks[i]
                    # Send packet
                    self.client_socket.sendto(packet, (DST_IP_ADDRESS, DST_PORT))
                    # Log packet sent
                    print(f"Client sent chunk with seq num {seq_num}")
            self.start_timeout()
            for i in range(MAX_WINDOW_SIZE):
                # Receive packet
                packet, _ = self.client_socket.recvfrom(12)
                # Extract ack number from packet header
                ack_num = int.from_bytes(packet[8:], "big")
                # Log ack received
                print(f"Client received ACK for seq num {ack_num}")
                # Slide window
                while (ack_num / 24) > self.window_base:
                    self.window_base = ack_num + 1
            
if __name__ == "__main__":
    client = Client()
    client.start_client()