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
MAX_WINDOW_SIZE = 2
STATIC_ACK = 0
RESERVED_SEQ = 4294967295
MAX_TERMINATION_REQUESTS = 20

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
        self.seq_num = 0
        self.full_chunks_size = 0
        self.chunks = []
        self.source_port = int(SRC_PORT)
        self.destination_port = int(DST_PORT)
        self.full_message_size = 0
        self.completed_chunks_size = 0
        self.connection_closed = False
    
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
        
    def stop_timeout(self):
        self.client_socket.settimeout(None)
    
    def wait_for_timeout(self):
        while time.time() - self.timeout < CLIENT_TIMEOUT:
            pass
    
    def take_user_input(self):
        for line in sys.stdin:
            self.user_input += line
        
    def create_header(self, seq_num: int, ack_num: int):
        size_of_data = 0
        if seq_num is not RESERVED_SEQ:
            size_of_data = len(self.chunks[seq_num - self.completed_chunks_size])
        # Header is 20 bytes long. 2 bytes for source port, 2 bytes for destination port, 2 bytes for size of data, 2 bytes for window size, 4 bytes for sequence number, 4 bytes for ack number, and 4 bytes for message size
        header = self.source_port.to_bytes(2, "big") + self.destination_port.to_bytes(2, "big") + size_of_data.to_bytes(2, "big") + MAX_WINDOW_SIZE.to_bytes(2, "big") + seq_num.to_bytes(4, "big") + ack_num.to_bytes(4, "big") + self.full_message_size.to_bytes(4, "big")
        return header

    def slide_window(self, ack_num: int):
        # Slide window up to the ACK received
        print(f"Sliding window up to {ack_num}")
        self.window_base = ack_num
        self.seq_num = ack_num
        print(f"Window base is {self.window_base}")
    
    def send_data(self, i):
        # Create sequence number
        seq_num = i
        # Create ack number
        ack_num = STATIC_ACK
        # Create protocol header
        header = self.create_header(seq_num, ack_num)
        # Create packet
        packet = header + self.chunks[i - self.completed_chunks_size]
        # Log packet sequence number
        print(f"Packet sequence number is {seq_num}")
        # Send packet
        self.client_socket.sendto(packet, (DST_IP_ADDRESS, int(DST_PORT)))
        # Log packet sent
        print(f"Client sent chunk with seq num {seq_num}")
    
    def check_data_size(self, data):
        if len(data) > MAX_MESSAGE_SIZE:
            print("Message size is too large")
            raise Exception("Message size is too large")
        else:
            self.full_message_size = len(data)
            print(f"Message size is {len(data)} bytes")
    
    def process_data_to_send(self, line):
        # Get user input
        self.user_input = line
        
        # Encode user input into bytes
        data_in_bytes = self.user_input.encode("utf-8")
        
        # Check if message size is too large
        self.check_data_size(data_in_bytes)
            
        # Split data into 1004 byte chunks
        self.chunks = [data_in_bytes[i:i+1004] for i in range(0, len(data_in_bytes), 1004)]

        # Add length of new message to the current length of total packets sent
        self.full_chunks_size += len(self.chunks)
        
        # Log chunks
        print("Window Base is:", self.window_base)
        print("Full Chunk Size is:", self.full_chunks_size)

    def hard_reset_client(self):
        self.completed_chunks_size += len(self.chunks)
        self.chunks = []
        self.full_message_size = 0
        
    def terminate_connection(self):
        print("Terminating connection")
        header = self.create_header(RESERVED_SEQ, STATIC_ACK)
        packet = header + b""
        termination_requests = 0
        while self.connection_closed is False:
            try:
                self.client_socket.sendto(packet, (DST_IP_ADDRESS, int(DST_PORT)))
                self.receive_ack()
            except socket.timeout:
                termination_requests += 1
                # We can assume that the server has terminated the connection if we have sent over 20 termination requests with no response
                if termination_requests == MAX_TERMINATION_REQUESTS:
                    self.connection_closed = True
                pass
        print("Connection terminated")
        self.client_socket.close()
        time.sleep(1)
        sys.exit(1)
        
    def receive_ack(self):
        # Start timeout
        self.start_timeout()
        
        # Wait for ACK
        packet, addr = self.client_socket.recvfrom(20)
        
        # Stop timeout
        self.stop_timeout()
        
        if packet is None:
            return None
        
        # Extract ACK number from header
        ack_num = int.from_bytes(packet[12:16], "big")

        # Close connection if termination ACK received
        if ack_num == RESERVED_SEQ:
            print("Received termination ACK")
            self.connection_closed = True
        
        return ack_num

    def start_client(self):
        
        # Create the client socket
        self.create_client_socket()
        
        # Bind the client socket to the source IP address and port
        self.bind_client_socket()
        
        # # Take user input
        # self.take_user_input()
        try:
            for line in sys.stdin:
                self.process_data_to_send(line)
                
                # While there are still chunks to send
                while self.window_base < self.full_chunks_size:
                    try:
                            
                        # For each chunk in the current window
                        for i in range(self.window_base, self.window_base + MAX_WINDOW_SIZE):
                            # Check if we have reached the end of the message (the last chunk has been sent from the current window)
                            # print(f"i is {i}")
                            # print(f"completed chunks size is {self.completed_chunks_size}")
                            # print(f"len of chunks is {len(self.chunks)}")
                            # print(i - self.completed_chunks_size < len(self.chunks))
                            
                            if i - self.completed_chunks_size < len(self.chunks):
                                self.send_data(i)
                        
                        while True:
                            ack_num = self.receive_ack()
                            print(f"Received ACK: {ack_num}")
                            # Check if the ACK received accounts for all packets in the current window
                            print(f"Old Window base is: {self.window_base}")
                            print(f"New Ack num is: {ack_num}")
                            if ack_num >= self.window_base:
                                self.slide_window(ack_num)
                                break
                            
                            # Log window base
                            print(f"New Window base is: {self.window_base}")
                            
                    # If timeout occurs, resend all packets in the current window
                    except socket.timeout:
                        
                        # Log timeout
                        print("Timeout occurred")

                # Done sending all chunks in the message
                print("Done sending all chunks in the message\n")
                self.hard_reset_client()
            
            # Done sending all messages
            self.terminate_connection()

        except KeyboardInterrupt:
            if self.connection_closed is False:
                self.terminate_connection()
            else:
                print("Keyboard interrupt received")
                self.client_socket.close()
                time.sleep(1)
                sys.exit(0)
            
        except Exception as e:
            if self.connection_closed is False:
                self.terminate_connection()
            else:
                print(e)
                self.client_socket.close()
                time.sleep(1)
                sys.exit(0)

if __name__ == "__main__":
    client = Client()
    client.start_client()