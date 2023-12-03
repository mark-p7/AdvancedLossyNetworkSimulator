import socket
import time
import sys
from ipaddress import ip_address, IPv4Address, IPv6Address
import os

MAX_MESSAGE_SIZE = 4294967295
SRC_IP_ADDRESS = sys.argv[1]
SRC_PORT = int(sys.argv[2])
DST_IP_ADDRESS = sys.argv[3]
DST_PORT = int(sys.argv[4])
SERVER_TIMEOUT = 0.5
STATIC_SEQ = 0
RESERVED_ACK = 4294967295

class Server:
    
    # Initialize the server
    def __init__(self) -> None:
        self.destination_port = 0
        self.packets = []
        self.decoded_packets = {}
        self.decoded_message = b""
        self.seq_numbers = []
        self.ack = 0
        self.seq = 0
        self.full_message_size = 0
        self.check_args()
        self.closing_connection = False
    
    # Validate the IP address
    # TODO: Make the ip_address_family a class variable so that server can create a socket with the correct IP address family passed in
    def validate_ip(self, ip: str):
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

    # Check the arguments
    def check_args(self):
        if len(sys.argv) != 5:
            print(
                "Usage: python3 server.py <source ipv4_addr or ipv6_addr> <source port> <destination ipv4_addr or ipv6_addr> <destination port>"
            )
            sys.exit(1)
        if self.validate_ip(sys.argv[1]) is False or self.validate_ip(sys.argv[3]) is False:
            print("Invalid IP address")
            sys.exit(1)
        if sys.argv[2].isnumeric() is False or sys.argv[4].isnumeric() is False:
            print("Port number must be numeric")
            sys.exit(1)
        if (int(sys.argv[2]) < 1024) or (int(sys.argv[2]) > 65535) or (int(sys.argv[4]) < 1024) or (int(sys.argv[4]) > 65535):
            print("Port number must be between 1024 and 65535")
            sys.exit(1)
            
    # Decode data
    def decode(self, data: bytes, type: str):
        if type == "utf-8":
            return data.decode("utf-8")
        if type == "big-endian":
            return int.from_bytes(data, "big")
        else:
            assert False, "Unknown data type"
    
    # Decapsulate the packet payload from the header
    def decapsulate(self, data: bytes):
        
        # if data is None:
        #     print("No data to decapsulate")
        
        # Header is 20 bytes long. 2 bytes for source port, 2 bytes for destination port, 2 bytes for size of data, 2 bytes for window size, 4 bytes for sequence number, 4 bytes for ack number, and 4 bytes for message size
        header = data[:20]
        payload = data[20:]
        return header, payload
    
    def extract_header_details(self, header: bytes):
        # Check if header is None
        # if header is None:
        #     print("No header to extract")
            
        # Extracting the header details
        # Header is 20 bytes long. 2 bytes for source port, 2 bytes for destination port, 2 bytes for size of data, 2 bytes for window size, 4 bytes for sequence number, 4 bytes for ack number, and 4 bytes for message size
        source_port = header[:2]
        destination_port = header[2:4]
        size_of_data = header[4:6]
        window_size = header[6:8]
        seq_num = header[8:12]
        ack_num = header[12:16]
        message_size = header[16:]
        
        # Decoding the header details
        source_port = self.decode(source_port, "big-endian")
        destination_port = self.decode(destination_port, "big-endian")
        size_of_data = self.decode(size_of_data, "big-endian")
        window_size = self.decode(window_size, "big-endian")
        seq_num = self.decode(seq_num, "big-endian")
        ack_num = self.decode(ack_num, "big-endian")
        message_size = self.decode(message_size, "big-endian")
        
        # Return the header details
        return source_port, destination_port, size_of_data, window_size, seq_num, ack_num, message_size
    
    # Decode the packet and store it in the decoded_packets dictionary
    def decode_packet(self, packet: bytes):
        
        # Decapsulate the packet
        header, payload = self.decapsulate(packet)
        
        # Extract the header details
        source_port, destination_port, size_of_data, window_size, seq_num, ack_num, message_size = self.extract_header_details(header)
        
        # Set the full message size
        self.full_message_size = message_size
        
        # If the sequence number is not in the sequence numbers list, add it to the list and decode the packet
        if seq_num not in self.seq_numbers:
            self.seq_numbers.append(seq_num)
            self.destination_port = source_port
            self.decoded_packets[seq_num] = { "destination_port": destination_port, "size_of_data": size_of_data, "window_size": window_size, "seq_num": seq_num, "ack_num": ack_num, "payload": payload}
    
    # Soft reset the server
    def soft_reset_server(self):
        self.packets = []
        self.seq_numbers = []
        self.decoded_packets = {}
        
    # Hard reset the server
    def hard_reset_server(self):
        self.packets = []
        self.seq_numbers = []
        self.decoded_packets = {}
        self.decoded_message = b""
        self.full_message_size = 0
    
    # Create the header
    def create_header(self, source_port: int, destination_port: int, size_of_data: int, window_size: int, seq_num: int, ack_num: int, message_size: int):
        header = (source_port.to_bytes(2, "big") + destination_port.to_bytes(2, "big")
                  + size_of_data.to_bytes(2, "big") + window_size.to_bytes(2, "big")
                  + seq_num.to_bytes(4, "big") + ack_num.to_bytes(4, "big")
                  + message_size.to_bytes(4, "big"))
        return header
    
    # Print the full message to stdout
    def print_full_message(self):
        decoded_message = self.decoded_message.decode("utf-8")
        print(decoded_message, end="")
    
    def start_server(self):
        
        # Create the server socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_sock:
            
            try:
                # Bind Socket
                server_sock.bind((SRC_IP_ADDRESS, SRC_PORT))
                
                # Logging
                # print("Server is listening...")
                
                # While the server is running
                while True:
                    
                    # Try to receive data from the client through the proxy or client
                    try:
                        # If the server is closing the connection, we can assume that the client may have already closed the connection
                        if self.closing_connection is True and server_sock.gettimeout() is None:
                            server_sock.settimeout(SERVER_TIMEOUT)
                            
                        # Receive data from the client through the proxy or client
                        data, addr = server_sock.recvfrom(1024)
                        
                        # Add the data to the packets list
                        self.packets.append(data)
                        
                        # If the server socket is not set to timeout, set it to timeout
                        if server_sock.gettimeout() is None:
                            server_sock.settimeout(SERVER_TIMEOUT)
                    
                    # When the server times out
                    except socket.timeout:
                        
                        # Assumed that the client has closed the connection, so we can close the server
                        if self.closing_connection is True:
                            break
                        
                        # Read the data and send an ACK back to the client through the proxy or client
                        for i in range(0, len(self.packets)):
                            self.decode_packet(self.packets[i])
                        
                        # Get the sequence numbers from the decoded packets in order
                        seq_nums = list(self.decoded_packets.keys())
                        seq_nums.sort()
                                            
                        # Send ACK back to the client through the proxy or client
                        ack_num = self.ack
                        for i in range(0, len(seq_nums)):
                            if seq_nums[i] == RESERVED_ACK:
                                ack_num = RESERVED_ACK
                                self.closing_connection = True
                            elif seq_nums[i] == ack_num:
                                # print(f"seq_num: {seq_nums[i]}, ack_num: {ack_num}")
                                ack_num += 1
                                self.decoded_message += self.decoded_packets[seq_nums[i]]["payload"]
                            else:
                                self.soft_reset_server()
                                break
                        
                        # TODO: Clarify if the server can take the client/proxy IP address from the command line.                        
                        self.ack = ack_num
                        header = self.create_header(SRC_PORT, self.destination_port, 0, 1, 0, ack_num, 0)
                        packet = header + b""
                        
                        # Log the ACK
                        with open ("server_log.txt", "a") as f:
                            f.write(f"Sending ACK to client\n")
                            f.write(f"ACK: {ack_num}\n")
                        
                        try:
                            # Send the ACK to the client through the proxy or client
                            server_sock.sendto(packet, (DST_IP_ADDRESS, int(DST_PORT)))
                        except Exception as e:
                            raise Exception("Connection Closed")
                        
                        # Check if the full message has been received
                        # TODO: Make ACK accurate to the data received so that we can change the >= operator to ==
                        # Right now the ACK also counts the extra padding that is added to the last packet
                        # The decoded_message also counts the extra padding that is added to the last packet
                        # print(f"ACK: {self.ack}")
                        # print(f"Full message size: {self.full_message_size}")
                        if self.ack * 1004 >= self.full_message_size:
                            # print("Full message received")
                            self.print_full_message()
                            self.hard_reset_server()
                            server_sock.settimeout(None)
                 
            except KeyboardInterrupt:
                pass
            except Exception as e:
                pass
                
if __name__ == "__main__":
    server = Server()
    server.start_server()
