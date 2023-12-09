import socket
import threading
import time
import sys
from ipaddress import ip_address, IPv4Address, IPv6Address

MAX_MESSAGE_SIZE = 4294967295
SRC_IP_ADDRESS = sys.argv[1]
SRC_PORT = sys.argv[2]
DST_IP_ADDRESS = sys.argv[3]
DST_PORT = sys.argv[4]
CLIENT_TIMEOUT = 1
MAX_WINDOW_SIZE = 3
STATIC_ACK = 0
RESERVED_SEQ = 4294967295
MAX_TERMINATION_REQUESTS = 15
MAX_TIMEOUT_REQUESTS = 15
RESERVED_PACKETS_SENT = 4294967295

class Client:
    
    def __init__(self):
        self.ip_address_family = ""
        self.check_args()
        self.client_socket = socket.socket()
        self.timeout_requests = 0
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
        
        # GUI variables
        self.start_time = time.time()
        threading.Thread(target=self.log).start()
        self.packets_sent = 0
        self.packets_received = 0

    def log(self):
        gui_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            gui_socket.connect(("10.2.121.144", 7785))
        except Exception as e:
            return
        gui_socket_open = True
        while self.connection_closed is False:
            try:
                packets_sent = int(self.packets_sent).to_bytes(4, "big")
                packets_received = int(self.packets_received).to_bytes(4, "big")
                current_time = int(time.time() - self.start_time).to_bytes(4, "big")
                gui_socket.send(b"" + packets_sent + packets_received + current_time)
                time.sleep(0.5)
            except Exception as e:
                print("GUI disconnected")
                gui_socket_open = False
                break
        if gui_socket_open is True:
            gui_socket.send(b"" + RESERVED_PACKETS_SENT.to_bytes(4, "big") + (0).to_bytes(4, "big") + (0).to_bytes(4, "big"))
        time.sleep(0.2)
        gui_socket.close()
        time.sleep(1)
    
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
        # Increment packets sent
        self.packets_sent += 1
        # Increment current requests
        self.timeout_requests += 1
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
                self.packets_sent += 1
                self.receive_ack()
            except socket.timeout:
                termination_requests += 1
                # We can assume that the server has terminated the connection if we have sent over 20 termination requests with no response
                if termination_requests == MAX_TERMINATION_REQUESTS:
                    self.connection_closed = True
        print("Connection terminated")
        self.client_socket.close()
        time.sleep(3)
        sys.exit(1)
        
    def receive_ack(self):
        # Start timeout
        self.start_timeout()
        
        # Wait for ACK
        packet, addr = self.client_socket.recvfrom(20)
        
        # Stop timeout
        self.stop_timeout()
        
        # Increment packets received
        self.packets_received += 1
        
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
                            
                            if i - self.completed_chunks_size < len(self.chunks):
                                self.send_data(i)
                        
                        while True:
                            ack_num = self.receive_ack()
                            print(f"Received ACK: {ack_num}")
                            # Check if the ACK received accounts for all packets in the current window
                            print(f"Old Window base is: {self.window_base}")
                            print(f"New Ack num is: {ack_num}")
                            if ack_num >= self.window_base:
                                self.timeout_requests = 0
                                self.slide_window(ack_num)
                                break
                            
                            # Log window base
                            print(f"New Window base is: {self.window_base}")
                            
                    # If timeout occurs, resend all packets in the current window
                    except socket.timeout:
                        
                        if self.timeout_requests > MAX_TIMEOUT_REQUESTS:
                            raise Exception("Server not responding")
                        
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
            print(e)
            if self.connection_closed is False:
                self.terminate_connection()
            else:
                self.client_socket.close()
                time.sleep(1)
                sys.exit(0)

if __name__ == "__main__":
    client = Client()
    client.start_client()