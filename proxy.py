import socket
import time
import sys
from ipaddress import ip_address, IPv4Address, IPv6Address
import random
import threading

SRC_IP_ADDRESS = sys.argv[1]
PORT_LISTEN = int(sys.argv[2])
PORT_SEND = int(sys.argv[3])
SERVER_IP_ADDRESS = sys.argv[4]
SERVER_PORT = int(sys.argv[5])
DELAY_TIME = 0.1

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


def check_args():
    if len(sys.argv) != 6:
        print(
            "Usage: python3 proxy.py <source ipv4_addr or ipv6_addr> <source port>" +
            "<server ipv4_addr or ipv6_addr> <server port>"
        )
        sys.exit(1)
    if validate_ip(sys.argv[1]) is False or validate_ip(sys.argv[4]) is False:
        print("Invalid IP address")
        sys.exit(1)
    if (sys.argv[2].isnumeric() is False or sys.argv[3].isnumeric() is False or sys.argv[5].isnumeric() is False):
        print("Port number must be numeric")
        sys.exit(1)
    if (((int(sys.argv[2]) < 1024) or (int(sys.argv[2]) > 65535)
         or (int(sys.argv[3]) < 1024) or (int(sys.argv[3]) > 65535)
         or (int(sys.argv[5]) < 1024) or (int(sys.argv[5]) > 65535))):
        print("Port number must be between 1024 and 65535")
        sys.exit(1)
        
def check_user_input(drop_percentage, delay_percentage):
    if drop_percentage.isnumeric() is False or delay_percentage.isnumeric() is False:
        print("Percentage must be numeric")
        sys.exit(1)
    if int(drop_percentage) < 0 or int(drop_percentage) > 100 or int(delay_percentage) < 0 or int(delay_percentage) > 100:
        print("Percentage must be between 0 and 100")
        sys.exit(1)
    
class BufferedPacket:
    def __init__(self, time_to_send, packet, destination):
        self.time_to_send = time_to_send
        self.packet = packet
        self.destination = destination

class Proxy:

    def __init__(self):
        
        # Get user input
        packet_drop_percentage = input("Enter packet drop percentage (example input for 60% -> 60): ")
        packet_delay_percentage = input("Enter packet delay percentage: ")
        ack_drop_percentage = input("Enter ack drop percentage: ")
        ack_delay_percentage = input("Enter ack delay percentage: ")
        
        # Check user input
        check_user_input(packet_drop_percentage, packet_delay_percentage)
        check_user_input(ack_drop_percentage, ack_delay_percentage)
        
        # Initialize user input class variables
        self.packet_drop_percentage = int(packet_drop_percentage) / 100
        self.packet_delay_percentage = int(packet_delay_percentage) / 100
        self.ack_drop_percentage = int(ack_drop_percentage) / 100
        self.ack_delay_percentage = int(ack_delay_percentage) / 100
        
        # Initialize class variables
        self.buffered_packets: [BufferedPacket] = []
        self.proxy_closing = False
        threading.Thread(target=self.thread_delay_packet).start()
        
        # GUI variables
        self.start_time = time.time()
        threading.Thread(target=self.log).start()
        self.packets_delayed = 0
        self.packets_dropped = 0
        self.acks_delayed = 0
        self.acks_dropped = 0
        
        # Check arguments then initialize ip addresses and ports
        check_args()
        self.client_ip_address = None
        self.client_port = None
        self.server_ip_address = sys.argv[4]
        self.server_port = int(sys.argv[5])
    
    def log(self):
        gui_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            gui_socket.connect(("10.2.121.144", 7787))
        except Exception as e:
            print(e)
            return
        while self.proxy_closing is False:
            try:
                packets_dropped = int(self.packets_dropped).to_bytes(4, "big")
                packets_delayed = int(self.packets_delayed).to_bytes(4, "big")
                acks_dropped = int(self.acks_dropped).to_bytes(4, "big")
                acks_delayed = int(self.acks_delayed).to_bytes(4, "big")
                current_time = int(time.time() - self.start_time).to_bytes(4, "big")
                gui_socket.send(b"" + packets_dropped + packets_delayed + acks_dropped + acks_delayed + current_time)
                time.sleep(0.5)
            except Exception as e:
                print("GUI disconnected")
                break
        gui_socket.close()
        time.sleep(1)

    def decode(self, data: bytes, data_type: str):
        if data_type == "utf-8":
            return data.decode("utf-8")
        if data_type == "big-endian":
            return int.from_bytes(data, "big")
        else:
            assert False, "Unknown data type"
        
    def change_packet_source_port(self, packet: bytes):
        packet = PORT_LISTEN.to_bytes(2, "big") + packet[2:]
        self.extract_packet_information(packet, "send")
        return packet
        
    def thread_delay_packet(self):
        while self.proxy_closing is False:
            if len(self.buffered_packets) > 0:
                if self.buffered_packets[0].time_to_send <= time.time():
                    
                    packet: BufferedPacket = self.buffered_packets.pop(0)
                    try:
                        if packet.destination == "client":
                            self.change_packet_source_port(packet.packet)
                            self.proxy_sock_send.sendto(packet.packet, (self.client_ip_address, self.client_port))
                            print("Sent delayed packet to client")
                        else:
                            self.change_packet_source_port(packet.packet)
                            self.proxy_sock_send.sendto(packet.packet, (SERVER_IP_ADDRESS, SERVER_PORT))
                            print("Sent delayed packet to server")
                    except Exception as e:
                        break
            else:
                time.sleep(0.01)

    def extract_packet_information(self, packet, status="recv"):
        # Extracting the packet details
        source_port = packet[:2]
        destination_port = packet[2:4]
        size_of_data = packet[4:6]
        window_size = packet[6:8]
        seq_num = packet[8:12]
        ack_num = packet[12:16]
        message_size = packet[16:20]
        payload = packet[20:]
        
        # Decoding the header details
        source_port = self.decode(source_port, "big-endian")
        destination_port = self.decode(destination_port, "big-endian")
        size_of_data = self.decode(size_of_data, "big-endian")
        window_size = self.decode(window_size, "big-endian")
        seq_num = self.decode(seq_num, "big-endian")
        ack_num = self.decode(ack_num, "big-endian")
        message_size = self.decode(message_size, "big-endian")
        payload = self.decode(payload, "utf-8")
        
        # Write Header information to file
        with open ("proxy_log.txt", "a") as f:
            f.write(f"Status: {status}\n")
            f.write(f"Source Port: {source_port}\n")
            f.write(f"Destination Port: {destination_port}\n")
            f.write(f"Size of Data: {size_of_data}\n")
            f.write(f"Window Size: {window_size}\n")
            f.write(f"Sequence Number: {seq_num}\n")
            f.write(f"Acknowledgement Number: {ack_num}\n")
            f.write(f"Message Size: {message_size}\n\n")
            f.write(f"Payload: {payload}\n\n")
        
        # Return the header information
        return source_port, destination_port, size_of_data, window_size, seq_num, ack_num, message_size

    def start_proxy(self):
        self.proxy_sock_recv =  socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.proxy_sock_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            self.proxy_sock_recv.bind((SRC_IP_ADDRESS, PORT_LISTEN))
            self.proxy_sock_send.bind((SRC_IP_ADDRESS, PORT_SEND))

            print(f"Proxy is receiving packets on {SRC_IP_ADDRESS}:{PORT_LISTEN}...")
            print(f"Proxy is sending packets from {SRC_IP_ADDRESS}:{PORT_SEND}...")

            while True:

                # Receive data and extract the packet information
                packet, addr = self.proxy_sock_recv.recvfrom(1024)
                self.extract_packet_information(packet)
                
                # Log where the data came from
                print(f"Received data from {addr}")
                
                # If the packet came from the server, send it to the client
                if addr[0] == SERVER_IP_ADDRESS and addr[1] == SERVER_PORT:
                    
                    if random.random() <= self.ack_drop_percentage:
                        # Log what happened to the data
                        print("Dropped packet going to client\n")
                        # Drop the packet
                        self.acks_dropped += 1
                        continue
                    if random.random() <= self.ack_delay_percentage:
                        # Log what happened to the data
                        print("Delayed packet going to client\n")
                        # Add the packet to the delay buffer
                        self.buffered_packets.append(BufferedPacket(time.time() + DELAY_TIME, packet, "client"))
                        self.acks_delayed += 1
                        continue
                    try:
                        # Log what happened to the data
                        print("Sent data to client\n")
                        # Change the source port of the packet to the proxy's port
                        self.proxy_sock_send.sendto(self.change_packet_source_port(packet), (self.client_ip_address, self.client_port))
                    except Exception as e:
                        raise("Exception sending ack to client")
                    
                # If the packet came from the client, send it to the server
                elif self.client_ip_address is None or (addr[0] == self.client_ip_address and addr[1] == self.client_port):

                    # If the client is connecting for the first time, store the client's address
                    if self.client_ip_address is None:
                        self.client_ip_address = addr[0]
                        self.client_port = addr[1]
                        print(f"Clients address: {addr}")
                    
                    if random.random() <= self.packet_drop_percentage:
                        # Log what happened to the data
                        print("Dropped packet going to server\n")
                        # Drop the packet
                        self.packets_dropped += 1
                        continue
                    if random.random() <= self.packet_delay_percentage:
                        # Log what happened to the data
                        print("Delayed packet going to server\n")
                        # Add the packet to the delay buffer
                        self.buffered_packets.append(BufferedPacket(time.time() + DELAY_TIME, packet, "server"))
                        self.packets_delayed += 1
                        continue
                    try:
                        # Log what happened to the data
                        print("Sent data to server\n")
                        # Change the source port of the packet to the proxy's port
                        self.proxy_sock_send.sendto(self.change_packet_source_port(packet), (SERVER_IP_ADDRESS, SERVER_PORT))
                    except Exception as e:
                        raise("Exception sending ack to client")
                
        except KeyboardInterrupt:
            self.proxy_closing = True
            time.sleep(1)
            print("Proxy shutting down...")
            
        except Exception as e:
            self.proxy_closing = True
            time.sleep(1)
            print(e)
            print("Proxy shutting down...")
        
        self.proxy_sock_recv.close()
        self.proxy_sock_send.close()
        self.proxy_sock_recv = None
        self.proxy_sock_send = None
        time.sleep(1)
        sys.exit(0)
        
if __name__ == "__main__":
    print("Starting proxy server")
    proxy = Proxy()
    proxy.start_proxy()
