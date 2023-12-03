import socket
import time
import sys
from ipaddress import ip_address, IPv4Address, IPv6Address
import os
import select
import struct
import random
import threading

SRC_IP_ADDRESS = sys.argv[1]
SRC_PORT_ONE = int(sys.argv[2])
SRC_PORT_TWO = int(sys.argv[3])
CLIENT_IP_ADDRESS = sys.argv[4]
CLIENT_PORT = int(sys.argv[5])
SERVER_IP_ADDRESS = sys.argv[6]
SERVER_PORT = int(sys.argv[7])

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
    if len(sys.argv) != 8:
        print(
            "Usage: python3 proxy.py <source ipv4_addr or ipv6_addr> <source port>" +
            "<client ipv4_addr or ipv6_addr> <client port>" +
            "<server ipv4_addr or ipv6_addr> <server port>"
        )
        sys.exit(1)
    if validate_ip(sys.argv[1]) is False or validate_ip(sys.argv[4]) is False or validate_ip(sys.argv[6]) is False:
        print("Invalid IP address")
        sys.exit(1)
    if (sys.argv[2].isnumeric() is False or sys.argv[3].isnumeric() is False or sys.argv[5].isnumeric() is False
            or sys.argv[7].isnumeric() is False):
        print("Port number must be numeric")
        sys.exit(1)
    if (((int(sys.argv[2]) < 1024) or (int(sys.argv[2]) > 65535)
         or (int(sys.argv[3]) < 1024) or (int(sys.argv[3]) > 65535)
         or (int(sys.argv[5]) < 1024) or (int(sys.argv[5]) > 65535))
            or (int(sys.argv[7]) < 1024) or (int(sys.argv[7]) > 65535)):
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
    def __init__(self, delay, packet, destination):
        self.destination = destination
        self.delay = delay
        self.packet = packet

class Proxy:

    def __init__(self):
        drop_percentage = input("Enter drop percentage (example input for 60% -> 60): ")
        delay_percentage = input("Enter delay percentage: ")
        check_user_input(drop_percentage, delay_percentage)
        self.drop_percentage = int(drop_percentage) / 100
        self.delay_percentage = int(delay_percentage) / 100
        self.buffered_packets: [BufferedPacket] = []
        check_args()

    def decode(self, data: bytes, data_type: str):
        if data_type == "utf-8":
            return data.decode("utf-8")
        if data_type == "big-endian":
            return int.from_bytes(data, "big")
        else:
            assert False, "Unknown data type"
        
    # def log_packet(self, packet):
    #     header = packet[:20]
    #     source_port = header[:2]
    #     destination_port = header[2:4]
    #     size_of_data = header[4:6]
    #     window_size = header[6:8]
    #     seq_num = header[8:12]
    #     ack_num = header[12:16]
    #     message_size = header[16:]
        
    #     with open("client_log.txt", "a") as file:
    #         file.write(f"source_port: {source_port}\n" +
    #                     "destination_port: {destination_port}\n" +
    #                     "size_of_data: {size_of_data}\n" +
    #                     "window_size: {window_size}\n" +
    #                     "seq_num: {seq_num}\n" +
    #                     "ack_num: {ack_num}\n" +
    #                     "message_size: {message_size}\n")

    def receive_data(self, sock):
        header, address = sock.recvfrom(20)
        # if not header:
        #     return None

        # if data_size is greater than 0, this is a data packet from client to server,
        # otherwise, the packet is an acknowledgement

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

        print(source_port, destination_port, size_of_data, window_size, seq_num, ack_num, message_size, sep=" ")

        # data_size = int.from_bytes(header[4:6], "big")
        print("data size = ", size_of_data)
        if size_of_data > 0:
            print("received data packet")
            payload, address = sock.recvfrom(1004)
            return header + payload, address
        else:
            print("received flag packet")
            return header, address

    def print_header(self, header):
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

        print(f"seq_num: {seq_num}")
        print(f"ack_num: {ack_num}", end="\n\n")

    def start_proxy(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as proxy_sock_client, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as proxy_sock_server:

            try:
                proxy_sock_client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                proxy_sock_client.bind((SRC_IP_ADDRESS, SRC_PORT_ONE))

                proxy_sock_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                proxy_sock_server.bind((SRC_IP_ADDRESS, SRC_PORT_TWO))

                inputs = [proxy_sock_client, proxy_sock_server]

                print(f"Proxy is listening for client on {SRC_IP_ADDRESS}:{SRC_PORT_ONE}...")
                print(f"Proxy is listening for server on {SRC_IP_ADDRESS}:{SRC_PORT_TWO}...")

                while True:

                    readable, _, _ = select.select(inputs, [], [])
                    for sock in readable:
                        if sock == proxy_sock_client:
                            data, client_address = sock.recvfrom(1024)
                            print("Received data from client")
                            # if random.random() <= self.drop_percentage:
                            #     print("Dropped packet going to server")
                            #     continue
                            # if random.random() <= self.delay_percentage:
                            #     print("Delayed packet going to server")
                            #     self.buffered_packets.append(BufferedPacket(self.delay_percentage, data, "server"))
                            try:
                                sock.sendto(data, (SERVER_IP_ADDRESS, SERVER_PORT))
                                print("Sent data to server")
                                self.print_header(data[:20])
                            except Exception as e:
                                raise("Exception sending ack to client")
                        elif sock == proxy_sock_server:
                            header, server_address = sock.recvfrom(20)
                            print("Received ack from server")
                            # if random.random() <= self.drop_percentage:
                            #     print("Dropped packet going to client")
                            #     continue
                            # if random.random() <= self.delay_percentage:
                            #     print("Delayed packet going to client")
                            #     self.buffered_packets.append(BufferedPacket(self.delay_percentage, data, "client"))
                            try:
                                sock.sendto(header, (CLIENT_IP_ADDRESS, CLIENT_PORT))
                                print("Sent ack to client")
                                self.print_header(header)
                            except Exception as e:
                                raise("Exception sending ack to client")
                            
            except KeyboardInterrupt:
                print("Proxy shutting down...")
                
            except Exception as e:
                print(e)
                print("Proxy shutting down...")
                
if __name__ == "__main__":
    print("Starting proxy server")
    proxy = Proxy()
    proxy.start_proxy()
