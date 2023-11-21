import socket
import time
import sys
from ipaddress import ip_address, IPv4Address, IPv6Address
import os
import select
import struct

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


class Proxy:

    def __init__(self):
        self.drop_percentage = 0
        self.delay = 0
        check_args()

    def decode(self, data: bytes, data_type: str):
        if data_type == "utf-8":
            return data.decode("utf-8")
        if data_type == "big-endian":
            return int.from_bytes(data, "big")
        else:
            assert False, "Unknown data type"

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

    def start_proxy(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as proxy_sock_client, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as proxy_sock_server:

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
                        sock.sendto(data, (SERVER_IP_ADDRESS, SERVER_PORT))
                    elif sock == proxy_sock_server:
                        header, server_address = sock.recvfrom(20)
                        sock.sendto(header, (CLIENT_IP_ADDRESS, CLIENT_PORT))
                # #Data received from a new client
                # data, client_address = self.receive_data(proxy_sock)
                # # clients.add(client_address)
                # # print(f"received data from {client_address}")
                # # Data received from a client
                # # data, client_address = self.receive_data(proxy_sock)
                # if not data:
                #     # Client disconnected
                #     print(f"Connection closed by {client_address}")
                #     # clients.remove(sock)
                # elif len(data) == 1024:
                #     # packet has payload
                #     # print(f"Received data packet from {client_address}")
                #     proxy_sock.sendto(data, (SERVER_IP_ADDRESS, SERVER_PORT))
                # elif len(data) == 20:
                #     # packet is an ACK or FIN
                #     # print(f"Received data packet from {client_address}: {data.decode()}")
                #     if client_address == (CLIENT_IP_ADDRESS, CLIENT_PORT):
                #         # send client ACKs and FINs to the server
                #         print("sent flag to server")
                #         proxy_sock.sendto(data, (SERVER_IP_ADDRESS, SERVER_PORT))
                #     elif client_address == (SERVER_IP_ADDRESS, SERVER_PORT):
                #         # send server ACKs and FINs to the client
                #         print("sent flag to clients")
                #         proxy_sock.sendto(data, (CLIENT_IP_ADDRESS, CLIENT_PORT))

            # data, client_address = proxy_sock_client.recvfrom(1024)
                #
                # if data is None:
                #     continue
                #
                # print("received data")
                #
                # proxy_sock_client.sendto(data, (SERVER_IP_ADDRESS, SERVER_PORT))
                # print("sent data to server")
                #
                # header, server_address = proxy_sock_server.recvfrom(20)
                # while header is None:
                #     print("didnt get header yet")
                #     header, server_address = proxy_sock_server.recvfrom(20)
                #
                # source_port = header[:2]
                # destination_port = header[2:4]
                # size_of_data = header[4:6]
                # window_size = header[6:8]
                # seq_num = header[8:12]
                # ack_num = header[12:16]
                # message_size = header[16:]
                #
                # # Decoding the header details
                # source_port = self.decode(source_port, "big-endian")
                # destination_port = self.decode(destination_port, "big-endian")
                # size_of_data = self.decode(size_of_data, "big-endian")
                # window_size = self.decode(window_size, "big-endian")
                # seq_num = self.decode(seq_num, "big-endian")
                # ack_num = self.decode(ack_num, "big-endian")
                # message_size = self.decode(message_size, "big-endian")
                #
                # print(source_port, destination_port, size_of_data, window_size, seq_num, ack_num, message_size, sep=" ")
                #
                # proxy_sock_server.sendto(header, (CLIENT_IP_ADDRESS, CLIENT_PORT))



if __name__ == "__main__":
    print("Starting proxy server")
    proxy = Proxy()
    proxy.start_proxy()
