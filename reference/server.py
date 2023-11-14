import socket
import sys
import os
import time
import select
from ipaddress import ip_address, IPv4Address, IPv6Address
from typing import List

# Create a FSM class
class StateMachine:
    def __init__(self, initial_state, states, actions):
        self.state = initial_state
        self.states = states
        self.actions = actions

    def transition(self, action: str):
        try:
            self.log_transition_details(action)
            if action in self.states[self.state] and action in self.actions:
                next_action = self.actions[action]()
                self.state = self.states[self.state][action]
                return next_action
            else:
                raise Exception("Invalid action")
        except Exception as e:
            print("Action:", action, "failed. Now transitioning to the error state from the", self.state, "state")
            raise e

    def log_transition_details(self, action: str):
        print(
            "\nCurrent State: ",
            self.state,
            "\nAction: ",
            action,
            "\nNext State: ",
            self.states[self.state][action],
        )

    def __str__(self):
        return "Current state: " + self.state

# Start server
class Server:
    def __init__(self):
        self.server_socket: socket.socket = None
        self.file_descriptors: List[socket.socket] = []
        self.error = None

        # File details dictionary
        #
        # Key: File descriptor
        #
        # Value:
        # List of file name, file name size, file content, file content size
        # 0: File name size
        # 1: File name
        # 2: File content size
        # 3: Boolean indicating if file has already been created
        # 4: File content
        self.fd_details = {}
        self.states = {
            "initial": {
                "check_arguments": "arguments",
                "handle_error": "error",
            },
            "arguments": {
                "create_socket": "socket",
                "handle_error": "error",
            },
            "socket": {
                "bind_socket": "bind",
                "handle_error": "error",
            },
            "bind": {
                "listen_on_socket": "listen",
                "handle_error": "error",
            },
            "listen": {
                "wait_for_new_data": "select",
                "handle_error": "error",
            },
            "select": {
                "accept_connection": "accept",
                "read_data": "recv",
                "handle_error": "error",
            },
            "accept": {
                "wait_for_new_data": "select",
                "handle_error": "error",
            },
            "recv": {
                "read_file_name_size": "read_file_name_size",
                "read_file_name": "read_file_name",
                "read_file_content_size": "read_file_content_size",
                "read_file_content": "read_file_content",
                "close_connection": "close",
                "wait_for_new_data": "select",
                "handle_error": "error",
            },
            "read_file_name_size": {
                "read_file_name": "read_file_name",
                "wait_for_new_data": "select",
                "handle_error": "error",
            },
            "read_file_name": {
                "check_for_duplicate_file_name": "check_for_duplicate_file_name",
                "handle_error": "error",
            },
            "check_for_duplicate_file_name": {
                "read_file_content_size": "read_file_content_size",
                "wait_for_new_data": "select",
                "handle_error": "error",
            },
            "read_file_content_size": {
                "read_file_content": "read_file_content",
                "write_to_file": "append",
                "wait_for_new_data": "select",
                "handle_error": "error",
            },
            "read_file_content": {
                "write_to_file": "append",
                "handle_error": "error",
            },
            "append": {
                "read_file_name_size": "read_file_name_size",
                "wait_for_new_data": "select",
                "handle_error": "error",
            },
            "close": {
                "wait_for_new_data": "select",
                "handle_error": "error",
            },
            "error": {"terminate_program": "exit"},
            "exit": {},
        }
        self.actions = {
            "check_arguments": self.check_args,
            "create_socket": self.create_socket,
            "bind_socket": self.bind_socket,
            "listen_on_socket": self.listen_on_socket,
            "wait_for_new_data": self.wait_for_new_data,
            "accept_connection": self.accept_connection,
            "read_data": self.read_data,
            "read_file_name_size": self.read_file_name_size,
            "read_file_name": self.read_file_name,
            "check_for_duplicate_file_name": self.check_for_duplicate_file_name,
            "read_file_content_size": self.read_file_content_size,
            "read_file_content": self.read_file_content,
            "write_to_file": self.write_to_file,
            "close_connection": self.close_connection,
            "handle_error": self.handle_error,
            "terminate_program": self.terminate_program,
        }
        self.state_machine: StateMachine = StateMachine(
            "initial", self.states, self.actions
        )

    # Start server
    def start_server(self):
        try:
            # Initial action
            next_action = "check_arguments"

            while 1:
                next_action = self.state_machine.transition(next_action)

        # If user presses Ctrl-C (This should be its own error state, so add it later)
        except KeyboardInterrupt:
            self.error = "KeyboardInterrupt"
            self.state_machine.transition("handle_error")
            self.state_machine.transition("terminate_program")
            
        # If there is an error (See above for error state comment)
        except Exception as e:
            self.error = e
            self.state_machine.transition("handle_error")
            self.state_machine.transition("terminate_program")

    # Handle error
    def handle_error(self):
        # If there is an error, log it
        if self.error is not None:
            print("Error:", self.error)
        self.error = None

    # Gracefully terminate program
    def terminate_program(self):
        print("Terminating program...")

        # Close server socket
        if self.server_socket is not None:
            self.server_socket.close()

        # Sleep for 1 second
        time.sleep(1)

        # Exit program
        if self.error is not None:
            sys.exit(1)
        else:
            sys.exit(0)

    # Check if arguments are passed in correctly
    def check_args(self):
        if len(sys.argv) != 4:
            print(
                "Usage: python3 server.py <ipv4_addr or ipv6_addr> <port> <output_dir>"
            )
            raise Exception("Invalid number of arguments")
        if self.validate_ip(sys.argv[1]) is False:
            print("Invalid IP address")
            raise Exception("Invalid IP address")
        if sys.argv[2].isnumeric() is False:
            print("Port number must be numeric")
            raise Exception("Port number must be numeric")
        if (int(sys.argv[2]) < 1024) or (int(sys.argv[2]) > 65535):
            print("Port number must be between 1024 and 65535")
            raise Exception("Port number must be between 1024 and 65535")
        if os.path.isdir(os.path.join(os.path.dirname(__file__), sys.argv[3])) is False:
            print("Output directory does not exist")
            raise Exception("Output directory does not exist")
        return "create_socket"

    # Validate IP address
    def validate_ip(self, ip: str):
        try:
            ip = ip_address(str(sys.argv[1]))
            if isinstance(ip, IPv4Address):
                self.ip_address_family = "IPv4"
            elif isinstance(ip, IPv6Address):
                self.ip_address_family = "IPv6"
            else:
                return False
        except Exception as e:
            self.error = e
            return False

    # Create socket
    def create_socket(self):
        print("Creating socket...")
        socket_family = socket.AF_INET6 if self.ip_address_family == "IPv6" else socket.AF_INET
        self.server_socket = socket.socket(socket_family, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return "bind_socket"

    # Bind socket
    def bind_socket(self):
        print("Binding socket...")
        self.server_socket.bind((str(sys.argv[1]), int(sys.argv[2])))
        return "listen_on_socket"

    # Listen on socket
    def listen_on_socket(self):
        print("Listening on socket...")
        self.server_socket.listen(1)
        self.file_descriptors.append(self.server_socket)
        return "wait_for_new_data"
    
    # Decode data
    def decode(self, data, type):
        if type == "utf-8":
            return data.decode("utf-8")
        if type == "big-endian":
            return int.from_bytes(data, "big")
        else:
            assert False, "Unknown data type"

    # Extract data
    def extract(self, data: bytes, size: int):
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

    # Check if there is more data to read
    def is_there_more_data_to_read(self, next_state: str):
        if len(self.remaining_data) > 0:
            return next_state
        elif len(self.remaining_data) == 0:
            return "wait_for_new_data"
    
    # Check if file has already been created
    def check_for_duplicate_file_name(self):
        # Build complete file path
        complete_file_dir = os.path.join(os.path.dirname(__file__), sys.argv[3])
        complete_file_name = os.path.join(complete_file_dir, self.fd_details[self.current_fd][1])
        # Check if file exists
        if os.path.isfile(complete_file_name) is True:
            self.fd_details[self.current_fd][3] = True
        for fd in self.fd_details:
            if self.fd_details[fd][0] == self.fd_details[self.current_fd][1]:
                self.fd_details[self.current_fd][3] = True
        # Return next state
        return self.is_there_more_data_to_read("read_file_content_size")
    
    # Read file name size
    def read_file_name_size(self):
        self.fd_details[self.current_fd] = [None, None, None, False, None]
        file_name_size, remaining_data = self.extract(self.remaining_data, 4)
        file_name_size = self.decode(file_name_size, "big-endian")
        print(file_name_size)
        assert file_name_size <= 255, "Invalid File Name Length"
        assert file_name_size >= 0, "Invalid File Name Length"
        self.remaining_data = remaining_data
        self.fd_details[self.current_fd][0] = file_name_size
        return self.is_there_more_data_to_read("read_file_name")

    # Read file name
    def read_file_name(self):
        print("Reading file name...")
        file_name, remaining_data = self.extract(self.remaining_data, self.fd_details[self.current_fd][0])
        self.fd_details[self.current_fd][0] -= len(file_name)
        file_name_str = file_name.decode("utf-8")
        assert self.fd_details[self.current_fd][0] == 0, "Invalid File Name Length"
        self.remaining_data = remaining_data
        self.fd_details[self.current_fd][1] = file_name_str
        return "check_for_duplicate_file_name"

    # Read file content size
    def read_file_content_size(self):
        file_content_size, remaining_data = self.extract(self.remaining_data, 4)
        file_content_size = self.decode(file_content_size, "big-endian")
        self.remaining_data = remaining_data
        self.fd_details[self.current_fd][2] = file_content_size
        if file_content_size == 0:
            self.fd_details[self.current_fd][4] = b""
            return "write_to_file"
        return self.is_there_more_data_to_read("read_file_content")

    # Wait for connection
    def wait_for_new_data(self):
        # Log waiting for connection
        print("Waiting for connection...")

        # Select sockets that are ready to be read
        self.sockets_to_read, _, self.exception_sockets = select.select(
            self.file_descriptors, [], self.file_descriptors
        )

        # Set socket to non-blocking
        self.server_socket.setblocking(0)

        # Iterate through sockets that are ready to be read
        for client_socket in self.sockets_to_read:
            # Get current file descriptor
            self.current_fd = client_socket.fileno()
            
            # Initalize client socket
            self.client_socket = client_socket

            # If client socket is actually the server socket then that means a new connection is being made
            if client_socket is self.server_socket:
                print("accepting new connection")
                return "accept_connection"
            # Else that means data is being read from an existing connection
            else:
                print("reading new data")
                return "read_data"

    # Accept connection
    def accept_connection(self):
        print("Accepting connection...")
        self.conn, self.addr = self.server_socket.accept()
        print("Connection accepted on: ", self.addr)
        self.file_descriptors.append(self.conn)
        return "wait_for_new_data"

    def check_for_new_data(self):
        self.remaining_data = self.client_socket.recv(1024)
        if len(self.remaining_data) == 0:
            return "close_connection"
        else:
            return "read_file_name_size"
    
    def read_file_content(self):
        self.fd_details[self.current_fd][4], self.remaining_data = self.extract(self.remaining_data, self.fd_details[self.current_fd][2])
        return "write_to_file"    
        
    def write_to_file(self):
        print("Writing to file...")
        if self.fd_details[self.current_fd][3] is False:
            self.append(self.fd_details[self.current_fd][1], self.fd_details[self.current_fd][4])
        self.fd_details[self.current_fd][2] = self.fd_details[self.current_fd][2] - len(self.fd_details[self.current_fd][4])
        self.fd_details[self.current_fd][4] = None
        
        # If file content size is 0 then that means there is no more file content
        if self.fd_details[self.current_fd][2] == 0:
            # Delete file descriptor details
            del self.fd_details[self.current_fd]
            return self.is_there_more_data_to_read("read_file_name_size")
        
        # If file content size is not 0 then that means there is more file content
        return self.is_there_more_data_to_read("read_file_content_size")    
        
    # Read data
    def read_data(self):
        # Read data from client socket
        self.remaining_data = self.client_socket.recv(1024)

        # Log remaining data length
        print("Remaining data length: ", len(self.remaining_data))

        # Determine next state
        if len(self.remaining_data) == 0:
            return "close_connection"
        if self.current_fd not in self.fd_details:
            return "read_file_name_size"
        elif self.fd_details[self.current_fd][1] is None:
            return "read_file_name"
        elif self.fd_details[self.current_fd][2] is None:
            return "read_file_content_size"
        else:
            return "read_file_content"

    # Append data to file
    def append(self, file_name: str, file_content: bytes):
        # Build complete file path
        complete_file_dir = os.path.join(os.path.dirname(__file__), sys.argv[3])
        complete_file_name = os.path.join(complete_file_dir, file_name)
        if os.path.isfile(complete_file_name) is False:
            file = open(complete_file_name, "wb")
            file.write(file_content)
            file.close()
        else:
            file = open(complete_file_name, "ab")
            file.write(file_content)
            file.close()

    # Close connection
    def close_connection(self):
        # Log socket closing
        print("Closing socket")

        # Close client socket connection
        self.client_socket.close()

        # Delete file descriptor details
        if self.current_fd in self.fd_details:
            del self.fd_details[self.current_fd]

        # Remove file descriptor from list of file descriptors
        self.file_descriptors.remove(self.client_socket)

        # Wait for new connection
        return "wait_for_new_data"

# Main function
if __name__ == "__main__":
    server = Server()
    server.start_server()
