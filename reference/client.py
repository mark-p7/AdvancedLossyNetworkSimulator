import socket
import sys
import os
from ipaddress import ip_address, IPv4Address, IPv6Address

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
            print(
                "Action:",
                action,
                "failed. Now transitioning to the error state from the",
                self.state,
                "state",
            )
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


class Client:
    def __init__(self):
        self.state_machine = None
        self.client_socket = None
        self.file_name = None
        self.file_content = None
        self.file_name_in_bytes = None
        self.file_name_length_in_bytes = None
        self.file_content_in_bytes = None
        self.file_content_length_in_bytes = None
        self.current_file_argument = 2

    # Check if arguments are passed in correctly
    def check_args(self):
        if len(sys.argv) < 4:
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
        return "CREATE_SOCKET"

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

    def check_for_files(self):
        # Check if all files have been sent
        if self.current_file_argument + 1 >= len(sys.argv):
            return "CLOSE"
        # Get next file name
        self.current_file_argument = self.current_file_argument + 1
        self.file_name = sys.argv[self.current_file_argument]
        # Transition to read file
        return "READ_FILE"

    def read_file(self):
        # Build file path
        complete_file_name = os.path.join(os.path.dirname(__file__), self.file_name)
        # Continue checking if file exists
        if os.path.isfile(complete_file_name) is False:
            print(self.file_name + " does not exist in the current directory")
            return "CHECK_FOR_FILES"
        # Open file in read mode
        file = open(complete_file_name, "rb")
        # Read file content
        self.file_content = file.read()
        # Close file
        file.close()
        # Convert file name to bytes
        self.file_name_in_bytes = self.file_name.encode("utf-8")
        # Convert file name length to bytes
        self.file_name_length_in_bytes = len(self.file_name_in_bytes).to_bytes(
            4, byteorder="big"
        )
        # Convert file content to bytes
        self.file_content_in_bytes = self.file_content
        # Convert file content length to bytes
        self.file_content_length_in_bytes = len(self.file_content_in_bytes).to_bytes(
            4, byteorder="big"
        )
        # Return file content
        return "SEND"

    def send(self):
        # Send data
        self.client_socket.send(self.file_name_length_in_bytes)
        self.client_socket.send(self.file_name_in_bytes)
        self.client_socket.send(self.file_content_length_in_bytes)
        self.client_socket.send(self.file_content_in_bytes)
        return "CHECK_FOR_FILES"

    def create_socket(self):
        # Create socket
        socket_family = (
            socket.AF_INET6 if self.ip_address_family == "IPv6" else socket.AF_INET
        )
        self.client_socket = socket.socket(socket_family, socket.SOCK_STREAM)
        return "CONNECT"

    def connect(self):
        # Connect to server
        self.client_socket.connect((str(sys.argv[1]), int(sys.argv[2])))
        return "CHECK_FOR_FILES"

    def close(self):
        # Gracefully close socket
        self.client_socket.close()
        return "EXIT"

    def exit(self):
        # Exit program
        sys.exit(1)

    def exception(self):
        print("Exception occurred")
        print(self.error_message)
        return "EXIT"

    def start_client(self):
        self.state_machine = StateMachine(
            "START",
            {
                "START": {"CHECK_ARGS": "ARGS_CHECKED", "EXCEPTION": "ERROR"},
                "ARGS_CHECKED": {"CREATE_SOCKET": "SOCKET", "EXCEPTION": "ERROR"},
                "SOCKET": {"CONNECT": "CONNECT", "EXCEPTION": "ERROR"},
                "CONNECT": {
                    "CHECK_FOR_FILES": "CHECKING_FOR_FILES",
                    "EXCEPTION": "ERROR",
                },
                "CHECKING_FOR_FILES": {
                    "READ_FILE": "FILE_READ",
                    "EXCEPTION": "ERROR",
                    "CLOSE": "CLOSED",
                },
                "FILE_READ": {
                    "SEND": "SENT",
                    "EXCEPTION": "ERROR",
                    "CHECK_FOR_FILES": "CHECKING_FOR_FILES",
                },
                "SENT": {"CHECK_FOR_FILES": "CHECKING_FOR_FILES", "EXCEPTION": "ERROR"},
                "CLOSED": {"EXIT": "EXIT", "EXCEPTION": "ERROR"},
                "ERROR": {"EXIT": "EXIT"},
                "EXIT": {},
            },
            {
                "CHECK_ARGS": self.check_args,
                "CREATE_SOCKET": self.create_socket,
                "CONNECT": self.connect,
                "CHECK_FOR_FILES": self.check_for_files,
                "READ_FILE": self.read_file,
                "SEND": self.send,
                "CLOSE": self.close,
                "EXCEPTION": self.exception,
                "EXIT": self.exit,
            },
        )

        next_action = "CHECK_ARGS"

        while 1:
            try:
                next_action = self.state_machine.transition(next_action)
            except KeyboardInterrupt:
                self.error_message = "Keyboard Interrupt"
                next_action = "EXCEPTION"
            except Exception as e:
                self.error_message = str(e)
                next_action = "EXCEPTION"


if __name__ == "__main__":
    client = Client()
    client.start_client()
