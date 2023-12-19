import socket
import sys
import threading
import time
from ipaddress import ip_address, IPv4Address, IPv6Address

# Tkinter stuff
import tkinter as tk
from matplotlib import pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

GUI_IP_ADDRESS = sys.argv[1]
GUI_CLIENT_PORT = sys.argv[2]
GUI_SERVER_PORT = sys.argv[3]
GUI_PROXY_PORT = sys.argv[4]

class GUI:
    def __init__(self):
        # Common variables
        self.connection_state = "CLOSED"
        
        # Initialize socket variables
        self.client_socket = None
        self.server_socket = None
        self.proxy_socket = None
        
        # Initialize data variables
        self.client_data = []
        self.server_data = []
        self.proxy_data = []
        
        # Check the arguments
        self.check_args()

    # Validate the IP address
    def validate_ip(self, ip: str):
        try:
            ip = ip_address(str(sys.argv[1]))
            if isinstance(ip, IPv4Address) or isinstance(ip, IPv6Address):
                return True
            else:
                return False
        except Exception as e:
            return False
    
    # Check the arguments
    def check_args(self):
        if len(sys.argv) != 5:
            print(
                "Usage: python3 server.py <source ipv4_addr or ipv6_addr> <source port> <gui ipv4_addr or ipv6_addr> <gui port>"
            )
            sys.exit(1)
        if self.validate_ip(sys.argv[1]) is False:
            print("Invalid IP address")
            sys.exit(1)
        if sys.argv[2].isnumeric() is False or sys.argv[3].isnumeric() is False or sys.argv[4].isnumeric() is False:
            print("Port number must be numeric")
            sys.exit(1)
        if (int(sys.argv[2]) < 1024) or (int(sys.argv[2]) > 65535) or (int(sys.argv[3]) < 1024) or (int(sys.argv[3]) > 65535) or (int(sys.argv[4]) < 1024) or (int(sys.argv[4]) > 65535):
            print("Port number must be between 1024 and 65535")
            sys.exit(1)
    
    # Start the GUI
    def start_gui_graph(self):
        try:
            # Set up the Tkinter window
            root = tk.Tk()
            root.title("Network Data Graphs")

            # Create a figure for the plots with adjusted size
            fig, axs = plt.subplots(3, 1, figsize=(8, 8))  # Adjust the figure size here

            # Adjust layout and spacing
            fig.subplots_adjust(left=0.1, right=0.9, top=0.9, bottom=0.1, hspace=1)  # Adjust the space between subplots

            # Adding the figure to the Tkinter window
            canvas = FigureCanvasTkAgg(fig, master=root)
            canvas_widget = canvas.get_tk_widget()
            canvas_widget.pack(side=tk.TOP, fill=tk.BOTH, expand=True, ipady=20, ipadx=20)

            # Updating the graphs
            root.after(200, self.update_graphs, axs, canvas, root)

            # Start the GUI loop
            root.mainloop()
            
        except KeyboardInterrupt:
            print("Gracefully shutting down...")
            self.connection_state = "CLOSED"
            canvas_widget.destroy()
            root.destroy()
            return

    # Update the graphs
    def update_graphs(self, axs, canvas, root):
        # Plotting the data
        self.plot_data(axs[0], self.client_data, 'Client Data')
        self.plot_data(axs[1], self.server_data, 'Server Data')
        self.plot_proxy_data(axs[2], self.proxy_data, 'Proxy Data')
        
        # Updating the graphs
        canvas.draw()
        root.after(200, self.update_graphs, axs, canvas, root)
    
    def plot_proxy_data(self, ax, data, title):
        ax.clear()
        ax.plot([x[4] for x in data], [x[0] for x in data], label="Packets Dropped")
        ax.plot([x[4] for x in data], [x[1] for x in data], label="Packets Delayed")
        ax.plot([x[4] for x in data], [x[2] for x in data], label="Acks Dropped")
        ax.plot([x[4] for x in data], [x[3] for x in data], label="Acks Delayed")
        ax.set_xlabel('Time')
        ax.set_ylabel('Packet/Ack')
        ax.set_title(title)
        ax.legend()
    
    def plot_data(self, ax, data, title):
        xLabel = "Packets Sent"
        yLabel = "Acks Received"
        if (title == "Server Data"):
            xLabel = "Acks Sent"
            yLabel = "Packets Received"
        ax.clear()
        ax.plot([x[2] for x in data], [x[0] for x in data], label=xLabel)
        ax.plot([x[2] for x in data], [x[1] for x in data], label=yLabel)
        ax.set_xlabel('Time')
        ax.set_ylabel('Packet/Ack')
        ax.set_title(title)
        ax.legend()
    
    # Decode the data
    def decode(self, data: bytes, data_type: str):
        if data_type == "utf-8":
            return data.decode("utf-8")
        if data_type == "big-endian":
            return int.from_bytes(data, "big")
        else:
            assert False, "Unknown data type"
    
    # Decapsulate the data
    def decapsulate(self, data: bytes, program: str):
        
        if program == "Proxy":
            packets_dropped = self.decode(data[0:4], "big-endian")
            packets_delayed = self.decode(data[4:8], "big-endian")
            acks_dropped = self.decode(data[8:12], "big-endian")
            acks_delayed = self.decode(data[12:16], "big-endian")
            time = self.decode(data[16:20], "big-endian")
            
            return packets_dropped, packets_delayed, acks_dropped, acks_delayed, time
        
        packets_sent = self.decode(data[0:4], "big-endian")
        packets_received = self.decode(data[4:8], "big-endian")
        time = self.decode(data[8:12], "big-endian")
        
        return packets_sent, packets_received, time
    
    # Process the data
    def process_data(self, data: bytes, program: str):
        
        # Initialize variables
        packets_dropped = 0
        packets_delayed = 0
        acks_dropped = 0
        acks_delayed = 0
        time = 0
        packets_sent = 0
        packets_received = 0
        
        # If Proxy, Retrieve the packet/ack drops and delays else retrieve packets sent/received
        if program == "Proxy":
            packets_dropped, packets_delayed, acks_dropped, acks_delayed, time = self.decapsulate(data, program)
        else:
            packets_sent, packets_received, time = self.decapsulate(data, program)
            
        # If the connection is closed, return
        if packets_sent == 4294967295:
            self.connection_state = "CLOSED"
            return
        
        # Append the data to the appropriate list
        if program == "Client":
            if time == 0 and len(self.client_data) > 3:
                self.connection_state = "CLOSED"
                return
            self.client_data.append([packets_sent, packets_received, time])
        elif program == "Server":
            if time == 0 and len(self.server_data) > 3:
                self.connection_state = "CLOSED"
                return
            self.server_data.append([packets_sent, packets_received, time])
        elif program == "Proxy":
            if time == 0 and len(self.proxy_data) > 3:
                self.connection_state = "CLOSED"
                return
            self.proxy_data.append([packets_dropped, packets_delayed, acks_dropped, acks_delayed, time])
            
        # Print the data
        print(len(self.client_data), len(self.server_data), len(self.proxy_data))

    # Start the GUI
    def start_gui(self):
        # Create sockets
        ip_family = socket.AF_INET if isinstance(ip_address(str(GUI_IP_ADDRESS)), IPv4Address) else socket.AF_INET6
        self.client_socket = socket.socket(ip_family, socket.SOCK_STREAM)
        self.server_socket = socket.socket(ip_family, socket.SOCK_STREAM)
        self.proxy_socket = socket.socket(ip_family, socket.SOCK_STREAM)
        
        # Bind sockets
        self.client_socket.bind((GUI_IP_ADDRESS, int(GUI_CLIENT_PORT)))
        self.server_socket.bind((GUI_IP_ADDRESS, int(GUI_SERVER_PORT)))
        self.proxy_socket.bind((GUI_IP_ADDRESS, int(GUI_PROXY_PORT)))
        
        self.connection_state = "OPEN"
        
        # Create a thread for each socket
        threading.Thread(target=self.thread_client).start()
        threading.Thread(target=self.thread_server).start()
        threading.Thread(target=self.thread_proxy).start()
        
        # Start the GUI
        self.start_gui_graph() 
        self.connection_state = "CLOSED"
        
        # Close the sockets
        while self.client_socket is not None or self.server_socket is not None or self.proxy_socket is not None:
            time.sleep(1)
            
        print("Sockets closed")
        sys.exit(0)
        
    # Thread for the client socket
    def thread_client(self):
        self.client_socket.listen(1)
        conn, addr = self.client_socket.accept()
        while self.connection_state != "CLOSED":
            try:
                conn.settimeout(0.5)
                data = conn.recv(12)
                conn.settimeout(None)
                self.process_data(data, "Client")
            except socket.timeout:
                pass
            except KeyboardInterrupt:
                self.connection_state = "CLOSED"
            except Exception as e:
                self.connection_state = "CLOSED"
                print(e)
        if conn is not None:
            conn.close()
        if self.client_socket is not None:
            self.client_socket.close()
        self.client_socket = None
    
    # Thread for the server socket
    def thread_server(self):
        self.server_socket.listen(1)
        conn, addr = self.server_socket.accept()
        while self.connection_state != "CLOSED":
            try:
                conn.settimeout(0.5)
                data = conn.recv(12)
                conn.settimeout(None)
                self.process_data(data, "Server")
            except socket.timeout:
                pass
            except KeyboardInterrupt:
                self.connection_state = "CLOSED"
            except Exception as e:
                self.connection_state = "CLOSED"
                print(e)
        if conn is not None:
            conn.close()
        if self.server_socket is not None:
            self.server_socket.close()
        self.server_socket = None
            
    # Thread for the proxy socket
    def thread_proxy(self):
        self.proxy_socket.listen(1)
        conn, addr = self.proxy_socket.accept()
        while self.connection_state != "CLOSED":
            try:
                conn.settimeout(0.5)
                data = conn.recv(20)
                conn.settimeout(None)
                self.process_data(data, "Proxy")
            except socket.timeout:
                pass
            except KeyboardInterrupt:
                self.connection_state = "CLOSED"
            except Exception as e:
                self.connection_state = "CLOSED"
                print(e)
        if conn is not None:
            conn.close()
        if self.proxy_socket is not None:
            self.proxy_socket.close()
        self.proxy_socket = None
        
if __name__ == "__main__":
    gui = GUI()
    gui.start_gui()
