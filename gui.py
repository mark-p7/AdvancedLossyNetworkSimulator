import socket
import sys
import threading
import time

# Tkinter stuff
import tkinter as tk
from matplotlib import pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

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
    
    def start_gui_graph(self):
        try:
            # Set up the Tkinter window
            root = tk.Tk()
            root.title("Network Data Graphs")

            # Create a figure for the plots
            fig, axs = plt.subplots(3, 1, figsize=(6, 8))

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
        ax.set_ylabel('Packets')
        ax.set_title(title)
        ax.legend()
    
    def plot_data(self, ax, data, title):
        ax.clear()
        ax.plot([x[2] for x in data], [x[0] for x in data], label="Packets Sent")
        ax.plot([x[2] for x in data], [x[1] for x in data], label="Packets Received")
        ax.set_xlabel('Time')
        ax.set_ylabel('Packets')
        ax.set_title(title)
        ax.legend()
    
    def decode(self, data: bytes, data_type: str):
        if data_type == "utf-8":
            return data.decode("utf-8")
        if data_type == "big-endian":
            return int.from_bytes(data, "big")
        else:
            assert False, "Unknown data type"
    
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
            self.client_data.append([packets_sent, packets_received, time])
        elif program == "Server":
            self.server_data.append([packets_sent, packets_received, time])
        elif program == "Proxy":
            self.proxy_data.append([packets_dropped, packets_delayed, acks_dropped, acks_delayed, time])
            
        # Print the data
        print(len(self.client_data), len(self.server_data), len(self.proxy_data))

    def start_gui(self):
        # Create sockets
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Bind sockets
        self.client_socket.bind(("10.2.121.144", 7785))
        self.server_socket.bind(("10.2.121.144", 7786))
        self.proxy_socket.bind(("10.2.121.144", 7787))
        
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
                print(e)
                self.connection_state = "CLOSED"
        if conn is not None:
            conn.close()
        if self.server_socket is not None:
            self.server_socket.close()
        self.server_socket = None
            
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
