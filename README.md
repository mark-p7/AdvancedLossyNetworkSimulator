# project-05

Command to run proxy:

`python <path_to_proxy.py> <source_ip_address> <source_port_to_recv_data> <source_port_to_send_data> <server_ip_address> <server_port>`

Command to run server:

`python <path_to_server.py> <source_ip_address> <source_port> > <path_to_std_out (optional)>`

Command to run client:

`python <path_to_client.py> <source_ip_address> <source_port> <proxy/server_ip_address> <proxy/server_port> < <path_to_std_in (optional)>`

Example runs:

Lab

python3 client.py 10.65.81.90 8888 10.65.81.90 8889 10.65.81.90 7771
python3 server.py 10.65.81.90 8080 10.65.81.90 7772
python3 proxy.py 10.65.81.90 8889 7651 10.65.81.90 8080 10.65.81.90 7773
python3 gui.py 10.65.81.90 7771 7772 7773

What to run in order:
1. GUI
2. Proxy
3. Server
4. Client

What to close in order:
1. GUI
2. Client
3. Proxy