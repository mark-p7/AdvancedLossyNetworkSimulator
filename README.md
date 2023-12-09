# project-05

Command to run proxy:

`python <path_to_proxy.py> <source_ip_address> <source_port_to_recv_data> <source_port_to_send_data> <server_ip_address> <server_port>`

Command to run server:

`python <path_to_server.py> <source_ip_address> <source_port> > <path_to_std_out (optional)>`

Command to run client:

`python <path_to_client.py> <source_ip_address> <source_port> <proxy/server_ip_address> <proxy/server_port> < <path_to_std_in (optional)>`

Example runs:

python3 client.py 142.58.214.160 8888 142.58.214.160 8889 
python3 proxy.py 142.58.214.160 8889 7651 142.58.214.160 8080
python3 server.py 142.58.214.160 8080

Library

python3 client.py 10.2.121.144 8888 10.2.121.144 8889 
python3 proxy.py 10.2.121.144 8889 7651 10.2.121.144 8080
python3 server.py 10.2.121.144 8080

What to run in order:
1. GUI
2. Proxy
3. Server
4. Client

What to close in order:
1. GUI
2. Client
3. Proxy