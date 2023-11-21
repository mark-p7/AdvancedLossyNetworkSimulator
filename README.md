# project-05

Command to run proxy:

`python <path_to_proxy.py> <source_ip_address> <source_port_client> <source_port_for_server> <client_ip_address> <client_port> <server_ip_address> <server_port>`

Command to run server:

`python <path_to_server.py> <source_ip_address> <source_port> <proxy_ip_address> <proxy_port_for_server> 

Command to run client:

`python <path_to_client.py> <source_ip_address> <source_port> <proxy_ip_address> <proxy_port_for_client>`< <path_to_input_file>`

Run client last

example run:

python3 proxy.py 192.168.4.141 8889 8890 192.168.4.141 8888 192.168.4.141 8887
python3 server.py 192.168.4.141 8887 192.168.4.141 8890
python3 client.py 192.168.4.141 8888 192.168.4.141 8889 < input.txt
