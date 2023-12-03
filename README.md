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

eduroam

python3 proxy.py 10.65.69.69 8112 8113 10.65.69.69 8114 10.65.69.69 8111
python3 server.py 10.65.69.69 8111 10.65.69.69 8113
python3 client.py 10.65.69.69 8114 10.65.69.69 8112 < input.txt

home

python3 proxy.py 192.168.1.101 8889 8890 192.168.1.101 8888 192.168.1.101 8080
python3 server.py 192.168.1.101 8080 192.168.1.101 8890 > output.txt
python3 client.py 192.168.1.101 8888 192.168.1.101 8889 < input2.txt

library

python3 proxy.py 10.2.125.213 8889 8890 10.2.125.213 8888 10.2.125.213 8080
python3 server.py 10.2.125.213 8080 10.2.125.213 8890
python3 client.py 10.2.125.213 8888 10.2.125.213 8889