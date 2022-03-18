"""
Client TCP by Lorenzo Favaro
"""

import socket

target_host = "localhost"
target_port = 9998

message = b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect((target_host, target_port))
    client.send(message)

    response = client.recv(4096)
    print(response.decode())
