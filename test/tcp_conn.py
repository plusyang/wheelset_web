# encoding:utf-8

import socket
import random

HOST = '127.0.0.1'
PORT = 11000
BUFSIZ = 1024
ADDR = (HOST, PORT)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(ADDR)

while True:
    data = 'a random number: ' + str(random.randrange(0, 100))
    s.send(data)
    rev_data = s.recv(BUFSIZ)

    if not rev_data:
        break
    print rev_data

s.close()
