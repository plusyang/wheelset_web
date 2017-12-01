# encoding:utf-8
import socket

HOST = '192.168.1.134'
PORT = 11000
BUFSIZ = 1024
ADDR = (HOST, PORT)


def udp_conn():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    s.sendto('data from udp conn test.', (ADDR))
    data = s.recv(BUFSIZ)
    print data
    s.close()
    return data

udp_conn()