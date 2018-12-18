# encoding:utf-8
import socket

HOST = '127.0.0.1'
PORT = 11000
BUFSIZ = 1024
ADDR = (HOST, PORT)


def udp_conn():
    print "UDP connected .."
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    s.sendto('data from udp conn test.', (ADDR))
    data = s.recv(BUFSIZ)
    s.close()
    return data


def udp_start():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto('start', (ADDR))
    data = s.recv(BUFSIZ)
    s.close()
    return data


def udp_stop():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto('stop', (ADDR))
    data = s.recv(BUFSIZ)
    s.close()
    return data