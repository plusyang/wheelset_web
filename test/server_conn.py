# encoding:utf-8
import socket
import threading
import time

# UDP connection
HOST = '127.0.0.1'
PORT = 11000
BUFSIZ = 1024
ADDR = (HOST, PORT)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# 绑定端口:
s.bind(ADDR)

print 'Bind UDP on 11000...'
while True:
    # 接收数据:
    data, addr = s.recvfrom(BUFSIZ)
    print 'Received from %s:%s.' % (addr, data)
    s.sendto('OK', addr)


# TCP connection
# def tcplink(sock, addr):
#     print 'Accept new connection from %s:%s...' % addr
#     sock.send('Welcome!')
#     while True:
#         data = sock.recv(BUFSIZ)
#         time.sleep(1)
#         if data == 'exit' or not data:
#             break
#         sock.send('Hello, %s!' % data)
#     sock.close()
#     print 'Connection from %s:%s closed.' % addr
#
#
# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# # 绑定端口:
# s.bind(ADDR)
#
# s.listen(5)
# print 'Waiting for connection...'
# while True:
#     # 接收数据:
#     # 接受一个新连接:
#     sock, addr = s.accept()
#     # 创建新线程来处理TCP连接:
#     t = threading.Thread(target=tcplink, args=(sock, addr))
#     t.start()
