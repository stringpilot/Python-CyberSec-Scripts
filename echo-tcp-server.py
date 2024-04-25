import requests
import socket
import threading



def server_socket(ip, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ip, port))
    server.listen(5)
    print(f'[+] Listening on {ip}:{port}')
    while True:
        client, address = server.accept()
        print(f'[+] Accepted Connection From {address[0]}:{address[1]}')
        server_handler = threading.Thread(target=server_send_recieve, args=(client))
        server_handler.start()


def server_send_recieve(client_socket):
    with client_socket as socks:
        request = socks.recv(1024)
        print(f'[*] Obtained 1024: {requests.decode("UTF-8")}')
        socks.send(b'ACK')


local = '0.0.0.0'
ports = 9001
if __name__ == '__main__':
    server_socket(local,ports)

#Reference
    #https://realpython.com/python-sockets/
