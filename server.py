import pickle
import socket
import sys
import time
import random
import json
import gzip

class Server:
    def __init__(self):
        self.srv_address = ('localhost', 12345)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(self.srv_address)
        self.sock.listen(1)
        print("SSL Server started at", self.srv_address)

    def client_connect(self):
        """
        Allows a client to connect to this server
        """
        while True:
        	#Waits for the connection here
            connection, client_address = self.sock.accept()
            try:
                print('client address:', client_address)
                print('connection information:', connection)

            finally:
                print("Disconected")
                connection.close()
                break

if __name__ == "__main__":
    server = Server()
    server.client_connect()