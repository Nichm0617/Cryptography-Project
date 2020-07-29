import socket
import sys
import time
import random
import json
import gzip
import pickle

class Client:
    def __init__(self):
        self.srv_address = ('localhost', 42010)

    def server_connect(self):
        self.srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv_sock.connect(self.srv_address)
        print("Connected")

    def server_disconnect(self):
    	self.srv_sock.close()
    	print("Disconnected")

    def hello_send(self):
		"""
		Send initial hello packet to server
		"""
		hello_packet = {'type': 'hello'}
		packet = encode_dict(packet)
		self.srv_sock.sendall(packet)

if __name__ == "__main__":
	client = Client()
	client.server_connect()
	client.server_disconnect()
	"""
	Handshake Step
	"""