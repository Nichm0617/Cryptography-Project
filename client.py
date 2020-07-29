import socket
import sys

class Client:
    def __init__(self):
        self.srv_address = ('localhost', 12345)

    def server_connect(self):
        self.srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv_sock.connect(self.srv_address)
        print("Connected")

    def server_disconnect(self):
    	self.srv_sock.close()
    	print("Disconnected")

if __name__ == "__main__":
	client = Client()
	client.server_connect()
	client.server_disconnect()
	"""
	Handshake Step
	"""