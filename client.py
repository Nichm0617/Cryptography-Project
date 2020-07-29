import socket
import json
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

	def send_hello(self):
		"""
		Send the hello, this includes information needed for encryption
		"""
		pack = {'type': 'hello'}
		pack['sym_key_type'] = 'des'
		pack['key_exc_type'] = 'rsa'
		pack['hash_type'] = 'sha1'
		pack = json.dumps(pack).encode('utf-8')
		self.srv_sock.sendall(pack)
		print("Sent Hello")

	def recive_hello(self):
		"""
		Recieve the hello from the server, including essential info
		"""
		pack = self.srv_sock.recv(20000)
		pack = json.loads(pack.decode('utf-8'))
		hash_type = pack['hash_type']
		key_exec_type = pack['key_exc_type']
		sym_key_type = pack['sym_key_type']
		#now do something with this information here
		print("Recived Hello")

if __name__ == "__main__":
	client = Client()
	client.server_connect()
	"""
	Handshake Step
	"""
	client.send_hello()
	client.recive_hello()
	client.server_disconnect()