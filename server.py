import socket
import json
import sys

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
				"""
				Handshake part
				"""
				# Exchange Hello part
				self.recive_hello(connection)
				self.send_hello(connection)
			finally:
				connection.close()
				print("Disconected")
				break

	def send_hello(self, connection):
		"""
		Send the selected suit back to client
		"""
		pack = {'type': 'hello'}
		pack['sym_key_type'] = self.sym_key_type
		pack['key_exc_type'] = self.key_exc_type
		pack['hash_type'] = self.hash_type
		pack = json.dumps(pack).encode('utf-8')
		connection.sendall(pack)
		print("Sent Hello")

	def recive_hello(self, connection):
		"""
		Recive a cipher suit from client for the hello
		"""
		pack = connection.recv(20000)
		pack = json.loads(pack.decode('utf-8'))
		if(pack['sym_key_type'] == 'des' and pack['key_exc_type'] == 'rsa' and pack['hash_type'] == 'sha1'):
			self.sym_key_type = pack['sym_key_type']
			self.key_exc_type = pack['key_exc_type']
			self.hash_type = pack['hash_type']
			print("Recived Hello")
		else:
			print("Incompatible Suite. Shutting Down")
			print("Disconected")
			connection.close()

if __name__ == "__main__":
	server = Server()
	server.client_connect()