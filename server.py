import socket
import json
import gzip
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

			print('client address:', client_address)
			print('connection information:', connection)
			"""
			Handshake part
			"""
			# Exchange Hello part
			self.recive_hello(connection)
			self.send_hello(connection)

			#public key exchange part
			self.recive_public_keys(connection)
			self.send_public_keys(connection)

			#symmetric key step
			self.recive_symmetric_key(connection)
			self.send_confirmation(connection)

			"""
			Banking Step
			"""
			#This should later on be replaced with options for all the commands the client might send
			message = ""
			while True:
				self.receive_message(connection)
				message = input("Enter a command: ")
				if message == "exit":
					break
				self.send_message(connection, message)


			connection.close()
			print("Disconected")
			break

	def send_hello(self, connection):
		"""
		Send the selected suit back to client
		"""
		#may need to also send protocol version, session ID, compression method, and inital random numbers
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

	def send_public_keys(self, connection):
		"""
		Generate public keys and send them to the client
		"""
		#generate keys here
		pack = {'type': 'public_keys'}
		pack['key_1_public'] = 'placeholder 1' #replace with keys
		pack['key_2_public'] = 'placeholder 2'
		pack = json.dumps(pack).encode('utf-8')
		connection.sendall(pack)
		print("Sent Public Keys")

	def recive_public_keys(self, connection):
		"""
		Recive public keys from the client
		"""
		pack = connection.recv(20000)
		pack = json.loads(pack.decode('utf-8'))
		self.client_public_key_1 = pack['key_1_public']
		self.client_public_key_2 = pack['key_2_public']
		print("Recived Public Keys From Client")

	def recive_symmetric_key(self, connection):
		"""
		Recive encrypted symmetric key from client
		"""
		pack = connection.recv(20000)
		pack = json.loads(pack.decode('utf-8'))
		encrypted_symmetric_key = pack['key_symmetric']
		#decrypt and save key here
		print("Recived Symmetric Key")

	def send_confirmation(self, connection):
		"""
		Send confirmation that handshake is complete
		"""
		pack = {'type': 'confirmation'}
		pack = json.dumps(pack).encode('utf-8')
		pack = connection.sendall(pack)
		print("Handshake complete")

	def send_message(self, conn, message):
		"""
		Compress the message, generate its hash, encrypt, and send to client
		"""
		message_bytes = message.encode()
		compressed = gzip.compress(message_bytes)

		#compute MAC of the compressed message here
		#encrypt the compressed message here

		pack = {'type': 'message'}
		pack['message'] = message
		pack['MAC'] = 'placeholder'

		pack = json.dumps(pack).encode('utf-8')
		conn.sendall(pack)

	def receive_message(self, conn):
		"""
		receive a message from the client
		"""
		pack = conn.recv(20000)
		# Client terminated connection
		if pack.decode('ascii') == "":
			print("Disconnected")
			sys.exit()
			
		pack = json.loads(pack.decode('utf-8'))

		encrypted = pack['message']

		# decrypt here
		# decompress here
		# message = decompressed.decode('utf-8')
		message = encrypted #remove this once it works

		#verify MAC here

		print("Received message from client:", message)


if __name__ == "__main__":
	server = Server()
	server.client_connect()