import socket
import json
import sys
import zlib
import gzip
import secrets
import hmac

from hmac_generator import hmac_generator

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
		#may need to also send protocol version, session ID, compression method, and inital random numbers, though I am unsure what those would be
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
		print("Recived Hello")

	def send_public_keys(self):
		"""
		Generate public keys and send them to the server
		"""

		#generate keys here, the public keys used with RSA

		pack = {'type': 'public_keys'}
		pack['key_1_public'] = 'placeholder 1' #replace with keys
		pack['key_2_public'] = 'placeholder 2' #replace with keys
		pack = json.dumps(pack).encode('utf-8')
		self.srv_sock.sendall(pack)
		print("Sent Public Keys")

	def recive_public_keys(self):
		"""
		Recive the servers public keys
		"""
		pack = self.srv_sock.recv(20000)
		pack = json.loads(pack.decode('utf-8'))
		self.server_public_key_1 = pack['key_1_public']
		self.server_public_key_2 = pack['key_2_public']
		print("Recived Public Keys From Server")

	def send_symmetric_key(self):
		"""
		Encrypt a symmetric key and send it to the server
		"""
		key_length = 100 #not sure about what size the key should be, this will effect DES
		self.sym_key = secrets.randbits(key_length) #this is a secure way of generating random bits

		#encrypt the key here before sending with RSA

		pack = {'type': 'symmetric_key'}
		pack['key_symmetric'] = 'placeholder' #replace with encrypted key
		pack = json.dumps(pack).encode('utf-8')
		self.srv_sock.sendall(pack)
		print("Sent Symmetric Key")

	def confirm_hanshake(self):
		"""
		Receive confirmation from the server
		"""
		pack = self.srv_sock.recv(20000)
		pack = json.loads(pack.decode('utf-8'))
		print("Handshake complete")

	def send_message(self, message):
		"""
		Compress the message, generate its hash, encrypt, and send to server
		"""
		message_bytes = message.encode()
		compressed = gzip.compress(message_bytes)

		HMAC = hmac_generator.generate(self.sym_key.to_bytes(len(compressed), byteorder='big'), compressed)
		#encrypt the compressed message here

		pack = {'type': 'message'}
		pack['message'] = message
		pack['MAC'] = HMAC

		pack = json.dumps(pack).encode('utf-8')
		self.srv_sock.sendall(pack)

	def receive_message(self):
		"""
		receive a message from the server
		"""
		pack = self.srv_sock.recv(20000)
		# server terminated connection
		if pack.decode('ascii') == "":
			print("Disconnected")
			sys.exit()

		pack = json.loads(pack.decode('utf-8'))
		encrypted = pack['message']
		MAC = pack['MAC']

		# decrypt here
		# decompress here
		# message = decompressed.decode('utf-8')
		message = encrypted #remove this once it works

		#verify MAC here
		# recived_MAC = MAC_generator.generate(self.sym_key.to_bytes(len(compressed), byteorder='big'), compressed)
		# if(hmac.compare_digest(MAC, recived_MAC)):
		# 	print("MACS DON'T MATCH. TERMINATING")
		# 	print("Disconnected")
		# 	sys.exit()
		

		print("Received message from client:", message)
		
if __name__ == "__main__":
	client = Client()
	client.server_connect()

	"""
	Handshake Step
	"""
	#hello step
	client.send_hello()
	client.recive_hello()

	#public key step
	client.send_public_keys()
	client.recive_public_keys()

	#symmetric key step
	client.send_symmetric_key()
	client.confirm_hanshake()

	"""
	Banking Step
	"""
	#send message and wait for a respose, these messages can be a command for the server
	message = ""
	while True:
		message = input("Enter a command: ")
		if message == "exit":
			break
		client.send_message(message)
		client.receive_message()

	client.server_disconnect()