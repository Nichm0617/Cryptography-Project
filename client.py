import socket
import json
import sys
import zlib
import gzip
import secrets
import hmac

from hmac_generator import hmac_generator
from RSA import generate_keys, encrypt_rsa, decrypt_rsa
from DES import encrypt_des, decrypt_des
from Private_Higher_Auth import Decrypt_Auth

class Client:
	def __init__(self):
		self.srv_address = ('localhost', 12345)
		self.certificate = "0xdee761ae9b2cdea80x9e54f29337c2dd2a0x8b7f4910b8b5ec8c0xb5e26f02c78672440xcadf5c5228f5a8b30x76c664ab69a7605b0xccea27bf72e061810xd76304543ccc19e30x7c4d094a3f2437050xeae4fc05fe53763c0xf48740eec3e8bf45"

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
		pack['certificate'] = self.certificate
		pack['certificate_bytelen'] = 36
		pack['certificate_numlen'] = 86
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
		if not Decrypt_Auth(pack['certificate'], pack['certificate_numlen'], pack['certificate_bytelen']):
			print("Untrused Server, Shutting Down...")
			print("Disconnected")
			sys.exit()

		print("Recived Hello")

	def send_public_keys(self):
		"""
		Generate public keys and send them to the server
		"""

		public, private = generate_keys();
		self.rsa_private_key_1 = private[0]
		self.rsa_private_key_2 = private[1]
		pack = {'type': 'public_keys'}
		pack['key_1_public'] = public[0]
		pack['key_2_public'] = public[1]
		pack = json.dumps(pack).encode('utf-8')
		self.srv_sock.sendall(pack)
		print("Sent Public Keys")

	def recive_public_keys(self):
		"""
		Recive the servers public keys
		"""
		pack = self.srv_sock.recv(20000)
		pack = json.loads(pack.decode('utf-8'))
		self.rsa_server_public_key_1 = pack['key_1_public']
		self.rsa_server_public_key_2 = pack['key_2_public']
		print("Recived Public Keys From Server")

	def send_symmetric_key(self):
		"""
		Encrypt a symmetric key and send it to the server
		"""
		self.sym_key = secrets.randbits(260) #this is a secure way of generating random bits
		encrypted_sym_key = encrypt_rsa(self.sym_key, self.rsa_server_public_key_1, self.rsa_server_public_key_2)

		pack = {'type': 'symmetric_key'}
		pack['key_symmetric'] = encrypted_sym_key #replace with encrypted key
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
		compressed_num = int.from_bytes(compressed, byteorder='big')
		bytelen = len(compressed)
		numlen = len(str(compressed_num))
		HMAC = hmac_generator.generate(self.sym_key.to_bytes(len(compressed)*4, byteorder='big'), compressed)
		encrypted = encrypt_des(compressed_num, self.sym_key)

		pack = {'type': 'message'}
		pack['message'] = encrypted
		pack['numlen'] = numlen
		pack['bytelen'] = bytelen
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
		numlen = pack['numlen']
		bytelen = pack['bytelen']
		MAC = pack['MAC']

		decrypted = decrypt_des(encrypted, self.sym_key)
		decrypted_no_padding = int(str(decrypted)[:numlen])#remove padding
		compressed = int(decrypted_no_padding).to_bytes(bytelen, byteorder='big')
		decompress = gzip.decompress(compressed)
		original = decompress.decode()

		#verify MAC here
		recived_MAC = hmac_generator.generate(self.sym_key.to_bytes(len(compressed)*4, byteorder='big'), compressed)
		if(not hmac.compare_digest(MAC, recived_MAC)):
			print("MACS DON'T MATCH. TERMINATING")
			print("Disconnected")
			sys.exit()
		
		print("Received message from server:", original)
		
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
	#client.send_public_keys()
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