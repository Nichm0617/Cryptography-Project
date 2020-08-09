import socket
import json
import gzip
import sys
import hmac

from hmac_generator import hmac_generator
from RSA import generate_keys, encrypt_rsa, decrypt_rsa
from DES import encrypt_des, decrypt_des
from Private_Higher_Auth import Decrypt_Auth

class Server:
	def __init__(self):
		self.srv_address = ('localhost', 12345)
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.bind(self.srv_address)
		self.sock.listen(1)
		self.balance = 0
		self.certificate = "0x3ff776cfb9c13e140xa6d92656f9446d7f0xbd6d77390ca641b50xe163e31bed2455130x9810d1fc0ca8d0050x3daa3513def568030x24999e0e479ec6760x7f4a9f0ad431d0c20x1c92061fc19a62920x52236f020c417bdd"
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
			#self.recive_public_keys(connection)
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
				if message == "exit":
					break


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
		pack['certificate'] = self.certificate
		pack['certificate_bytelen'] = 33
		pack['certificate_numlen'] = 79
		pack = json.dumps(pack).encode('utf-8')
		connection.sendall(pack)
		print("Sent Hello")

	def recive_hello(self, connection):
		"""
		Recive a cipher suit from client for the hello
		"""
		pack = connection.recv(20000)
		pack = json.loads(pack.decode('utf-8'))
		if not Decrypt_Auth(pack['certificate'], pack['certificate_numlen'], pack['certificate_bytelen']):
			print("Untrused Server, Shutting Down...")
			print("Disconnected")
			sys.exit()
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
		public, private = generate_keys();
		self.rsa_private_key_1 = private[0]
		self.rsa_private_key_2 = private[1]
		pack = {'type': 'public_keys'}
		pack['key_1_public'] = public[0]
		pack['key_2_public'] = public[1]
		pack = json.dumps(pack).encode('utf-8')
		connection.sendall(pack)
		print("Sent Public Keys")

	def recive_public_keys(self, connection):
		"""
		Recive public keys from the client
		"""
		pack = connection.recv(20000)
		pack = json.loads(pack.decode('utf-8'))
		self.rsa_client_public_key_1 = pack['key_1_public']
		self.rsa_client_public_key_2 = pack['key_2_public']
		print("Recived Public Keys From Client")

	def recive_symmetric_key(self, connection):
		"""
		Recive encrypted symmetric key from client
		"""
		pack = connection.recv(20000)
		pack = json.loads(pack.decode('utf-8'))
		encrypted_symmetric_key = pack['key_symmetric']
		self.sym_key = decrypt_rsa(encrypted_symmetric_key, self.rsa_private_key_1, self.rsa_private_key_2)

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
		

		print("Received message from client:", original)
		if(original.count(' ') == 0):
			self.send_message(conn, "Cammand Not Recognized")
			return
		command = original.split(' ', 1)[0]
		second_part = original.split(' ', 1)[1]
		if (command == "deposit"):
			if (second_part.isdigit()):
				self.balance = self.balance + int(second_part)
				self.send_message(conn, "Deposited $" + second_part + ".")
				return
			else:
				self.send_message(conn, "Invalid Number")
				return
		elif (command == "check" and second_part == "balance"):
			self.send_message(conn, "Current Balance: $" + str(self.balance) + ".")
			return
		elif (command == "withdraw"):
			if (second_part.isdigit() and int(second_part) <= self.balance):
				self.balance = self.balance - int(second_part)
				self.send_message(conn, "Withdrew $" + second_part + ".")
				return
			elif (int(second_part) > self.balance):
				self.send_message(conn, "Not Enough Funds.")
				return
			else:
				self.send_message(conn, "Invalid Number")
				return
		else:
			self.send_message(conn, "Cammand Not Recognized")


if __name__ == "__main__":
	server = Server()
	server.client_connect()