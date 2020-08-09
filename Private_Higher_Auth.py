import zlib
import gzip

from DES import encrypt_des, decrypt_des

def Decrypt_Auth(message, numlen, bytelen):
	Key = 0b0001001100110100010101110111100110011011101111001101111111110001
	decrypted = decrypt_des(message, Key)
	decrypted_no_padding = int(str(decrypted)[:numlen])#remove padding
	return decrypted_no_padding == 61277781330815824767295655865360935175012407472568160253120699204769525781217222328320 or decrypted_no_padding == 3652440391732370859795778665694815759524693653910866536716331948723553278361600