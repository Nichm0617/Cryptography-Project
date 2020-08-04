import hmac
import hashlib

class hmac_generator:

	def generate(sym_key, enc_message):
		digest_maker = hmac.new(sym_key, enc_message, hashlib.sha1)

		digest = digest_maker.hexdigest()
		return digest