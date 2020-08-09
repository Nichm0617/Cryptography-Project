# RSA implementation for CNS project

import random
import math

# Generating Large Primes:
# https://medium.com/@prudywsh/how-to-generate-big-prime-numbers-miller-rabin-49e6e6af32fb

# Probabilistic Primality Test using Miller-Rabin:
def is_prime(n, k=64):

	# test if n is not even
	if n == 2 or n == 3:
		return True
	if n <= 1 or n % 2 == 0:
		return False

	# find r and s for Miller-Rabin
	s = 0
	r = n - 1
	while r & 1 == 0:
		s += 1
		r //= 2

	# do k tests:
	for _ in range(k):
		a = random.randrange(2, n - 1)
		x = pow(a, r, n)
		if x != 1 and x != n - 1:
			j = 1
			while j < s and x != n - 1:
				x = pow(x, 2, n)
				if x == 1:
					return False
				j += 1
			if x != n - 1:
				return False

	# if k tests fail to show n is composite, assume it is prime:
	return True

# Generate prime candidate with a given length (in bits):
def generate_prime_candidate(length):
	
	p = random.getrandbits(length)
	p |= (1 << length - 1) | 1
	# random string of bits starting and ending with 1
	return p

# Generate prime number of a desired length (512 bits):
def generate_prime_number(length=512):
	
	p = 4
	while not is_prime(p, 64):
		p = generate_prime_candidate(length)
	return p

# modulo inverse to quickly calculate d from ed (mod phi) = 1:
def mod_inverse(a, m):

	if math.gcd(a, m) != 1:
		return None
	u1, u2, u3 = 1, 0, a
	v1, v2, v3 = 0, 1, m

	while v3 != 0:
		q = u3 // v3
		v1, v2, v3, u1, u2, u3 = (
			u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
	return u1 % m

# Key Generation:
def generate_keys():
	
	# generate two large primes, p and q, such that n = pq is 1024 bits
	p = generate_prime_number(512)
	q = generate_prime_number(512)

	# compute n = pq and phi = (p-1)(q-1)
	n = p * q
	phi = (p - 1) * (q - 1)

	# choose an encryption key, e, such that 1 < e < phi and gcd(e, phi) = 1:
	e = phi
	while math.gcd(e, phi) != 1:
		e = random.randrange(2, phi)

	# compute the decryption key, d, such that ed (mod phi) = 1:
	d = mod_inverse(e, phi)

	public = (e, n)
	private = (d, n)
	return public, private

# Encryption algorithm:
def encrypt_rsa(m, e, n):
    c = pow(m, e, n)
    return c

# Decryption algorithm:
def decrypt_rsa(c, d, n):
    p = pow(c, d, n)
    return p

# print("Generate_keys:\n")
# public, private = generate_keys()
# print("Public Key = " + str(public))
# print("Private Key = " + str(private))

# print("\nEncrypting Message 12345678987654321:\n")
# message = 12345678987654321
# c = encrypt(message, public[0], public[1])
# p = decrypt(c, private[0], private[1])
# print("Ciphertext = " + str(c))
# print("Plaintext = " + str(p))