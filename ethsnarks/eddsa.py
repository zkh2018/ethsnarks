import math
from hashlib import sha256
from .field import FQ, SNARK_SCALAR_FIELD
from .jubjub import Point, JUBJUB_L, JUBJUB_Q, JUBJUB_E

"""
Implements EdDSA

The signer has two secret values:

	* k = Secret key
	* r = Per-(message,key) nonce

The signer provides a signature consiting of two pairs:

	* R = Point, image of `r*B`
	* s = Image of `r + (k*t)`

The signer provides the verifier with their public key:

	* A = k*R

Both the verifier and the signer calculate the common reference string:

	* t = H(R, A, m)

The nonce `r` is secret, and protects the value `s` from revealing the
signers secret key.

For further information see: https://ed2519.cr.yp.to/eddsa-20150704.pdf
"""


EDDSA_B = math.floor(math.log2(SNARK_SCALAR_FIELD))


def encodeint(y):
	bits = [(y >> i) & 1 for i in range(EDDSA_B)]
	data = [bytes([sum([bits[i * 8 + j] << j for j in range(8)])]) for i in range(EDDSA_B//8)]
	return b''.join(data)


def make_bytes(arg):
	if isinstance(arg, bytes):
		return arg
	elif isinstance(arg, FQ):
		return encodeint(arg.n)
	elif isinstance(arg, Point):
		return make_bytes(arg.x) + make_bytes(arg.y)
	raise TypeError("Cannot convert unknown type to bytes: " + str(type(arg)))


def HashToBytes(*args):
	# XXX: The EdDSA spec requires the hash function outputs a 2b-bit output
	return sha256(b''.join([make_bytes(_) for _ in args])).digest()


def HashToInt(*args):
	"""
	Hashes arguments, returns first 250 least significant bits
	"""
	# Verify that any 250 bits will be less than `L`
	assert math.ceil(math.log2(JUBJUB_L)) > 250
	data = HashToBytes(*args)
	value = int.from_bytes(data, 'big')
	mask = (1<<250) - 1
	return value & mask


def eddsa_verify(A, R, s, m, B):
	"""
	@param A public key
	@param R Signature point
	@param s Signature scalar
	@param m Message being signed
	@param B base point
	"""
	assert isinstance(R, Point)
	A = A.as_point()

	assert s < JUBJUB_Q

	mhash = HashToBytes(m)
	t = HashToInt(R, A, mhash)
	lhs = B * s
	rhs = R + (A * t)
	return lhs == rhs


def eddsa_sign(m, S, B, A=None):
	"""
	@param m Message being signed
	@param k secret key
	@param B base point
	"""	
	if not isinstance(S, FQ):
		raise TypeError("Invalid type for parameter S")

	# Strict parsing ensures key is in the prime-order group
	if S.n >= JUBJUB_L or S.n <= 0:
		raise RuntimeError("Strict parsing of S failed")

	if A is None:
		A = S * B

	# XXX: secret scalars are multiples of 2^c (where c is the cofactor)
	# TODO: verify the bottom `c` bits are always cleared

	mhash = HashToBytes(m)
	khash = HashToBytes(S)
	r = HashToInt(khash, mhash)
	R = B * r
	t = HashToInt(R, A, mhash)
	s = ((S.n*t) + r) % JUBJUB_E
	return [R, s]
