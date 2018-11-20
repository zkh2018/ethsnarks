import math
from hashlib import sha256, sha512
from .field import FQ, SNARK_SCALAR_FIELD
from .jubjub import Point, JUBJUB_L, JUBJUB_Q, JUBJUB_E
from .pedersen import pedersen_hash_zcash_bytes, pedersen_hash_zcash_bits

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


def eddsa_hash_message(data):
    return pedersen_hash_zcash_bytes('EdDSA_Verify.M', data)


def eddsa_hash_kM(k, M):
    assert isinstance(k, FQ)
    assert isinstance(M, Point)
    khash = sha512(k.n.to_bytes(32, 'little')).digest()
    data = b''.join([khash, M.x.n.to_bytes(32, 'little')])
    return int.from_bytes(sha512(data).digest(), 'little') % JUBJUB_L


def _point_x_to_bits(p):
    return bin(p.n)[2:][::-1].ljust(254, '0')


def eddsa_hash_RAM(R, A, M):
    """
    Hash R, A and M parameters.

        hash_RAM = H(R.x,A.x,M.x)

    @param R Signature point
    @param A Signers public key
    @param M Hashed message (Point)
    @returns Point
    """
    assert isinstance(R, Point)
    assert isinstance(A, Point)
    assert isinstance(M, Point)
    # Encode each point coordinate into 254 bits, then concatenate them
    bits = ''.join([
        _point_x_to_bits(R.x),
        _point_x_to_bits(A.x),
        _point_x_to_bits(M.x)])
    return pedersen_hash_zcash_bits("EdDSA_Verify.RAM", bits).x.n


def eddsa_verify(A, R, s, m, B):
    """
    @param A public key
    @param R Signature point
    @param s Signature scalar
    @param m Message being signed
    @param B base point
    """
    assert isinstance(R, Point)
    assert isinstance(s, int)
    assert s < JUBJUB_Q and s > 0
    assert isinstance(A, Point)

    M = eddsa_hash_message(m)
    hash_RAM = eddsa_hash_RAM(R, A, M)
    lhs = B * s
    rhs = R + (A * hash_RAM)
    return lhs == rhs


def eddsa_sign(msg, k, B, A=None):
    """
    @param msg Message being signed
    @param k secret key
    @param B base point
    @param A public key, k*B
    """
    if not isinstance(k, FQ):
        raise TypeError("Invalid type for parameter k")

    # Strict parsing ensures key is in the prime-order group
    if k.n >= JUBJUB_L or k.n <= 0:
        raise RuntimeError("Strict parsing of k failed")

    if A is None:
        A = k * B

    M = eddsa_hash_message(msg)     # hash message: H(msg) -> M
    r = eddsa_hash_kM(k, M)         # r = H(k,M) mod L
    R = B * r                       #
    t = eddsa_hash_RAM(R, A, M)     # Bind the message to the nonce, public key and message
    # XXX: there is a small chance that #E doesn't fit into #Q
    S = (r + (k.n*t)) % JUBJUB_E    # S -> r + H(R,A,M)*s
    return [R, S]
