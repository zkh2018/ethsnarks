import math
from hashlib import sha256, sha512
import bitstring
from .field import FQ, SNARK_SCALAR_FIELD
from .jubjub import Point, JUBJUB_L, JUBJUB_Q, JUBJUB_E
from .pedersen import pedersen_hash_zcash_bytes, pedersen_hash_zcash_bits

"""
Implements Pure-EdDSA and Hash-EdDSA

The signer has two secret values:

    * k = Secret key
    * r = Per-(message,key) nonce

The signer provides a signature consiting of two values:

    * R = Point, image of `r*B`
    * s = Image of `r + (k*t)`

The signer provides the verifier with their public key:

    * A = k*B

Both the verifier and the signer calculate the common reference string:

    * t = H(R, A, M)

The nonce `r` is secret, and protects the value `s` from revealing the
signers secret key.

For Hash-EdDSA, the message `M` is compressed before H(R,A,M)

For further information see: https://ed2519.cr.yp.to/eddsa-20150704.pdf
"""


def eddsa_hash_message(data):
    return pedersen_hash_zcash_bytes('EdDSA_Verify.M', data)


def eddsa_hash_kM(k, M):
    """
    Hash the key and message to create `r`, the blinding factor for this signature.

    If the same `r` value is used more than once, the key for the signature is revealed.

    From: https://eprint.iacr.org/2015/677.pdf (EdDSA for more curves)    

    Page 3:

        (Implementation detail: To save time in the computation of `rB`, the signer
        can replace `r` with `r mod L` before computing `rB`.)
    """
    assert isinstance(k, FQ)
    if isinstance(M, Point):
        M = M.x.n.to_bytes(32, 'little')
    elif isinstance(M, bitstring.BitArray):
        M = M.tobytes()
    elif not isinstance(M, bytes):
        raise TypeError("Bad type for M: " + str(type(M)))

    khash = sha512(k.n.to_bytes(32, 'little')).digest()
    data = b''.join([khash, M])
    return int.from_bytes(sha512(data).digest(), 'little') % JUBJUB_L


def eddsa_tobits(M):
    if isinstance(M, Point):
        return M.x.bits()
    elif isinstance(M, FQ):
        return M.bits()
    elif isinstance(M, bytes):
        return bitstring.BitArray(M).bin.zfill(8)
    elif isinstance(M, bitstring.BitArray):
        return M.bin
    else:
        raise TypeError("Bad type for M: " + str(type(M)))


def eddsa_hash_RAM(R, A, M):
    """
    Hash R, A and M parameters.

        hash_RAM = H(R.x,A.x,M)

    # XXX: need to hash both X and Y coordinates

    @param R Signature point
    @param A Signers public key
    @param M Hashed message (Point)
    @returns Point
    """
    assert isinstance(R, Point)
    assert isinstance(A, Point)

    msg_parts = [R.x, A.x, M]

    bits = ''.join([eddsa_tobits(_) for _ in msg_parts])
    print('# bits is', bits)
    return pedersen_hash_zcash_bits("EdDSA_Verify.RAM", bits).x.n


def pureeddsa_verify(A, R, s, M, B):
    """
    Verifies an EdDSA signature

    Potential vulnerabilities:

        A is Infinity
            - When `A` is infinity, the signature for *every* message will be the same
            - All that's validated is `s` is the secret for `R`

        A is a low-order point
            - Forging a signature requires knowledge of the scalar value of the low-order point
            - There is a 1/# (where # is order of the point A) probability of passing validation
            - e.g. when A is of order 1 (Infinity), there is a 1/1 probability (100%)

        A, B or R are not of prime-order
            - TBD?

        s is 0

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
    
    hash_RAM = eddsa_hash_RAM(R, A, M)
    lhs = B * s
    rhs = R + (A * hash_RAM)
    return lhs == rhs


def eddsa_verify(A, R, s, m, B):
    """
    For HashEdDSA, where the message is compressed first
    """
    return pureeddsa_verify(A, R, s, eddsa_hash_message(m), B)


def pureeddsa_sign(M, k, B):
    """
    @param M Message being signed, bytes, (len(M)*8)%3 == 0
    @param k secret key
    @param B base point
    @param A public key, k*B
    """
    if not isinstance(k, FQ):
        raise TypeError("Invalid type for parameter k")

    # Strict parsing ensures key is in the prime-order group
    if k.n >= JUBJUB_L or k.n <= 0:
        raise RuntimeError("Strict parsing of k failed")

    A = B * k
    r = eddsa_hash_kM(k, M)         # r = H(k,M) mod L
    R = B * r                       # rB
    t = eddsa_hash_RAM(R, A, M)     # Bind the message to the nonce, public key and message
    S = (r + (k.n*t)) % JUBJUB_E    # S -> r + H(R,A,M)*k
    return [R, S, A]


def eddsa_sign(msg, k, B):
    """
    For HashEdDSA, where the message is compressed first
    """
    return pureeddsa_sign(eddsa_hash_message(msg), k, B)
