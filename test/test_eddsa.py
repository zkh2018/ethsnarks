import unittest
from os import urandom


from ethsnarks.jubjub import JUBJUB_L, Point, FQ
from ethsnarks.eddsa import eddsa_sign, eddsa_verify


class TestEdDSA(unittest.TestCase):
	def test_signverify(self):
		B = Point.from_hash(b'eddsa_base')
		k = FQ.random(JUBJUB_L)
		m = urandom(32)
		R, S, A = eddsa_sign(m, k, B)

		self.assertTrue(eddsa_verify(A, R, S, m, B))


if __name__ == "__main__":
	unittest.main()
