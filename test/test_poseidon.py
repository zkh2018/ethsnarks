# Copyright (c) 2019 Harry Roberts
# License: LGPL-3.0+

import unittest

from ethsnarks.poseidon import DefaultParams, poseidon


class TestPedersenHash(unittest.TestCase):
    def test_constants(self):
        self.assertEqual(DefaultParams.constants_C[0], 14397397413755236225575615486459253198602422701513067526754101844196324375522)
        self.assertEqual(DefaultParams.constants_C[-1], 10635360132728137321700090133109897687122647659471659996419791842933639708516)
        self.assertEqual(DefaultParams.constants_M[0][0], 19167410339349846567561662441069598364702008768579734801591448511131028229281)
        self.assertEqual(DefaultParams.constants_M[-1][-1], 20261355950827657195644012399234591122288573679402601053407151083849785332516)
    

    def test_permutation(self):
        self.assertEqual(poseidon([1,2]), 12242166908188651009877250812424843524687801523336557272219921456462821518061)


if __name__ == "__main__":
    unittest.main()
