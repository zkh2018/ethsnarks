import unittest
import logging
import sys
from web3 import Web3

from ethsnarks.field import FQ
from ethsnarks.mimc import mimc
from ethsnarks.mimc.contract import mimc_abi, mimc_contract


class TestMiMCEvm(unittest.TestCase):
    def _deploy_contract(self, w3, exponent):
        abi = mimc_abi(exponent)
        contract = w3.eth.contract(abi=abi, bytecode=mimc_contract(exponent))
        tx_hash = contract.constructor().transact()
        tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
        return w3.eth.contract(address=tx_receipt.contractAddress, abi=abi)

    def setUp(self):
        super(TestMiMCEvm, self).setUp()        
        w3 = Web3(Web3.EthereumTesterProvider())
        self.contract_e7 = self._deploy_contract(w3, 7)
        self.contract_e5 = self._deploy_contract(w3, 5)

    def test_e7(self):
        m_i, k_i = int(FQ.random()), int(FQ.random())
        python_result = mimc(m_i, k_i, e=7, R=91)
        evm_result = self.contract_e7.functions.MiMCpe7(m_i, k_i).call()
        self.assertEqual(evm_result, python_result)

    def test_e5(self):
        m_i, k_i = int(FQ.random()), int(FQ.random())
        python_result = mimc(m_i, k_i, e=5, R=110)
        evm_result = self.contract_e5.functions.MiMCpe5(m_i, k_i).call()
        self.assertEqual(evm_result, python_result)


if __name__ == "__main__":
    unittest.main()
