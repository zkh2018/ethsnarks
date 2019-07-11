import unittest
import logging
import sys
from web3 import Web3
from ethsnarks.poseidon import poseidon
from ethsnarks.poseidon.contract import poseidon_abi, poseidon_contract

"""
def vm_logger():
    # Enable trace logging for EVM opcodes
    from eth.tools.logging import DEBUG2_LEVEL_NUM
    level = DEBUG2_LEVEL_NUM
    logger = logging.getLogger()
    logger.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    logger.addHandler(handler)

vm_logger()
"""


class TestPoseidonEvm(unittest.TestCase):
    def setUp(self):
        super(TestPoseidonEvm, self).setUp()        
        w3 = Web3(Web3.EthereumTesterProvider())

        bytecode = poseidon_contract()
        abi = poseidon_abi()

        PoseidonContract = w3.eth.contract(abi=abi, bytecode=bytecode)
        tx_hash = PoseidonContract.constructor().transact()
        tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)        
        self.contract = w3.eth.contract(
            address=tx_receipt.contractAddress,
            abi=abi)

    def test_basic(self):
        inputs = [1,2]
        python_result = poseidon(inputs)
        evm_result = self.contract.functions.poseidon(inputs).call()
        self.assertEqual(evm_result, python_result)


if __name__ == "__main__":
    unittest.main()
