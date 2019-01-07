const MiMC = artifacts.require('MiMC.sol');
const JubJub = artifacts.require('JubJub.sol');
const MerkleTree = artifacts.require('MerkleTree.sol');

module.exports = function(deployer) {
	deployer.deploy(MiMC).then(() => {
        deployer.deploy(MerkleTree);
    });
};
