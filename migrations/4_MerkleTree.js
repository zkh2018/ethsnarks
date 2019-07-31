const MiMC_hash = artifacts.require('MiMC_hash.sol');
const MerkleTree = artifacts.require('MerkleTree.sol');

module.exports = function(deployer) {
	return deployer.then( async () => {
		await deployer.link(MiMC_hash, MerkleTree);
		await deployer.deploy(MerkleTree);
	});	
};
