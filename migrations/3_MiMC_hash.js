const MiMC_hash = artifacts.require('MiMC_hash.sol');
const MiMC_permutation = artifacts.require('MiMC_permutation.sol');

module.exports = function(deployer) {
	return deployer.then( async () => {
		await deployer.link(MiMC_permutation, MiMC_hash);
		await deployer.deploy(MiMC_hash);
	});
	
};
