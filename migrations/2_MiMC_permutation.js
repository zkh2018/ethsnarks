const MiMC_permutation = artifacts.require('MiMC_permutation.sol');
const MiMCpe5_evm = artifacts.require('MiMCpe5_evm');
const MiMCpe7_evm = artifacts.require('MiMCpe7_evm');

module.exports = function(deployer) {
    return deployer.then( async () => {
        await deployer.deploy(MiMC_permutation);
        await deployer.deploy(MiMCpe5_evm);
        await deployer.deploy(MiMCpe7_evm);
    }); 
};
