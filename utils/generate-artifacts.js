const fs = require('fs');
const path = require('path');
const Artifactor = require('truffle-artifactor');

async function _artifact_generate (artifactor, name) {
    const abi_e5 = JSON.parse(fs.readFileSync('build/evm/'+name+'.abi', 'utf8'));
    const contract_e5 = fs.readFileSync('build/evm/'+name+'.contract', 'utf8');
    await artifactor.save({
        contractName: name+'_evm',
        abi: abi_e5,
        unlinked_binary: contract_e5,
    });
};

async function main () {
    const contractsDir = path.join(__dirname, '..', 'build/contracts');
    let artifactor = new Artifactor(contractsDir);

    await _artifact_generate(artifactor, 'MiMCpe5');
    await _artifact_generate(artifactor, 'MiMCpe7');
}

main();
