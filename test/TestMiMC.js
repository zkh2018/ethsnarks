const MiMCpe7_evm = artifacts.require("MiMCpe7_evm");
const MiMCpe5_evm = artifacts.require("MiMCpe5_evm");


contract("MiMCpe7_evm", () => {
	let contract;

	before(async () => {
		contract = await MiMCpe7_evm.new();
	});

	describe('MiMCpe7', () => {
		it('works', async () => {
			const x = "0x82fe7600c00459988362f29375cb4db2324362ea5e0e3e4fd9bba41fffd13eb";
			const k = "0x4c27419ddb3bb02ee994297b254e2d8648c40d494cada169e4f35f97944085";
			const expected = "1949609bfcfbcd9d0b7934768516661b9564d6d3779c4380cbceab5b3de44498";

			const cost = await contract.MiMCpe7.estimateGas(x, k);
			console.log("      Cost", cost)

			const result = await contract.MiMCpe7(x, k);
			assert.equal(result.toString('hex'), expected);
		});
	})
});


contract("MiMCpe5_evm", () => {
	let contract;

	before(async () => {
		contract = await MiMCpe5_evm.new();
	});

	describe('MiMCpe5', () => {
		it('works', async () => {
			const x = "0x82fe7600c00459988362f29375cb4db2324362ea5e0e3e4fd9bba41fffd13eb";
			const k = "0x4c27419ddb3bb02ee994297b254e2d8648c40d494cada169e4f35f97944085";
			const expected = "26eaa6904f1ed35fc571fe913b2e6c2c4b1497ddde33aae79b24dec77dffd8d5";

			const cost = await contract.MiMCpe5.estimateGas(x, k);
			console.log("      Cost", cost)

			const result = await contract.MiMCpe5(x, k);
			assert.equal(result.toString('hex'), expected);
		});
	})
});