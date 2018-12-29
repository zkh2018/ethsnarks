const Web3 = require("web3");

const SEED = "mimc";
const NROUNDS = 91;
const SNARK_SCALAR_FIELD = Web3.utils.toBN("21888242871839275222246405745257275088548364400416034343698204186575808495617");


const getConstants = (seed, nRounds) => {
    if (typeof seed === "undefined") seed = SEED;
    if (typeof nRounds === "undefined") nRounds = NROUNDS;

    const cts = new Array(nRounds);
    var c = SEED;

    for (let i=0; i<nRounds; i++)
    {
        c = Web3.utils.keccak256(c);
        cts[i] = Web3.utils.toBN(c);
    }

    return cts;
};

console.log(getConstants());
