const web3 = require("web3");


const SEED = "mimc";
const NROUNDS = 91;
const SNARK_SCALAR_FIELD = Web3.utils.toBN("21888242871839275222246405745257275088548364400416034343698204186575808495617");


const getConstants = (seed, nRounds) => {
    if (typeof seed === "undefined") seed = SEED;
    if (typeof nRounds === "undefined") nRounds = NROUNDS;

    const cts = new Array(nRounds);
    let c = Web3.utils.keccak256(SEED);

    for (let i=1; i<nRounds; i++)
    {
        c = Web3.utils.keccak256(c);
        const n1 = Web3.utils.toBN(c).mod(SNARK_SCALAR_FIELD);
        const c2 = Web3.utils.padLeft(Web3.utils.toHex(n1), 64);
        cts[i] = bigInt(Web3.utils.toBN(c2).toString());
    }

    cts[0] = bigInt(0);
    return cts;
};

