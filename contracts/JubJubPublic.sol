// Copyright (c) 2018 @HarryR
// Copyright (c) 2018 @yondonfu
// License: LGPL-3.0+

pragma solidity ^0.5.0;

import "./JubJub.sol";

contract JubJubPublic
{
    function pointAddViaEtec(uint256[2] memory a, uint256[2] memory b)
        public view returns (uint256[2] memory)
    {
        uint256[4] memory p;
        uint256[4] memory q;
        uint256[4] memory r;
        JubJub.pointToEtec(a[0], b[0], p);
        JubJub.pointToEtec(a[0], b[0], q);
        JubJub.etecAdd(p, q, r);

        (p[0], p[1]) = JubJub.etecToPoint(r[0], r[1], r[2], r[3]);
        return [p[0], p[1]];
    }

    function pointAdd(uint256[2] memory a, uint256[2] memory b)
        public view returns (uint256[2] memory)
    {
        return JubJub.pointAdd(a, b);
    }

    function scalarMult(uint256[2] memory a, uint256 s)
        public view returns (uint256, uint256)
    {
        return JubJub.scalarMult(a[0], a[1], s);
    }
}
