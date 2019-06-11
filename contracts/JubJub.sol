// Copyright (c) 2018 @HarryR
// Copyright (c) 2018 @yondonfu
// License: LGPL-3.0+

pragma solidity ^0.5.0;

library JubJub
{
    // A should be a square in Q
    uint256 constant public JUBJUB_A = 168700;

    // D should not be a square in Q
    uint256 constant public JUBJUB_D = 168696;

    uint256 constant public COFACTOR = 8;

    uint256 constant public Q = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // L * COFACTOR = Curve Order
    uint256 constant public L = 2736030358979909402780800718157159386076813972158567259200215660948447373041;


    function Generator()
        internal pure returns (uint256[2] memory)
    {
        return 
[17777552123799933955779906779655732241715742912184938656739573121738514868268,
 2626589144620713026669568689430873010625803728049924121243784502389097019475];
    }


    function submod(uint256 a, uint256 b, uint256 modulus)
        internal pure returns (uint256)
    {
        uint256 n = a;

        if (a <= b) {
            n += modulus;
        }

        return (n - b) % modulus;
    }


    function modexp(uint256 base, uint256 exponent, uint256 modulus)
        internal view returns (uint256)
    {
        uint256[1] memory output;
        uint256[6] memory input;
        input[0] = 0x20;
        input[1] = 0x20;
        input[2] = 0x20;
        input[3] = base;
        input[4] = exponent;
        input[5] = modulus;

        bool success;
        assembly {
            success := staticcall(sub(gas, 2000), 5, input, 0xc0, output, 0x20)
        }
        require(success);
        return output[0];
    }


    function inv(uint256 value, uint256 field_modulus)
        internal view returns (uint256)
    {
        return modexp(value, field_modulus - 2, field_modulus);
    }


    /**
    * Project X,Y point to extended twisted edwards coordinates
    */
    function pointToEtec( uint256 X, uint256 Y, uint256[4] memory output )
        internal pure
    {
        output[0] = X;
        output[1] = Y;
        output[2] = mulmod(X, Y, Q);
        output[3] = 1;
    }


    function scalarMultNAF(uint256 x, uint256 y, uint256 value)
        internal view returns (uint256, uint256)
    {
        uint256 booth_double = 2*value;
        require( booth_double > value );

        uint256 a = 1<<255;
        uint256 i = 0xFF;

        uint256[4] memory r = [uint256(0), uint256(1), uint256(0), uint256(1)];

        // Window, [-1, R, 1], where R stores the result/accumulator
        uint256[4][3] memory w;
        pointToEtec(x, y, w[2]);
        // Negate first point in window
        // Twisted Edwards Curves Revisited - HWCD, pg 5, section 3
        //  -(X : Y : T : Z) = (-X : Y : -T : Z)
        w[0] = [Q-x, y, Q-w[2][2], 1];

        while( a != 0 )
        {
            // Calculate a two-bit window of the Booth encoding (in right-to-left form)
            // See: https://eprint.iacr.org/2005/384.pdf
            int256 naf_a = int256((booth_double & a) >> i) - int256((value & a) >> i);
            a = a / 2;
            i -= 1;
            int256 naf_b = int256((booth_double & a) >> i) - int256((value & a) >> i);
            a = a / 2;
            i -= 1;

            if( (naf_a + naf_b) == 0 ) {
                naf_b = naf_a;
                naf_a = 0;
            }

            etecDouble(r, r);
            if( naf_a != 0 ) {
                etecAdd(r, w[uint256(1 + naf_a)], r);
            }

            etecDouble(r, r);
            if( naf_b != 0 ) {
                etecAdd(r, w[uint256(1 + naf_b)], r);
            }
        }
        return etecToPoint(r[0], r[1], r[2], r[3]);
    }


    function scalarMult(uint256 x, uint256 y, uint256 value)
        internal view returns (uint256, uint256)
    {
        uint256[4] memory p;
        pointToEtec(x, y, p);

        uint256[4] memory a = [uint256(0), uint256(1), uint256(0), uint256(1)];

        while (value != 0)
        {
            if ((value & 1) != 0)
            {
                etecAdd(a, p, a);
            }

            etecDouble(p, p);

            value = value / 2;
        }

        return etecToPoint(a[0], a[1], a[2], a[3]);
    }


    /**
    * Project X,Y point to extended affine coordinates
    */
    function pointToEac( uint256 X, uint256 Y )
        internal pure returns (uint256, uint256, uint256)
    {
        return (X, Y, mulmod(X, Y, Q));
    }


    /**
    * Extended twisted edwards coordinates to extended affine coordinates
    */
    function etecToEac( uint256 X, uint256 Y, uint256 T, uint256 Z )
        internal view returns (uint256, uint256, uint256)
    {
        Z = inv(Z, Q);
        return (mulmod(X, Z, Q), mulmod(Y, Z, Q), mulmod(T, Z, Q));
    }


    /**
    * Extended twisted edwards coordinates to extended affine coordinates
    */
    function etecToPoint( uint256 X, uint256 Y, uint256 T, uint256 Z )
        internal view returns (uint256, uint256)
    {
        Z = inv(Z, Q);
        return (mulmod(X, Z, Q), mulmod(Y, Z, Q));
    }


    function eacToPoint( uint256 X, uint256 Y, uint256 T )
        internal pure returns (uint256, uint256)
    {
        return (X, Y);
    }

    /**
     * @dev Double an ETEC point on the Baby-JubJub curve
     * Using the `dbl-2008-hwcd` method
     * https://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-dbl-2008-hwcd
     */
    function etecDouble(
        uint256[4] memory _p1,
        uint256[4] memory p2
    )
        internal
        pure
    {
        assembly {
            //let localA := 0x292FC
            let localQ := 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001
            let x := mload(_p1)
            let y := mload(add(_p1, 0x20))
            // T, is not used
            let z := mload(add(_p1, 0x60))

            // a = self.x * self.x
            let a := mulmod(x, x, localQ)

            // b = self.y * self.y
            let b := mulmod(y, y, localQ)

            // t0 = self.z * self.z
            // c = t0 * 2
            let c := mulmod(mulmod(z, z, localQ), 2, localQ)

            // d = JUBJUB_A * a
            let d := mulmod(0x292FC, a, localQ)

            // t1 = self.x + self.y
            let e := add(x, y)
            // t2 = t1 * t1
            // t3 = t2 - a
            // e = t3 - b
            e := addmod(
                    add(
                        mulmod(e, e, localQ),
                        sub(localQ, a)),
                    sub(localQ, b),
                    localQ)

            // g = d + b
            let g := add(d, b)

            // f = g - c
            let f := addmod(g, sub(localQ, c), localQ)

            // h = d - b
            let h := add(d, sub(localQ, b))

            // x3 <- E * F
            mstore(p2, mulmod(e, f, localQ))
            // y3 <- G * H
            mstore(add(p2, 0x20), mulmod(g, h, localQ))
            // t3 <- E * H
            mstore(add(p2, 0x40), mulmod(e, h, localQ))
            // z3 <- F * G
            mstore(add(p2, 0x60), mulmod(f, g, localQ))
        }
    }

    /**
     * @dev Add 2 etec points on baby jubjub curve
     * x3 = (x1y2 + y1x2) * (z1z2 - dt1t2)
     * y3 = (y1y2 - ax1x2) * (z1z2 + dt1t2)
     * t3 = (y1y2 - ax1x2) * (x1y2 + y1x2)
     * z3 = (z1z2 - dt1t2) * (z1z2 + dt1t2)
     */
    function etecAdd(
        uint256[4] memory _p1,
        uint256[4] memory _p2,
        uint256[4] memory p3
    ) 
        internal
        pure
    {
        assembly {
            let localQ := 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001
            let y1 := mload(add(_p1, 0x20))
            let y2 := mload(add(_p2, 0x20))
            //let localA := 0x292FC
            //let localD := 0x292F8

            // A <- x1 * x2
            let a := mulmod(mload(_p1), mload(_p2), localQ)

            // B <- y1 * y2
            let b := mulmod(y1, y2, localQ)

            // C <- d * t1 * t2
            let c := mulmod(mulmod(0x292F8, mload(add(_p1, 0x40)), localQ), mload(add(_p2, 0x40)), localQ)

            // D <- z1 * z2
            let d := mulmod(mload(add(_p1, 0x60)), mload(add(_p2, 0x60)), localQ)

            // E <- (x1 + y1) * (x2 + y2) - A - B
            let e := addmod(mulmod(add(mload(_p1), y1), add(mload(_p2), y2), localQ), add(sub(localQ, a), sub(localQ, b)), localQ)

            // F <- D - C
            let f := addmod(d, sub(localQ, c), localQ)

            // G <- D + C
            let g := add(d, c)

            // H <- B - a * A
            let h := add(b, sub(localQ, mulmod(0x292FC, a, localQ)))

            // x3 <- E * F
            mstore(p3, mulmod(e, f, localQ))
            // y3 <- G * H
            mstore(add(p3, 0x20), mulmod(g, h, localQ))
            // t3 <- E * H
            mstore(add(p3, 0x40), mulmod(e, h, localQ))
            // z3 <- F * G
            mstore(add(p3, 0x60), mulmod(f, g, localQ))
        }
    }

    function pointAdd(uint256[2] memory self, uint256[2] memory other)
        internal view returns (uint256[2] memory)
    {
        if (self[0] == 0 && self[1] == 0) {
            return other;
        } else if (other[0] == 0 && other[1] == 0)
        {
            return self;
        }

        uint256 x1x2 = mulmod(self[0], other[0], Q);
        uint256 y1y2 = mulmod(self[1], other[1], Q);

        // ----------------     

        //          (x1*y2 + y1*x2)
        uint256 x3_lhs = addmod(mulmod(self[0], other[1], Q), mulmod(self[1], other[0], Q), Q);

        //                                    JUBJUB_D*x1*x2*y1*y2
        uint256 dx1x2y1y2 = mulmod(mulmod(JUBJUB_D, x1x2, Q), y1y2, Q);

        //                          (Fq.ONE + JUBJUB_D*u1*u2*v1*v2)
        uint256 x3_rhs = addmod(1, dx1x2y1y2, Q);

        //                          (Fq.ONE - JUBJUB_D*u1*u2*v1*v2)
        uint256 y3_rhs = submod(1, dx1x2y1y2, Q);


        //          (y1*y2 - A*x1*x2)
        uint256 y3_lhs = submod(y1y2, mulmod(JUBJUB_A, x1x2, Q), Q);

        // ----------------

        // lhs / rhs
        return [
            // x3 = (x1*y2 + y1*x2)   / (Fq.ONE + D*x1*x2*y1*y2)
            mulmod(x3_lhs, inv(x3_rhs, Q), Q),

            // y3 = (y1*y2 - A*x1*x2) / (Fq.ONE - D*x1*x2*y1*y2)
            mulmod(y3_lhs, inv(y3_rhs, Q), Q)
        ];
    }
}
