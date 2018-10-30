"""
    assert_eq!(bits.len(), 3);
    assert_eq!(coords.len(), 8);

    // Calculate the index into `coords`
    let i =
    match (bits[0].get_value(), bits[1].get_value(), bits[2].get_value()) {
        (Some(a_value), Some(b_value), Some(c_value)) => {
            let mut tmp = 0;
            if a_value {
                tmp += 1;
            }
            if b_value {
                tmp += 2;
            }
            if c_value {
                tmp += 4;
            }
            Some(tmp)
        },
        _ => None
    };

    // Allocate the x-coordinate resulting from the lookup
    let res_x = AllocatedNum::alloc(
        cs.namespace(|| "x"),
        || {
            Ok(coords[*i.get()?].0)
        }
    )?;

    let mut x_coeffs = [E::Fr::zero(); 8];

    synth::<E, _>(3, coords.iter().map(|c| &c.0), &mut x_coeffs);

    let precomp = Boolean::and(cs.namespace(|| "precomp"), &bits[1], &bits[2])?;

    let one = CS::one();

    cs.enforce(
        || "x-coordinate lookup",
        |lc| lc + (x_coeffs[0b001], one)
                + &bits[1].lc::<E>(one, x_coeffs[0b011])
                + &bits[2].lc::<E>(one, x_coeffs[0b101])
                + &precomp.lc::<E>(one, x_coeffs[0b111]),
        |lc| lc + &bits[0].lc::<E>(one, E::Fr::one()),
        |lc| lc + res_x.get_variable()
                - (x_coeffs[0b000], one)
                - &bits[1].lc::<E>(one, x_coeffs[0b010])
                - &bits[2].lc::<E>(one, x_coeffs[0b100])
                - &precomp.lc::<E>(one, x_coeffs[0b110]),
    );
"""

from math import ceil, log2
from os import urandom
from ethsnarks.field import FQ
from ethsnarks.jubjub import Point

N = 8
nbits = ceil(log2(N))

c = [FQ.random() for _ in range(0, N)]


def sumfq(x):
    r = FQ(0)
    for _ in x:
        r = r + _
    return r


for i in range(0, 8):
    b = [int(_) for _ in bin(i)[2:].rjust(nbits, '0')][::-1]
    r = c[i]
    precomp = b[0] * b[1]
    precomp1 = b[0] * b[2]
    precomp2 = b[1] * b[2]
    precomp3 = precomp * b[2]
    A = [
        c[0b000],
        (b[0] * -c[0]),
        (b[0] * c[1]),

        (b[1] * -c[0]),
        (b[1] * c[2]),

        (precomp * (-c[1] + -c[2] + c[0] + c[3])),

        (b[2] * (-c[0] + c[4])),

        (precomp1 * (c[0] - c[1] - c[4] + c[5])),

        (precomp2 * (c[0] - c[2] - c[4] + c[6])),

        (precomp3 * ( -c[0] + c[1] + c[2] - c[3] + c[4] - c[5] - c[6] + c[7] ))
    ]
    assert sumfq(A) == r
