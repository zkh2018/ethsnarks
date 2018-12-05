# (Baby) JubJub gadgets

## Gadgets

 * [adder.hpp](adder.hpp) - affine twisted Edwards point addition
 * [commitment.hpp](commitment.hpp) - Point Commitment (for Schnorr etc.)
 * [conditional_point.hpp](conditional_point.hpp) - Conditional point, if bit is 0 return Inifnity, otherwise the point
 * [doubler.hpp](doubler.hpp) - Twisted Edwards affine doubling
 * [eddsa.hpp](eddsa.hpp) - EdDSA signature verification
 * [fixed_base_mul.hpp](fixed_base_mul.hpp) - Multiply a fixed point by a variable scalar (affine twisted Edwards coordinates)
 * [fixed_base_mul_zcash.hpp](fixed_base_mul_zcash.hpp) - Multiply a fixed point by a variable scalar (ZCash scheme, for 'Pedersen Hash') 
 * [isoncurve.hpp](isoncurve.hpp) - Verify if a point is on the curve (is it valid?)
 * [montgomery.hpp](montgomery.hpp) - Montgomery point operations: `MontgomeryAdder`, `MontgomeryToEdwards`
 * [notloworder.hpp](notloworder.hpp) - Verify that point isn't a low-order point
 * [pedersen_hash.cpp](pedersen_hash.cpp) - Pedersen Hash, using ZCash scheme
 * [scalarmult.hpp](scalarmult.hpp) - Affine scalar multiplication, variable point and variable scalar
 * [validator.hpp](validator.hpp) - Point validation (IsOnCurve and NotLowOrder)


## EdDSA parameters

See: [EdDSA for more curves](https://ed25519.cr.yp.to/eddsa-20150704.pdf)

* q = 21888242871839275222246405745257275088548364400416034343698204186575808495617

* b = 255
* Encoding GF\(p\): 254-bit little-endian encoding of {0..q-1} for Fq elements
* `H` : with 2b-bit output, can be implementation specific
* c = 3
* n = 254
* a = 168700
* d = 168696
* l = 21888242871839275222246405745257275088614511777268538073601725287587578984328
* B (base point)
  * x = 16540640123574156134436876038791482806971768689494387082833631921987005038935
  *  y = 20819045374670962167435360035096875258406992893633759881276124905556507972311
* Prehash function `H'` : *"ZCash Pedersen Hash"* scheme for `M = H(m)` and `H(R,A,M)`

The base point `B` is derived deterministically from the curve parameters using the following Sage math script: [ejubjub.sage](../.appendix/ejubjub.sage)
