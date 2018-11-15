#include "jubjub/point.hpp"
#include "utils.hpp"
#include <openssl/sha.h>

using libff::bigint;


namespace ethsnarks {
    
namespace jubjub {



EdwardsPoint::EdwardsPoint(
    const FieldT& in_x,
    const FieldT& in_y
) :
    x(in_x),
    y(in_y)
{

}


const EdwardsPoint EdwardsPoint::infinity() const
{
    return EdwardsPoint(FieldT::zero(), FieldT::one());
}


const EdwardsPoint EdwardsPoint::neg() const
{
    return EdwardsPoint(-x, y);
}


const EdwardsPoint EdwardsPoint::dbl(const Params& params) const
{
    return add(*this, params);
}


const EdwardsPoint EdwardsPoint::add(const EdwardsPoint& other, const Params& params) const
{
    const auto x3_rhs = FieldT::one() + params.d * x*other.x*y*other.y;
    const auto x3_lhs = x*other.y + y*other.x;

    const auto y3_lhs = y*other.y - params.a*x*other.x;
    const auto y3_rhs = FieldT::one() - params.d * x*other.x*y*other.y;

    return EdwardsPoint(x3_lhs * x3_rhs.inverse(), y3_lhs * y3_rhs.inverse());
}


const EdwardsPoint EdwardsPoint::from_hash( void *in_bytes, size_t n, const Params& params )
{
    // Hash input
    SHA256_CTX ctx;
    uint8_t output_digest[SHA256_DIGEST_LENGTH];
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, in_bytes, n);
    SHA256_Final(output_digest, &ctx);

    // Convert output to MPZ
    mpz_t output_as_mpz;
    mpz_init(output_as_mpz);
    mpz_import(
        output_as_mpz,              // output
        SHA256_DIGEST_LENGTH,       // count
        1,                          // order
        sizeof(output_digest[0]),   // size
        1,                          // endian (1, MSB first)
        0,                          // nails
        output_digest);             // op

    // Then convert to bigint
    const bigint<FieldT::num_limbs> y_bigint(output_as_mpz);
    const FieldT y(y_bigint);

    // Finally derive point from that coordinate
    const auto result = from_y_always(y, params);
    mpz_clear(output_as_mpz);

    // Multiply point by cofactor, ensures it's on the prime-order subgroup
    return result.dbl(params).dbl(params).dbl(params);
}


const EdwardsPoint EdwardsPoint::from_y_always (const FieldT in_y, const Params& params)
{
    mpz_t modulus;
    mpz_init(modulus);
    in_y.mod.to_mpz(modulus);

    for( int i = 0; i < 10; i++ )
    {
        const auto tmp_y = in_y + i;
        const auto ysq = tmp_y.squared();
        const auto lhs = (ysq - 1);
        const auto rhs = ((params.d * ysq) - params.a);
        const auto xx = lhs * rhs.inverse();

        // Verify if xx is square, if not, increment y, continue
        // No square when: jacobi(xx, p) == -1
        mpz_t a;
        mpz_init(a);
        xx.as_bigint().to_mpz(a);

        if( mpz_jacobi(a, modulus) == -1 ) {
            mpz_clear(a);
            continue;
        }

        // Otherwise, return the point
        mpz_clear(modulus);
        mpz_clear(a);

        // Always return the lexicographically larger point
        // If the X value is considered negative, negate it
        const auto tmp_x = xx.sqrt();
        if( is_negative(tmp_x) ) {
            return EdwardsPoint(-tmp_x, tmp_y);
        }
        return EdwardsPoint(tmp_x, tmp_y);
    }

    assert(0);
    abort();
}


const MontgomeryPoint EdwardsPoint::as_montgomery(const Params& in_params) const
{
    if(y == FieldT::one())
    {
        return {FieldT::zero(), FieldT::zero()}; //This should be infinity
    }
    else if (x.is_zero())
    {
        return {FieldT::zero(), FieldT::zero()};
    }
    else {
        // The mapping is defined as above.
        //
        // (x, y) -> (u, v) where
        //      u = (1 + y) / (1 - y)
        //      v = u / x
        FieldT u = (FieldT::one() + y) * (FieldT::one() - y).inverse();
        return {u, in_params.scale * u * x.inverse()};
    }
}


// --------------------------------------------------------------------


MontgomeryPoint::MontgomeryPoint(const FieldT& in_x, const FieldT& in_y)
: x(in_x), y(in_y)
{}


const EdwardsPoint MontgomeryPoint::as_edwards(const Params& in_params) const
{
    return {
        in_params.scale * x * y.inverse(),
        (x - FieldT::one()) * (x + FieldT::one()).inverse()
    };
}


// namespace jubjub
}

// namespace ethsnarks
}

