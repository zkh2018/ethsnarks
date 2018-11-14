#include "jubjub/point.hpp"
#include <openssl/sha.h>

using libff::bigint;


namespace ethsnarks {
    
namespace jubjub {


/**
* Returns true if the value is less than its modulo negative
*/
static bool is_negative( const FieldT& value )
{
    // XXX: why doesn't libsnark's bigint have a comparison operator...

    mpz_t a;
    mpz_init(a);
    value.as_bigint().to_mpz(a);

    mpz_t b;
    mpz_init(b);
    const auto negated_value = -value;
    negated_value.as_bigint().to_mpz(b);

    int res = mpz_cmp(a, b);

    mpz_clear(a);
    mpz_clear(b);

    return res < 0;
}



Point::Point(
    const FieldT& in_x,
    const FieldT& in_y
) :
    x(in_x),
    y(in_y)
{

}


const Point Point::infinity() const
{
    return Point(FieldT::zero(), FieldT::one());
}


const Point Point::neg() const
{
    return Point(-x, y);
}


const Point Point::dbl() const
{
    return add(*this);
}


const Point Point::add(const Point& other) const
{
    const Params params;

    const auto x3_rhs = FieldT::one() + params.d * x*other.x*y*other.y;
    const auto x3_lhs = x*other.y + y*other.x;

    const auto y3_lhs = y*other.y - params.a*x*other.x;
    const auto y3_rhs = FieldT::one() - params.d * x*other.x*y*other.y;

    return Point(x3_lhs * x3_rhs.inverse(), y3_lhs * y3_rhs.inverse());
}


const Point Point::from_hash( void *in_bytes, size_t n, const Params& params )
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
    return result.dbl().dbl().dbl();
}


const Point Point::from_y_always (const FieldT in_y, const Params& params)
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
            return Point(-tmp_x, tmp_y);            
        }
        return Point(tmp_x, tmp_y);
    }

    assert(0);
    abort();
}

// namespace jubjub
}

// namespace ethsnarks
}

