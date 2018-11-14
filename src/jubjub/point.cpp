#include "jubjub/point.hpp"


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


const Point Point::neg() const
{
    return Point(-x, y);
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

