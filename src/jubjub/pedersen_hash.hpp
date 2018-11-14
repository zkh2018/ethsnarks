#ifndef JUBJUB_PEDERSEN_HASH_HPP_
#define JUBJUB_PEDERSEN_HASH_HPP_

#include "jubjub/commitment.hpp"
#include "jubjub/point.hpp"


namespace ethsnarks {

namespace jubjub {


/**
* Windowed hash function using elliptic curves point multiplication
*
* For a given input of scalars, create an equivalent set of base points
* within a namespace.
*/
class PedersenHash : public GadgetT
{
public:
    Commitment m_commitment;

    PedersenHash(
        ProtoboardT& in_pb,
        const Params& in_params,
        const char *name,
        std::vector<VariableArrayT> in_scalars,
        const std::string& annotation_prefix);

    /**
    * Determine the Y coordinate for a base point sequence
    */
    static const Point make_basepoint(const char *name, unsigned int sequence, const Params& in_params);

    /**
    * Return a sequence of base points for the given namespace
    */
    static const std::vector<Point> make_basepoints(const char *name, unsigned int n, const Params& in_params);

    const VariableT& result_x() const;

    const VariableT& result_y() const;
};


// namespace jubjub
}

// namespace ethsnarks
}

// JUBJUB_PEDERSEN_HASH_HPP_
#endif
