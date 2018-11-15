#ifndef JUBJUB_PEDERSEN_HASH_HPP_
#define JUBJUB_PEDERSEN_HASH_HPP_

// Copyright (c) 2018 @HarryR
// License: LGPL-3.0+

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

    const VariableT& result_x() const;

    const VariableT& result_y() const;
};


// namespace jubjub
}

// namespace ethsnarks
}

// JUBJUB_PEDERSEN_HASH_HPP_
#endif
