#ifndef JUBJUB_PEDERSEN_HASH_HPP_
#define JUBJUB_PEDERSEN_HASH_HPP_

// Copyright (c) 2018 @HarryR
// License: LGPL-3.0+

#include "jubjub/point.hpp"
#include "jubjub/fixed_base_mul_zcash.hpp"


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
    fixed_base_mul_zcash m_commitment;

    PedersenHash(
        ProtoboardT& in_pb,
        const Params& in_params,
        const char *name,
        const VariableArrayT in_scalars,
        const std::string& annotation_prefix);

    const VariableT& result_x() const;

    const VariableT& result_y() const;

    void generate_r1cs_constraints ();

	void generate_r1cs_witness ();
};


// namespace jubjub
}

// namespace ethsnarks
}

// JUBJUB_PEDERSEN_HASH_HPP_
#endif
