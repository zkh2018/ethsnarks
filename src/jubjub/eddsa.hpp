#ifndef JUBJUB_EDDSA_HPP_
#define JUBJUB_EDDSA_HPP_

#include "ethsnarks.hpp"

#include "gadgets/field2bits_strict.hpp"

#include "jubjub/params.hpp"
#include "jubjub/validator.hpp"
#include "jubjub/point.hpp"
#include "jubjub/pedersen_hash.hpp"
#include "jubjub/scalarmult.hpp"
#include "jubjub/fixed_base_mul.hpp"
#include "jubjub/adder.hpp"

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>


namespace ethsnarks {

namespace jubjub {


class EdDSA_Verify : public GadgetT
{
public:
    const EdwardsPoint& m_B;
    const VariablePointT m_A;
    const VariablePointT m_R;
    const VariableArrayT m_s;
    const VariableArrayT m_msg;

    // Intermediate gadgets
    PointValidator m_validator_R;           // IsValid(R)
    PedersenHash m_msg_hashed;              // M = H(m)
    field2bits_strict m_msg_hashed_bits;    // R_bits = BITS(R.y)
    fixed_base_mul m_lhs;                   // lhs = B*s
    field2bits_strict m_R_x_bits;           // R_x_bits = BITS(R.x)
    field2bits_strict m_R_y_bits;           // R_y_bits = BITS(R.y)
    field2bits_strict m_A_x_bits;           // A_x_bits = BITS(A.x)
    field2bits_strict m_A_y_bits;           // A_y_bits = BITS(A.y)
    PedersenHash m_hash_t;                  // t = H(R, A, M)
    field2bits_strict m_t_bits;             // t_bits = BITS(t)
    ScalarMult m_At;                        // A*t
    PointAdder m_rhs;                       // R + (A*t)

    EdDSA_Verify(
        ProtoboardT& in_pb,
        const Params& in_params,
        const EdwardsPoint& in_base,    // B
        VariablePointT in_A,            // A
        VariablePointT in_R,            // R
        VariableArrayT in_s,            // s
        VariableArrayT in_msg,          // m
        const std::string& annotation_prefix);

    void generate_r1cs_constraints();

    void generate_r1cs_witness();
};


// namespace jubjub
}

// namespace ethsnarks
}

// JUBJUB_EDDSA_HPP_
#endif
