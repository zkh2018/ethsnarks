#include "jubjub/pedersen_hash.hpp"

namespace ethsnarks {

namespace jubjub {


PedersenHash::PedersenHash(
    ProtoboardT& in_pb,
    const Params& in_params,
    const char *name,
    const VariableArrayT in_scalar,
    const std::string& annotation_prefix
) :
    GadgetT(in_pb, annotation_prefix),
    m_commitment(
        in_pb, in_params,
        EdwardsPoint::make_basepoints(name, in_scalar.size(), in_params),
        in_scalar,
        FMT(annotation_prefix, ".commitment"))
{

}


const VariableT& PedersenHash::result_x() const
{
    return m_commitment.result_x();
}


const VariableT& PedersenHash::result_y() const
{
    return m_commitment.result_y();
}


void PedersenHash::generate_r1cs_constraints ()
{
    m_commitment.generate_r1cs_constraints();
}


void PedersenHash::generate_r1cs_witness ()
{
    m_commitment.generate_r1cs_witness();
}


// namespace jubjub
}

// namespace ethsnarks
}