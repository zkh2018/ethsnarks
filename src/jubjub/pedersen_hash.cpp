#include "jubjub/pedersen_hash.hpp"

namespace ethsnarks {

namespace jubjub {


PedersenHash::PedersenHash(
    ProtoboardT& in_pb,
    const Params& in_params,
    const char *name,
    std::vector<VariableArrayT> in_scalars,
    const std::string& annotation_prefix
) :
    GadgetT(in_pb, annotation_prefix),
    m_commitment(
        in_pb, in_params,
        EdwardsPoint::make_basepoints(name, in_scalars.size(), in_params),
        in_scalars,
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


// namespace jubjub
}

// namespace ethsnarks
}