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
        make_basepoints(name, in_scalars.size(), in_params),
        in_scalars,
        FMT(annotation_prefix, ".commitment"))
{

}


const EdwardsPoint PedersenHash::make_basepoint(const char *name, unsigned int sequence, const Params& in_params)
{
    unsigned int name_sz = ::strlen(name);
    assert( name_sz < 28 );
    assert( sequence <= 0xFFFF );

    // At most 28 characters of name
    // Suffixed with the sequence number as a 16bit hexadecimal
    char data[33];
    ::sprintf(data, "%-28s%04X", name, sequence);

    return EdwardsPoint::from_hash(data, 32, in_params);
}


const std::vector<EdwardsPoint> PedersenHash::make_basepoints(const char *name, unsigned int n, const Params& in_params)
{
    std::vector<EdwardsPoint> ret;

    for( unsigned int i = 0; i < n; i++ )
    {
        ret.emplace_back(make_basepoint(name, i, in_params));
    }

    return ret;
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