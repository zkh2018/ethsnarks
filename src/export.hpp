#ifndef ETHSNARKS_EXPORT_HPP_
#define ETHSNARKS_EXPORT_HPP_

#include "ethsnarks.hpp"

namespace ethsnarks {

std::string HexStringFromBigint( LimbT _x);

std::string outputPointG1AffineAsHex( G1T _p );

std::string outputPointG2AffineAsHex( G2T _p );

std::string proof_to_json( ProofT &proof, PrimaryInputT &input );

std::string vk2json( VerificationKeyT &vk );

void vk2json_file( VerificationKeyT &vk, const std::string &path );

bool r1cs2json(libsnark::protoboard<FieldT>& pb, const std::string& path);

bool witness2json(libsnark::protoboard<FieldT>& pb, const std::string& path);

bool pk_bellman2ethsnarks(const std::string& bellman_pk_file, const std::string& pk_file);

bool pk_alt2mcl(const std::string& alt_pk_file, const std::string& mcl_pk_file);
bool pk_mcl2nozk(const std::string& mcl_pk_file, const std::string& nozk_pk_file);

}

#endif
