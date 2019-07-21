#ifndef ETHSNARKS_WEBSNARK_HPP_
#define ETHSNARKS_WEBSNARK_HPP_

#include "ethsnarks.hpp"
#include <iostream>
#include <fstream>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>

namespace ethsnarks {


void websnark_write( std::ofstream &out, const ProvingKeyT &provingKey );

bool websnark_write( const std::string &filename, const ProvingKeyT &provingKey );

void websnark_write(
    std::ofstream &out,
    const libsnark::r1cs_primary_input<FieldT> &primary_input,
    const libsnark::r1cs_auxiliary_input<FieldT> &auxiliary_input );

bool websnark_write(
    const std::string &filename,
    const libsnark::r1cs_primary_input<FieldT> &primary_input,
    const libsnark::r1cs_auxiliary_input<FieldT> &auxiliary_input );


// namespace ethsnarks
}

// ETHSNARKS_WEBSNARK_HPP_
#endif
