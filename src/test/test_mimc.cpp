// Copyright (c) 2018 HarryR
// License: LGPL-3.0+

#include "utils.hpp"
#include "gadgets/mimc.hpp"

using ethsnarks::ppT;
using ethsnarks::FieldT;
using ethsnarks::ProtoboardT;
using ethsnarks::VariableT;
using ethsnarks::MiMC_gadget;
using ethsnarks::make_variable;


struct MiMC_TestCase
{
    FieldT plaintext;
    FieldT key;
    FieldT result;
};


bool test_MiMC(const MiMC_TestCase& test_case)
{
    ProtoboardT pb;

    const VariableT in_x = make_variable(pb, test_case.plaintext, "x");
    const VariableT in_k = make_variable(pb, test_case.key, "k");
    pb.set_input_sizes(2);

    MiMC_gadget the_gadget(pb, in_x, in_k, "the_gadget");
    the_gadget.generate_r1cs_witness();
    the_gadget.generate_r1cs_constraints();

    if( test_case.result != pb.val(the_gadget.result()) )
    {
        std::cerr << "Unexpected result!\n";
        return false;
    }

    std::cout << pb.num_constraints() << " constraints" << std::endl;

    return pb.is_satisfied();
}


int main( int argc, char **argv )
{
    ppT::init_public_params();

    const std::vector<MiMC_TestCase> test_cases = {
        {FieldT("0"), FieldT("0"), FieldT("0")}
    };

    int i = 0;
    for( const auto& tc : test_cases )
    {        
        if( ! test_MiMC(tc) )
        {
            std::cerr << "FAIL " << i << std::endl;
            return 1;
        }

        i += 1;
    }

    std::cout << "OK" << std::endl;
    return 0;
}
