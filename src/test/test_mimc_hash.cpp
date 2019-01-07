// Copyright (c) 2018 HarryR
// License: LGPL-3.0+


#include "gadgets/mimc.hpp"
#include "stubs.hpp"

namespace ethsnarks {


bool test_mimc_hash()
{
    ProtoboardT pb;

    // Public inputs
    VariableT m_0 = make_variable(pb, FieldT("1"), "m_0");
    VariableT m_1 = make_variable(pb, FieldT("1"), "m_1");
    pb.set_input_sizes(2);

    // Private inputs
    VariableT iv = make_variable(pb, FieldT("0"), "iv");

    MiMC_hash_gadget the_gadget(pb, iv, {m_0, m_1}, "gadget");
    the_gadget.generate_r1cs_witness();
    the_gadget.generate_r1cs_constraints();

    auto result_expected = FieldT("4087330248547221366577133490880315793780387749595119806283278576811074525767");
    if( result_expected != pb.val(the_gadget.result()) )
    {
        std::cerr << "Unexpected result!\n";

        std::cerr << "Result: ";
        pb.val(the_gadget.result()).print();

        std::cerr << "Outputs:" << std::endl;
        int i = 0;
        for( auto& x : the_gadget.m_outputs )
        {
            std::cerr << i << " = ";
            pb.val(x).print();
            i += 1;
        }

        std::cerr << "Messages:" << std::endl;
        i = 0;
        for( auto& x : the_gadget.m_messages )
        {
            std::cerr << i << " = ";
            pb.val(x).print();
            i += 1;
        }

        return false;
    }

    std::cout << pb.num_constraints() << " constraints" << std::endl;

    if( ! pb.is_satisfied() ) {
        std::cerr << "Not satisfied!" << std::endl;
        return false;
    }

    return stub_test_proof_verify(pb);
}


// namespace ethsnarks
}


int main( int argc, char **argv )
{
    // Types for board
    ethsnarks::ppT::init_public_params();

    if( ! ethsnarks::test_mimc_hash() )
    {
        std::cerr << "FAIL\n";
        return 1;
    }

    std::cout << "OK\n";
    return 0;
}
