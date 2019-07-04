// Copyright (c) 2019 HarryR
// License: LGPL-3.0+

#include "utils.hpp"
#include "gadgets/poseidon.hpp"
#include "stubs.hpp"

using ethsnarks::ppT;
using ethsnarks::FieldT;
using ethsnarks::ProtoboardT;
using ethsnarks::VariableT;
using ethsnarks::make_var_array;
using ethsnarks::Poseidon128;
using ethsnarks::stub_test_proof_verify;

using std::cout;
using std::cerr;


static bool test_constants( ) {
    ProtoboardT pb;
    const auto inputs = make_var_array(pb, 2, "input");
    Poseidon128<2,1> p(pb, inputs, "gadget");

    struct constant_test {
        const char *name;
        const FieldT& actual;
        const FieldT expected;
    };
    const constant_test tests[] = {
        {"C[0]", p.constants.C[0], FieldT("14397397413755236225575615486459253198602422701513067526754101844196324375522")},
        {"C[-1]", p.constants.C.back(), FieldT("10635360132728137321700090133109897687122647659471659996419791842933639708516")},
        {"M[0][0]", p.constants.M[0], FieldT("19167410339349846567561662441069598364702008768579734801591448511131028229281")},
        {"M[-1][-1]", p.constants.M.back(), FieldT("20261355950827657195644012399234591122288573679402601053407151083849785332516")}
    };

    for( const auto& t : tests )
    {
        if( t.actual != t.expected )
        {
            cerr << "FAIL Constant check " << t.name << " != "; t.expected.print();
            cerr << " value is: "; t.actual.print();
            return false;
        }
    }    

    return true;
}


static bool test_prove_verify() {
    ProtoboardT pb;

    auto var_inputs = make_var_array(pb, "input", {1, 2});

    Poseidon128<1,2> the_gadget(pb, var_inputs, "gadget");    
    the_gadget.generate_r1cs_witness();
    the_gadget.generate_r1cs_constraints();
    if( ! pb.is_satisfied() ) {
        return false;
    }

    #ifdef DEBUG
    ethsnarks::dump_pb_r1cs_constraints(pb);
    #endif

    cout << pb.num_constraints() << " constraints\n";
    return stub_test_proof_verify( pb );
}


int main( int argc, char **argv )
{
    ppT::init_public_params();

    if( ! test_constants() )
        return 1;

    if( ! test_prove_verify() )
        return 2;

    const auto actual = Poseidon128<2,1>::permute({1, 2});
    const FieldT expected("12242166908188651009877250812424843524687801523336557272219921456462821518061");
    if( actual[0] != expected ) {
        cerr << "poseidon([1,2]) incorrect result, got ";
        actual[0].print();
    }

    std::cout << "OK" << std::endl;
    return 0;
}
