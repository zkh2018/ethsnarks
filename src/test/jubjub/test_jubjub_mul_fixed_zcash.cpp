#include "jubjub/fixed_base_mul_zcash.hpp"
#include "utils.hpp"

namespace ethsnarks {

using jubjub::EdwardsPoint;
using jubjub::fixed_base_mul_zcash;
using jubjub::Params;


static bool test_jubjub_mul_fixed_zcash(ProtoboardT& pb, const VariableArrayT& bits, const EdwardsPoint& expectedResult)
{
    const Params params;
    const auto basepoints = EdwardsPoint::make_basepoints("test", 2, params);
    fixed_base_mul_zcash the_gadget(pb, params, basepoints, bits, "the_gadget");

    the_gadget.generate_r1cs_witness();
    the_gadget.generate_r1cs_constraints();

    if( pb.val(the_gadget.result_x()) != expectedResult.x ) {
        std::cerr << "x mismatch: ";
        pb.val(the_gadget.result_x()).print();
        std::cerr << std::endl;
        return false;
    }

    if( pb.val(the_gadget.result_y()) != expectedResult.y ) {
        std::cerr << "y mismatch: ";
        pb.val(the_gadget.result_y()).print();
        std::cerr << std::endl;
        return false;
    }

    std::cout << "\t" << pb.num_constraints() << " constraints" << std::endl;
    std::cout << "\t" << (pb.num_constraints() / float(bits.size())) << " constraints per bit" << std::endl;

    return pb.is_satisfied();
}


static bool test_jubjub_mul_fixed_zcash(const libff::bit_vector& bits, const EdwardsPoint& expectedResult)
{
    ProtoboardT pb;

    VariableArrayT scalar;
    scalar.allocate(pb, bits.size(), "scalar");
    scalar.fill_with_bits(pb, bits);

    return test_jubjub_mul_fixed_zcash(pb, scalar, expectedResult);
}


static bool test_jubjub_mul_fixed_zcash(const FieldT& s, size_t size, const EdwardsPoint& expectedResult)
{
    ProtoboardT pb;

    VariableArrayT scalar;
    scalar.allocate(pb, size, "scalar");
    scalar.fill_with_bits_of_field_element(pb, s);

    return test_jubjub_mul_fixed_zcash(pb, scalar, expectedResult);
}


static bool testcases_jubjub_mul_fixed_zcash()
{
    std::cout << "Test 252bit point" << std::endl;
    FieldT scalar("6453482891510615431577168724743356132495662554103773572771861111634748265227");
    EdwardsPoint expected = {
        FieldT("6545697115159207040330446958704617656199928059562637738348733874272425400594"),
        FieldT("16414097465381367987194277536478439232201417933379523927469515207544654431390")
    };
    if (!test_jubjub_mul_fixed_zcash(scalar, 252, expected)) {
        return false;
    }

    std::cout << "Test short (9bit) point" << std::endl;
    scalar = FieldT("267");
    expected = {
        FieldT("6790798216812059804926342266703617627640027902964190490794793207272357201212"),
        FieldT("2522797517250455013248440571887865304858084343310097011302610004060289809689")
    };
    if (!test_jubjub_mul_fixed_zcash(scalar, 9, expected)) {
        return false;
    }
    if (!test_jubjub_mul_fixed_zcash({1,1,0,1,0,0,0,0,1}, expected)) {
        return false;
    }

    std::cout << "Test point that needs padding (254bit)" << std::endl;
    scalar = FieldT("21888242871839275222246405745257275088548364400416034343698204186575808495616");
    expected = {
        FieldT("16322787121012335146141962340685388833598805940095898416175167744309692564601"),
        FieldT("7671892447502767424995649701270280747270481283542925053047237428072257876309")
    };
    if (!test_jubjub_mul_fixed_zcash(scalar, 255, expected)) {
        return false;
    }

    return true;
}

// namespace ethsnarks
}

int main( int argc, char **argv )
{
    // Types for board 
    ethsnarks::ppT::init_public_params();

    if( ! ethsnarks::testcases_jubjub_mul_fixed_zcash() )
    {
        std::cerr << "FAIL\n";
        return 1;
    }

    std::cout << "OK\n";
    return 0;
}