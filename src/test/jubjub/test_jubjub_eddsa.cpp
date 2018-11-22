#include "jubjub/eddsa.hpp"
#include "utils.hpp"

using ethsnarks::jubjub::EdwardsPoint;
using ethsnarks::jubjub::VariablePointT;
using ethsnarks::jubjub::EdDSA_Verify;
using ethsnarks::bytes_to_bv;
using ethsnarks::FieldT;


namespace ethsnarks {


bool test_jubjub_eddsa(
    const EdwardsPoint& B,
    const EdwardsPoint& A,
    const EdwardsPoint& R,
    const FieldT& s,
    const libff::bit_vector& msg
) {
    ProtoboardT pb;
    jubjub::Params params;

    auto msg_var_bits = make_var_array(pb, msg.size(), "msg_var_bits");
    msg_var_bits.fill_with_bits(pb, msg);

    const auto A_var = A.as_VariablePointT(pb, "A");

    const auto R_var = R.as_VariablePointT(pb, "R");

    auto s_var_bits = make_var_array(pb, FieldT::size_in_bits(), "s_var_bits");
    s_var_bits.fill_with_bits_of_field_element(pb, s);

    EdDSA_Verify the_gadget(pb, params, B, A_var, R_var, s_var_bits, msg_var_bits, "the_gadget");

    the_gadget.generate_r1cs_witness();
    the_gadget.generate_r1cs_constraints();

    std::cout << "Num constraints: " << pb.num_constraints() << std::endl;

    return pb.is_satisfied();
}


// namespace ethsnarks
}


int main( int argc, char **argv )
{
    ethsnarks::ppT::init_public_params();

    // Base point
    const EdwardsPoint B(
        FieldT("21609035313031231356478892405209584931807557563713540183143349090940105307553"),
        FieldT("845281570263603011277359323511710394920357596931617398831207691379369851278"));

    // Public key
    const EdwardsPoint A(
        FieldT("5616630816018221659484394091994939318481030030481519242876140465113436048304"),
        FieldT("8476221375891900895034976644661703008703725320613595264559419965669922411183"));

    // Signature point
    const EdwardsPoint R(
        FieldT("17883110238616315155327756854433987355427639458557188556819876765548551765197"),
        FieldT("11833558192785987866925773659755699683735551950878443451361314529874236222818"));

    const FieldT s("9920504625278683304895036460477595239370241328717115039061027107077120437288");

    const char *msg = "abc";
    const auto msg_bits = bytes_to_bv((const uint8_t*)msg, strlen(msg));

    if( ! ethsnarks::test_jubjub_eddsa(B, A, R, s, msg_bits) )
    {
        std::cerr << "FAIL\n";
        return 1;
    }

    std::cout << "OK\n";
    return 0;
}
