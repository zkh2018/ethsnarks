#include "websnark.hpp"
#include "utils.hpp"

using ethsnarks::ProtoboardT;
using ethsnarks::ProverF;
using ethsnarks::make_variable;
using ethsnarks::ConstraintT;
using ethsnarks::websnark_write;

int main( int argc, char **argv )
{
	ethsnarks::ppT::init_public_params();

	ProtoboardT pb;
	const auto &var = make_variable(pb, 1, "var");
	pb.add_r1cs_constraint(ConstraintT(var, var, var), "var 1 or 0");

	const std::string filename_key("test_websnark.key");
	const std::string filename_witness("test_websnark.wit");
    const auto keypair = ProverF(pb.get_constraint_system());

    if( ! websnark_write(filename_key, keypair.pk) ) {
    	std::cerr << "ERROR: Cannot write proving key in websnark format, to file: " << filename_key << std::endl;
    	return 1;
    }

    if( ! websnark_write(filename_witness, pb.primary_input(), pb.auxiliary_input()) ) {
    	std::cerr << "ERROR: Cannot write witness in websnark format, to file: " << filename_witness << std::endl;
    	return 1;
    }

    return 0;
}
