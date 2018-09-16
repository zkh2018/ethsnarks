#include "circuit_reader.hpp"
#include "stubs.hpp"


int main(int argc, char **argv)
{
	ProtoboardT pb;

	ethsnarks::ppT::init_public_params();

	// Read the circuit, evaluate, and translate constraints
	CircuitReader reader(argv[1], argv[2], pb);

	if( ! pb.is_satisfied() ) {
		std::cerr << "Error: not satisfied!" << std::endl;
		return 1;
	}

	if( ! ethsnarks::stub_test_proof_verify(pb) ) {
		std::cerr << "Error: failed to prove!" << std::endl;
		return  2;
	}

	return 0;
}

