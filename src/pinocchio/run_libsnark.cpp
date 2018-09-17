#include "circuit_reader.hpp"
#include "stubs.hpp"

using ethsnarks::ppT;
using ethsnarks::CircuitReader;
using ethsnarks::ProtoboardT;

using std::cerr;
using std::endl;
using std::string;


int main(int argc, char **argv)
{
	ProtoboardT pb;

	ppT::init_public_params();

	if( argc < 2 ) {
		cerr << "Usage: " << argv[0] << " <circuit.arith> <operation>" << endl;
	}

	const char *arith_file = argv[1];
	const string cmd(argv[2]);

	// Read the circuit, evaluate, and translate constraints
	CircuitReader reader(pb, argv[1], argv[2]);

	if( ! pb.is_satisfied() ) {
		cerr << "Error: not satisfied!" << endl;
		return 1;
	}

	if( ! ethsnarks::stub_test_proof_verify(pb) ) {
		cerr << "Error: failed to prove!" << endl;
		return  2;
	}

	return 0;
}

