#include "gadgets/subadd.hpp"
#include "utils.hpp"

using namespace ethsnarks;


bool test_subadd( FieldT A, FieldT B, FieldT N, size_t n_bits, bool expected, const std::string& test_name )
{
	ProtoboardT pb;

	VariableT v_A = make_variable(pb, "A");
	pb.val(v_A) = A;

	VariableT v_B = make_variable(pb, "B");
	pb.val(v_B) = B;

	VariableT v_N = make_variable(pb, "N");
	pb.val(v_N) = N;

	subadd_gadget the_gadget(pb, n_bits, v_A, v_B, v_N, test_name);

	the_gadget.generate_r1cs_witness();
	the_gadget.generate_r1cs_constraints();

	if( pb.is_satisfied() != expected ) {
		std::cerr << "FAIL " << test_name << std::endl;
		return false;
	}

	return true;
}


int main( void )
{
	bool result = true;

	result &= test_subadd(100, 100, 10, 32, true, "1-bit");

	if( ! result ) {
		return 1;
	}
	return 0;
}
