#include "jubjub/isoncurve.hpp"
#include "stubs.hpp"

using ethsnarks::FieldT;

namespace ethsnarks {

	
bool test_jubjub_isoncurve(const FieldT x, const FieldT y, bool expected_result)
{
	jubjub::Params params;

	ProtoboardT pb;

	const auto var_x = make_variable(pb, x, "x");
	const auto var_y = make_variable(pb, y, "y");

	jubjub::IsOnCurve the_gadget(pb, params, var_x, var_y, "the_gadget");

	the_gadget.generate_r1cs_witness();
	the_gadget.generate_r1cs_constraints();

	return (pb.is_satisfied() == expected_result);
}


// namespace ethsnarks
}


typedef struct {
	FieldT x;
	FieldT y;
	bool expected_result;
} isoncurve_test_t;


int main( int argc, char **argv )
{
    ethsnarks::ppT::init_public_params();

    const isoncurve_test_t tests[] = {
    	{FieldT::zero(), FieldT::one(), true},
    	{FieldT::one(), FieldT::one(), false}
    };

    for( const auto& test : tests ) {    	
	    if( ! ethsnarks::test_jubjub_isoncurve(test.x, test.y, test.expected_result) )
	    {
	        std::cerr << "FAIL\n";
	        return 1;
	    }
    }

    std::cout << "OK\n";
    return 0;
}
