#include "jubjub/pedersen_hash.hpp"
#include "utils.hpp"


namespace ethsnarks {


/*
* Replicates `pedersen_hash_zcash_bytes('EdDSA_Verify.M', data)`
*/
bool test_jubjub_hash(const char *name, const uint8_t *data, size_t data_sz, const jubjub::EdwardsPoint& expected)
{
	ProtoboardT pb;
	const jubjub::Params params;
	const auto data_bitvector = bytes_to_bv(data, data_sz);
	const auto data_variables = VariableArray_from_bits(pb, data_bitvector, "data_bitvector");

	jubjub::PedersenHash the_gadget(pb, params, name, data_variables, "the_gadget");
	the_gadget.generate_r1cs_constraints();
	the_gadget.generate_r1cs_witness();

	bool is_ok = true;
	if( expected.x != pb.val(the_gadget.result_x()) )
	{
		std::cerr << "FAIL unexpected x" << std::endl;
		std::cerr << "Expected:"; expected.x.print();
		std::cerr << "  Actual:"; pb.val(the_gadget.result_x()).print();
		is_ok = false;
	}

	if( expected.y != pb.val(the_gadget.result_y())  )
	{
		std::cerr << "FAIL unexpected y" << std::endl;
		std::cerr << "Expected:"; expected.y.print();
		std::cerr << "  Actual:"; pb.val(the_gadget.result_y()).print();
		is_ok = false;
	}

	return is_ok && pb.is_satisfied();
}


bool testcases_jubjub_hash( void )
{
	struct TestcaseJubjubHash {
		const char *name;
		const char *data;
		jubjub::EdwardsPoint expected;
	};

	const std::vector<TestcaseJubjubHash> testcases = {
		{"EdDSA_Verify.m", "abc", {
			FieldT("9731843879694143436495111581488282877782046018277278061737612767920874642317"),
			FieldT("18679624827252625091380135611330259545748299185353272409619199893672152553192")}
		},
		{"EdDSA_Verify.m", "abcdefghijklmnopqrstuvwx", {
			FieldT("2924038456136707858258403902562106998409981203870787479135526690738568452881"),
			FieldT("14512385781738072049298244430820733351541114749367860936355491268534915271519")}
		}
	};

	size_t i = 0;

	for( const auto& test_case : testcases )
	{
		if( ! test_jubjub_hash(test_case.name, (uint8_t*)test_case.data, ::strlen(test_case.data), test_case.expected) ) {
			std::cerr << "Test case " << i << std::endl;
			return false;
		}

		i += 1;
	}

	return true;
}


// namespace ethsnarks
}


int main( void )
{
	ethsnarks::ppT::init_public_params();

	if( ! ethsnarks::testcases_jubjub_hash() )
	{
        std::cerr << "FAIL\n";
        return 1;
    }

    std::cout << "OK\n";
    return 0;
}
