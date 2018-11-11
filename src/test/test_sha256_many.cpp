#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include "gadgets/sha256_many.cpp"
#include "utils.hpp"


#include <openssl/sha.h>
#include <openssl/rand.h>

using libsnark::digest_variable;
using libsnark::block_variable;
using libsnark::SHA256_digest_size;
using libsnark::SHA256_block_size;

using ethsnarks::ppT;

static const size_t SHA256_block_size_bytes = SHA256_block_size / 8;
static const size_t SHA256_digest_size_bytes = SHA256_digest_size / 8;


namespace ethsnarks {


bool test_sha256_many()
{
    // Create a block_size'd buffer of random bytes
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    uint8_t input_buffer[SHA256_block_size_bytes];
    uint8_t output_digest[SHA256_digest_size_bytes];
    assert( SHA256_block_size / 2 == SHA256_digest_size );

    // Perform full round of SHA256 using the test vector
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, "test", 4);
    SHA256_Final(input_buffer, &ctx);
    memcpy(&input_buffer[SHA256_digest_size_bytes], input_buffer, SHA256_digest_size_bytes);
    // 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a089f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'

    // Then verify the result is as expected
    // sha256(sha256('test').digest() + sha256('test').digest()).digest()
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, input_buffer, sizeof(input_buffer));    
    SHA256_Final(output_digest, &ctx);
    uint8_t output_expected[] = {
        0xD2, 0x94, 0xF6, 0xE5, 0x85, 0x87, 0x4F, 0xE6,
        0x40, 0xBE, 0x4C, 0xE6, 0x36, 0xE6, 0xEF, 0x9E,
        0x3A, 0xDC, 0x27, 0x62, 0x0A, 0xA3, 0x22, 0x1F,
        0xDC, 0xF5, 0xC0, 0xA7, 0xC1, 0x1C, 0x6F, 0x67};
    if( memcmp(output_digest, output_expected, sizeof(output_digest)) != 0 ) {
        printf("output_digest mismatch!\n");
        return false;
    }

    // ----------------------------------------------------------------
    // Setup circuit to do full_output = SHA256(left, right)

    ProtoboardT pb;

    // Fill array of input bits
    VariableArrayT block;
    block.allocate(pb, SHA256_block_size, "block");
    const libff::bit_vector block_bits = bytes_to_bv(input_buffer, SHA256_block_size_bytes);
    block.fill_with_bits(pb, block_bits);

    sha256_many the_gadget(pb, block, "the_gadget");
    the_gadget.generate_r1cs_witness();
    the_gadget.generate_r1cs_constraints();

    std::cout << "Number of blocks: " << the_gadget.m_blocks.size() << std::endl;
    for( size_t b = 0; b < the_gadget.m_blocks.size(); b++ )
    {
        std::cout << "Block " << b << std::endl;

        const auto& block = the_gadget.m_blocks[b];
        for( size_t j = 0; j < SHA256_block_size; j++ ) {
            std::cout << (pb.val(block[j]) == FieldT::one() ? "1" : "0");
        }

        std::cout << std::endl;
    }

    // ----------------------------------------------------------------    

    // Binds circuit satisfiability to whether or not the full output
    // matches what was computed by OpenSSL's SHA256
    auto output_digest_bits = bytes_to_bv(output_digest, SHA256_digest_size_bytes);

    // Verify the result matches what we computed
    auto full_output_bits = the_gadget.result().get_digest();
    uint8_t full_output_bytes[SHA256_digest_size_bytes];
    bv_to_bytes(full_output_bits, full_output_bytes);
    if( memcmp(full_output_bytes, output_digest, SHA256_digest_size_bytes) != 0 ) {
        std::cout << "full_output_bytes mismatch" << std::endl;
        print_bytes("Expected: ", SHA256_digest_size_bytes, output_digest);
        print_bytes("Actual: ", SHA256_digest_size_bytes, full_output_bytes);
        return false;
    }

	// Show the two, as bits, side-by-side
    print_bv("full (r1cs)", full_output_bits);
    print_bv("full (SHA2)", output_digest_bits);

    std::cout << "Constraints: " << pb.num_constraints() << "\n";
    std::cout << "Variables: " << pb.num_variables() << "\n";
    std::cout << "Inputs: " << pb.num_inputs() << "\n";

    for( auto& var : pb.primary_input() )
    {
        std::cout << "  var " << var << "\n";
    }

    uint8_t output_buffer[SHA256_digest_size_bytes];
    bv_to_bytes(full_output_bits, output_buffer);
    printf("Output digest bytes: ");
    for( uint8_t x : output_buffer )
    {
        printf("%02X", x);
    }
    printf("\n");

    return pb.is_satisfied();
}

// namespace ethsnarks
}

int main( int argc, char **argv )
{
	ppT::init_public_params();

    /*
    if( ! ethsnarks::test_bits2blocks() ) {
        std::cerr << "FAIL (bits2blocks)" << std::endl;
        return 1;
    }
    */

	if( ! ethsnarks::test_sha256_many() )
	{
		std::cerr << "FAIL (sha256_many)" << std::endl;
		return 1;
	}

	std::cout << "OK" << std::endl;
	return 0;
}
