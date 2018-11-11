#ifndef ETHSNARKS_SHA256_MANY_HPP_
#define ETHSNARKS_SHA256_MANY_HPP_

// Copyright (c) 2018 HarryR
// License: LGPL-3.0+

#include "ethsnarks.hpp"


#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>                   // digest_variable
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_components.hpp>  // SHA256_default_IV
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>      // sha256_compression_function_gadget


namespace ethsnarks {


/**
* The following document was used as reference:
* http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf
*
* 1. Pad the message in the usual way: Suppose the length of the message M,
* in bits, is L. Append the bit "1" to the end of the message, and then K
* zero bits, where K is the smallest non-negative solution to the equation
*
*	L + 1 + K ≡ 448 mod 512
*
* To this append the 64-bit block which is equal to the number L written 
* in binary. For example, the (8-bit ASCII) message "abc" has length
*
*	8 * 3 = 24
*
* So it is padded with a one, then `448-(24+1) = 423` zero bits, and then
* its length to become the 512-bit padded message:
*
*	01100001 01100010 01100011 1 {00...0} {00...011000}
*									423		   64
*
* The length of the padded message should now be a multiple of 512 bits.
*/
void bits2blocks_padded(ProtoboardT& in_pb, const VariableArrayT& in_bits, std::vector<VariableArrayT>& out_blocks);


/**
* This gadget hashes an arbitrary number of bits, in a way which is compatible
* with the Ethereum and Python SHA2-256 implementations. It accepts a VariableArrayT
* of bits as inputs, any number of bits can be provided, and provides one
* output digest.
*/
class sha256_many : public GadgetT
{
public:
	typedef libsnark::sha256_compression_function_gadget<FieldT> HashT;
	typedef libsnark::digest_variable<FieldT> DigestT;

	std::vector<VariableArrayT> m_blocks;
	std::vector<HashT> m_hashers;
	std::vector<DigestT> m_outputs;

	sha256_many(
		ProtoboardT& in_pb,
		const VariableArrayT& in_bits,
		const std::string &annotation_prefix);

	const DigestT& result() const;

	void generate_r1cs_constraints();

	void generate_r1cs_witness();
};


// namespace
}


// ETHSNARKS_SHA256_MANY_HPP_
#endif