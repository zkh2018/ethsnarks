// Copyright (c) 2018 HarryR
// License: LGPL-3.0+

#include "gadgets/sha256_many.hpp"


using libsnark::SHA256_block_size;
using libsnark::SHA256_digest_size;


namespace ethsnarks {


/*
* begin with the original message of length L bits
* append a single '1' bit
* append K '0' bits, where K is the minimum number >= 0 such that L + 1 + K + 64 is a multiple of 512
* append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
* So given a 512bit message, the _final_padding_512 is another block of 512 bits
* which begins with a '1' bit, and ends with a 64bit big-endian number representing '512'
*/
void bits2blocks_padded(ProtoboardT& in_pb, const VariableArrayT& in_bits, size_t block_size, std::vector<VariableArrayT>& out_blocks)
{
    assert( (in_bits.size() % 8) == 0 );
    assert( in_bits.size() > 0 );

    size_t total_bits = in_bits.size() + 1 + 64;
    if( total_bits % block_size != 0 ) {
        // Number of padding bits (K), to fill the block
        total_bits += (block_size - (total_bits % block_size));
    }
    size_t n_blocks = total_bits / block_size;

    size_t in_bits_offset = 0;
    for( size_t i = 0; i < n_blocks; i++ )
    {
        out_blocks.emplace_back();
        auto& block = out_blocks[out_blocks.size() - 1];
        block.resize(block_size);

        size_t block_end = (in_bits_offset + block_size);
        size_t bits_end = block_end;
        if( bits_end > in_bits.size() ) {
            bits_end = in_bits.size();
        }

        size_t j = 0;
        if( in_bits_offset < in_bits.size() ) {
            while( in_bits_offset < bits_end ) {
                block[j++].index = in_bits[in_bits_offset++].index;
            }
        }

        // Allocate remaining bits in the block
        while( in_bits_offset < block_end )
        {
            block[j].allocate(in_pb, FMT("padding", "[%zu]", in_bits_offset));

            // Set the bit immediately after the input bits to 1
            if( in_bits_offset == in_bits.size() ) {
                in_pb.val(block[j]) = FieldT::one();
            }

            j += 1;
            in_bits_offset += 1;
        }
    }

    auto& last_block = out_blocks[out_blocks.size() - 1];

    // Add 64bit big-endian length specifier to the end
    size_t bitlen = in_bits.size();
    const libff::bit_vector bitlen_bits = libff::int_list_to_bits({
        (bitlen >> 56) & 0xFF,
        (bitlen >> 48) & 0xFF,
        (bitlen >> 40) & 0xFF,
        (bitlen >> 32) & 0xFF,
        (bitlen >> 24) & 0xFF,
        (bitlen >> 16) & 0xFF,
        (bitlen >> 8) & 0xFF,
        bitlen & 0xFF,
    }, 8);
    size_t k = 0;
    for( size_t j = (SHA256_block_size - 64); j < SHA256_block_size; j++ )
    {
        in_pb.val(last_block[j]) = bitlen_bits[k++];
    }
}


sha256_many::sha256_many(
        ProtoboardT& in_pb,
        const VariableArrayT& in_bits,
        const std::string &annotation_prefix
) :
    GadgetT(in_pb, annotation_prefix)
{
    bits2blocks_padded(in_pb, in_bits, SHA256_block_size, m_blocks);

    // Construct hashers, inputs and outputs
    for( size_t i = 0; i < m_blocks.size(); i++ )
    {
        // Allocate output digests
        m_outputs.emplace_back(
            in_pb,
            SHA256_digest_size,
            FMT(annotation_prefix, ".outputs[%zu]", i));

        // First round includes IV as input
        // Further rounds include previous digest as input
        m_hashers.emplace_back(
            in_pb,
            i == 0 ? SHA256_default_IV(in_pb) : m_outputs[i - 1].bits,
            m_blocks[i],
            m_outputs[i],
            FMT(annotation_prefix, ".hasher[%zu]", i));
    }
}


const sha256_many::DigestT& sha256_many::result() const
{
    return m_outputs[ m_outputs.size() - 1 ];
}


void sha256_many::generate_r1cs_constraints()
{
    for( size_t i = 0; i < m_hashers.size(); i++ )
    {
        m_hashers[i].generate_r1cs_constraints();

        m_outputs[i].generate_r1cs_constraints();
    }
}


void sha256_many::generate_r1cs_witness()
{
    for( size_t i = 0; i < m_hashers.size(); i++ )
    {
        auto is_last = i == (m_hashers.size() - 1);

        m_hashers[i].generate_r1cs_witness();
    }
}


// namespace ethsnarks
}
