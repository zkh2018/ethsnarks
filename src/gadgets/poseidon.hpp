#ifndef ETHSNARKS_POSEIDON_HPP_
#define ETHSNARKS_POSEIDON_HPP_

#include "ethsnarks.hpp"
#include "crypto/blake2b.h"

namespace ethsnarks {

using libsnark::linear_combination;
using libsnark::linear_term;


struct PoseidonConstants
{
	std::vector<FieldT> C; // `t` constants
	std::vector<FieldT> M; // `t * t` matrix of constants
};


class FifthPower_gadget : public GadgetT {
public:
	const VariableT x2;
	const VariableT x4;
	const VariableT x5;

	FifthPower_gadget(
		ProtoboardT &pb,
		const std::string& annotation_prefix
	) :
		GadgetT(pb, annotation_prefix),
		x2(make_variable(pb, FMT(annotation_prefix, ".x2"))),
		x4(make_variable(pb, FMT(annotation_prefix, ".x4"))),
		x5(make_variable(pb, FMT(annotation_prefix, ".x5")))
	{		
	}

	void generate_r1cs_constraints(const libsnark::linear_combination<FieldT>& x) const
	{
		pb.add_r1cs_constraint(ConstraintT(x, x, x2), ".x^2 = x * x");
		pb.add_r1cs_constraint(ConstraintT(x2, x2, x4), ".x^4 = x2 * x2");
		pb.add_r1cs_constraint(ConstraintT(x, x4, x5), ".x^5 = x * x4");
	}

	void generate_r1cs_witness(const FieldT& val_x) const
    {
    	const auto val_x2 = val_x * val_x;
    	const auto val_x4 = val_x2 * val_x2;
    	const auto val_x5 = val_x4 * val_x;
    	this->pb.val(x2) = val_x2;
    	this->pb.val(x4) = val_x4;
    	this->pb.val(x5) = val_x5;
    }

    const VariableT& result() const 
    {
    	return x5;
    }
};


void poseidon_constants_fill(const std::string &seed, unsigned n_constants, std::vector<FieldT> &result )
{
	blake2b_ctx ctx;

	const unsigned n_bits_roundedup = FieldT::size_in_bits() + (8 - (FieldT::size_in_bits()%8));
	const unsigned output_size = n_bits_roundedup / 8;
	uint8_t output[output_size];

	result.reserve(n_constants);

	blake2b(output, output_size, NULL, 0, seed.c_str(), seed.size());
	result.emplace_back( bytes_to_FieldT_littleendian(output, output_size) );

	for( unsigned i = 0; i < (n_constants - 1); i++ )
	{
		blake2b(output, output_size, NULL, 0, output, output_size);
		result.emplace_back( bytes_to_FieldT_littleendian(output, output_size) );
	}
}


const std::vector<FieldT> poseidon_constants(const std::string &seed, unsigned n_constants)
{
	std::vector<FieldT> result;
	poseidon_constants_fill(seed, n_constants, result);
	return result;
}


void poseidon_matrix_fill(const std::string &seed, unsigned t, std::vector<FieldT> &result)
{
	const std::vector<FieldT> c = poseidon_constants(seed, t*2);

	result.reserve(t*2);

	for( unsigned i = 0; i < t; i++ )
	{
		for( unsigned j = 0; j < t; j++ )
		{		
			result.emplace_back((c[i] - c[t+j]).inverse());
		}
	}
}


const std::vector<FieldT> poseidon_matrix(const std::string &seed, unsigned t)
{
	std::vector<FieldT> result;
	poseidon_matrix_fill(seed, t, result);
	return result;
}


template<unsigned param_t, unsigned param_F, unsigned param_P>
const PoseidonConstants& poseidon_params()
{
    static PoseidonConstants constants;
    static std::once_flag flag;

    std::call_once(flag, [](){
    	poseidon_constants_fill("poseidon_constants", param_F + param_P, constants.C);
        poseidon_matrix_fill("poseidon_matrix_0000", param_t, constants.M);
    });

    return constants;
}


/**
* One round of the Poseidon permutation:
*
*    - takes a state of `t` elements
*    - adds the round constant to each element in the state
*    - performs exponentiation on the first `n` elements of the state
*    - creates `o` outputs, mixed using a matrix vector transform
*
* This generic version can be used as either a 'full', 'partial' or 'last' round.
* It avoids computing as many constraints as is possible, given all the information.
*/
template<unsigned param_t, unsigned nSBox, unsigned nInputs, unsigned nOutputs>
class Poseidon_Round : public GadgetT {
public:	
	const VariableArrayT outputs;
	const FieldT& C_i;
	const std::vector<FieldT>& M;
	const VariableArrayT state;
	std::vector<FifthPower_gadget> sboxes;

	Poseidon_Round(
		ProtoboardT &pb,
		const FieldT& in_C_i,
		const std::vector<FieldT>& in_M,
		const VariableArrayT& in_state,
		const std::string& annotation_prefix
	) :
		GadgetT(pb, annotation_prefix),
		outputs(make_var_array(pb, nOutputs, FMT(annotation_prefix, ".output"))),
		C_i(in_C_i),
		M(in_M),
		state(in_state)
	{
		assert( nInputs <= param_t );
		assert( nOutputs <= param_t );
		//assert( nSBox <= nInputs );

		// Initialise S-Boxes
		sboxes.reserve(nSBox);
		for( unsigned h = 0; h < nSBox; h++ )
		{
			sboxes.emplace_back( pb, FMT(annotation_prefix, ".sbox[%u]", h) );
		}
	}

	void generate_r1cs_witness() const
	{
		for( unsigned h = 0; h < nSBox; h++ )
		{
			auto value = C_i;
			if( h < nInputs ) {
				value += this->pb.val(state[h]);
			}
			sboxes[h].generate_r1cs_witness( value );
		}

		for( unsigned i = 0; i < nOutputs; i++ )
		{
			FieldT result;
			const unsigned M_offset = i * param_t;

			// Output result of S-Boxes
			for( unsigned s = 0; s < nSBox; s++ )
			{
				result += this->pb.val(sboxes[s].result()) * M[M_offset+s];
			}

			// Output inputs with round constants added
			for( unsigned k = nSBox; k < param_t; k++ )
			{
				auto value = C_i;
				if( k < nInputs ) {
					value += this->pb.val(state[k]);
				}
				result += value * M[M_offset+k];
			}

			this->pb.val(outputs[i]) = result;
		}
	}

	void generate_r1cs_constraints() const
	{
		for( unsigned h = 0; h < nSBox; h++ )
		{
			if( h < nInputs ) {
				sboxes[h].generate_r1cs_constraints( state[h] + C_i );
			}
			else {
				sboxes[h].generate_r1cs_constraints( C_i );
			}
		}

		for( unsigned i = 0; i < nOutputs; i++ )
		{
			const unsigned M_offset = i * param_t;

			// Any element which isn't passed through an sbox
			// Can be accumulated separately as part of the constant term
			FieldT constant_term;
			for( unsigned j = nSBox; j < param_t; j++ ) {
				constant_term += C_i * M[M_offset+j];
			}

			linear_combination<FieldT> lc;
			lc.terms.reserve(param_t);
			if( nSBox < param_t )
			{
				lc.add_term(libsnark::ONE, constant_term);
			}			

			// Add S-Boxes to the output row
			for( unsigned s = 0; s < nSBox; s++ )
			{
				lc.add_term(sboxes[s].result(), M[M_offset+s]);
			}

			// Then add inputs (from the state) multiplied by the matrix element
			for( unsigned k = nSBox; k < nInputs; k++ )
			{
				lc.add_term(state[k], M[M_offset+k]);
			}

			this->pb.add_r1cs_constraint(
				ConstraintT(lc, libsnark::ONE, outputs[i]),
				FMT(this->annotation_prefix, ".output[%u]", i));
		}
	}
};


template<unsigned param_t, unsigned param_c, unsigned param_F, unsigned param_P, unsigned nInputs, unsigned nOutputs>
class Poseidon_gadget_T : public GadgetT
{
protected:
	typedef Poseidon_Round<param_t, param_t, nInputs, param_t> FirstRoundT;    // ingests `nInput` elements, expands to `t` elements using round constants
	typedef Poseidon_Round<param_t, param_c, param_t, param_t> PartialRoundT;  // partial round only runs sbox on `c` elements (capacity)
	typedef Poseidon_Round<param_t, param_t, param_t, param_t> FullRoundT;     // full bandwidth
	typedef Poseidon_Round<param_t, param_t, param_t, nOutputs> LastRoundT;   // squeezes state into `nOutputs`

	static constexpr unsigned partial_begin = (param_F/2);
	static constexpr unsigned partial_end = (partial_begin + param_P);
	static constexpr unsigned total_rounds = param_F + param_P;

public:
	const VariableArrayT& inputs;
	const PoseidonConstants& constants;
	
	const FirstRoundT first_round;	
	const std::vector<FullRoundT> prefix_full_rounds;
	const std::vector<PartialRoundT> partial_rounds;
	const std::vector<FullRoundT> suffix_full_rounds;
	const LastRoundT last_round;

	template<typename T>
	static const std::vector<T> make_rounds(unsigned n_begin, unsigned n_end, ProtoboardT& pb, const VariableArrayT& inputs, const PoseidonConstants& constants, const std::string& annotation_prefix)
	{
		std::vector<T> result;
		result.reserve(n_end - n_begin);

		for( unsigned i = n_begin; i < n_end; i++ )
		{
			const VariableArrayT& state = (i == n_begin) ? inputs : result.back().outputs;
			result.emplace_back(pb, constants.C[i], constants.M, state, FMT(annotation_prefix, ".round[%u]", i));
		}

		return result;
	}

	static std::vector<FieldT> permute( std::vector<FieldT> inputs )
	{
		ProtoboardT pb;

		assert( inputs.size() == nInputs );
		auto var_inputs = make_var_array(pb, "input", inputs);

		Poseidon_gadget_T<param_t, param_c, param_F, param_P, nInputs, nOutputs> gadget(pb, var_inputs, "gadget");
		gadget.generate_r1cs_witness();

		/*
		gadget.generate_r1cs_constraints();

		unsigned i = 0;
		const auto first_outputs = gadget.first_round.outputs;
		for( unsigned j = 0; j < first_outputs.size(); j++ ) {
			std::cout << "o[" << i << "][" << j << "] = ";
			pb.val(first_outputs[j]).print();
		}
		std::cout << std::endl;

		for( const auto prefix_round : gadget.prefix_full_rounds )
		{
			i += 1;
			const auto outputs = prefix_round.outputs;
			for( unsigned j = 0; j < outputs.size(); j++ ) {
				std::cout << "o[" << i << "][" << j << "] = ";
				pb.val(outputs[j]).print();
			}
		}
		std::cout << std::endl;

		for( const auto partial_round : gadget.partial_rounds )
		{
			i += 1;
			const auto outputs = partial_round.outputs;
			for( unsigned j = 0; j < outputs.size(); j++ ) {
				std::cout << "o[" << i << "][" << j << "] = ";
				pb.val(outputs[j]).print();
			}
		}
		std::cout << std::endl;

		for( const auto suffix_round : gadget.suffix_full_rounds )
		{
			i += 1;
			const auto outputs = suffix_round.outputs;
			for( unsigned j = 0; j < outputs.size(); j++ ) {
				std::cout << "o[" << i << "][" << j << "] = ";
				pb.val(outputs[j]).print();
			}
		}
		std::cout << std::endl;

		const auto last_outputs = gadget.last_round.outputs;
		for( unsigned j = 0; j < last_outputs.size(); j++ ) {
			std::cout << "o[" << i << "][" << j << "] = ";
			pb.val(last_outputs[j]).print();
		}
		std::cout << std::endl;

		if( ! pb.is_satisfied() ) {
			std::cerr << "Not satisfied\n";
		}

		std::cout << pb.num_constraints() << " constraints" << std::endl;
		*/

		return gadget.outputs().get_vals(pb);
	}

	Poseidon_gadget_T(
		ProtoboardT &pb,
		const VariableArrayT& in_inputs,
		const std::string& annotation_prefix
	) :
		GadgetT(pb, annotation_prefix),
		inputs(in_inputs),
		constants(poseidon_params<param_t, param_F, param_P>()),
		first_round(pb, constants.C[0], constants.M, in_inputs, FMT(annotation_prefix, ".round[0]")),
		prefix_full_rounds(
			make_rounds<FullRoundT>(
				1, partial_begin, pb,
				first_round.outputs, constants, annotation_prefix)),
		partial_rounds(
			make_rounds<PartialRoundT>(
				partial_begin, partial_end, pb,
				prefix_full_rounds.back().outputs, constants, annotation_prefix)),
		suffix_full_rounds(
			make_rounds<FullRoundT>(
				partial_end, total_rounds-1, pb,
				partial_rounds.back().outputs, constants, annotation_prefix)),
		last_round(pb, constants.C.back(), constants.M, suffix_full_rounds.back().outputs, FMT(annotation_prefix, ".round[%u]", total_rounds-1))

	{
	}

	const VariableArrayT outputs() const
	{
		return last_round.outputs;
	}

	void generate_r1cs_constraints()
	{
		first_round.generate_r1cs_constraints();

		for( auto& prefix_round : prefix_full_rounds ) {
			prefix_round.generate_r1cs_constraints();
		}

		for( auto& partial_round : partial_rounds ) {
			partial_round.generate_r1cs_constraints();
		}

		for( auto& suffix_round : suffix_full_rounds ) {
			suffix_round.generate_r1cs_constraints();
		}

		last_round.generate_r1cs_constraints();
	}


	void generate_r1cs_witness()
	{
		first_round.generate_r1cs_witness();

		for( auto& prefix_round : prefix_full_rounds ) {
			prefix_round.generate_r1cs_witness();
		}

		for( auto& partial_round : partial_rounds ) {
			partial_round.generate_r1cs_witness();
		}

		for( auto& suffix_round : suffix_full_rounds ) {
			suffix_round.generate_r1cs_witness();
		}

		last_round.generate_r1cs_witness();
	}
};


template<unsigned nInputs, unsigned nOutputs>
using Poseidon128 = Poseidon_gadget_T<6, 1, 8, 57, nInputs, nOutputs>;


// namespace ethsnarks
}

#endif
