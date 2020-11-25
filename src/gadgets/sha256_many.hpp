#ifndef ETHSNARKS_SHA256_MANY_HPP_
#define ETHSNARKS_SHA256_MANY_HPP_

// Copyright (c) 2018 HarryR
// License: LGPL-3.0+

#include "ethsnarks.hpp"
#include "utils.hpp"


#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>                   // digest_variable
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_components.hpp>  // SHA256_default_IV
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>      // sha256_compression_function_gadget

#include <mutex>

namespace ethsnarks {


class sha256_compression_function_gadget_instance : public GadgetT, public libsnark::ITranslator
{
public:
	typedef libsnark::sha256_compression_function_gadget<FieldT> Master;
	Master& master;

	VariableArrayT prev_output;
	VariableArrayT new_block;
	libsnark::digest_variable<FieldT> output;
	unsigned int instance_variables_offset;

	Master& get_master()
	{
		static ProtoboardT master_pb;
		static Master* master;
		static std::once_flag flag;
		std::call_once(flag, [](){
			VariableArrayT prev_output = make_var_array(master_pb, 256, ".dummy_inputs");
			VariableArrayT new_block = make_var_array(master_pb, 512, ".dummy_inputs");
			libsnark::digest_variable<FieldT> output(master_pb, 256, ".dummy_inputs");
			master = new Master(master_pb, prev_output, new_block, output, ".sha256_master");
			master->generate_r1cs_constraints();
			master_pb.set_use_thread_values(true);
		});
		return *master;
	}

	sha256_compression_function_gadget_instance(
		ProtoboardT &pb,
		const VariableArrayT &_prev_output,
		const VariableArrayT &_new_block,
		const libsnark::digest_variable<FieldT> &_output,
		const std::string& annotation_prefix
	) :
		GadgetT(pb, annotation_prefix),
		master(get_master()),
		prev_output(_prev_output),
		new_block(_new_block),
		output(_output)
	{
		// Keep track of where the variable for this instance start
		instance_variables_offset = pb.num_variables() + 1;
		// Allocate the variables on the pb needed for this instance
		make_var_array(pb, master.pb.num_variables() - 256*4, FMT(annotation_prefix, ".instance_var"));
	}

	~sha256_compression_function_gadget_instance()
	{
		//std::cout << "destructor" << std::endl;
	}

	void generate_r1cs_constraints() const
	{
		// For now, still copy all constraints to the main pb
		const auto& constraints = master.pb.constraint_system.constraints;
		for(unsigned int i = 0; i < constraints.size(); i++)
		{
			pb.constraint_system.constraints.emplace_back(
				libsnark::make_unique<libsnark::r1cs_constraint_light_instance<FieldT>>(
					(libsnark::r1cs_constraint_light<FieldT>*) constraints[i].get(),
					(libsnark::ITranslator*) this
				)
			);
		}
	}

	void generate_r1cs_witness()
	{
		// TODO: this can be done smarter by replacing the variable indices in the background
		// Set the input values
		for (unsigned int i = 0; i < prev_output.size(); i++)
		{
			master.pb.val(1 + i) = pb.val(prev_output[i]);
		}
		for (unsigned int i = 0; i < new_block.size(); i++)
		{
			master.pb.val(1 + 256 + i) = pb.val(new_block[i]);
		}
		// Calculate the funtion witnesses
		master.generate_r1cs_witness();
		// Copy variable values
		for (unsigned int i = 0; i < master.pb.num_variables() - 256*4; i++)
		{
			pb.val(instance_variables_offset + i) = master.pb.val(1 + 256*4 + i);
		}
		// Copy outputs
		for (unsigned int i = 0; i < output.bits.size(); i++)
		{
			pb.val(output.bits[i]) = master.pb.val(1 + 256*3 + i);
		}
	}

	unsigned int translate(unsigned int index) const override
	{
		if (index > 256*4)
		{
			return instance_variables_offset + (index - (1 + 256*4));
		}
		else if (index == 0)
		{
			return 0;
		}
		else if (index <= 256)
		{
			return prev_output[index - 1].index;
		}
		else if (index <= 256*3)
		{
			return new_block[index - 256 - 1].index;
		}
		else/* if (index <= 256*4)*/
		{
			return output.bits[index - 256*3 - 1].index;
		}
	}

	void swapAB() override
	{
		static std::once_flag flag;
		std::call_once(flag, [&](){
			const auto& constraints = master.pb.constraint_system.constraints;
			for(unsigned int i = 0; i < constraints.size(); i++)
			{
				constraints[i]->swapAB();
			}
		});
	}
};


/**
* This gadget hashes an arbitrary number of bits, in a way which is compatible
* with the Ethereum and Python SHA2-256 implementations. It accepts a VariableArrayT
* of bits as inputs, any number of bits can be provided, and provides one
* output digest.
*/
class sha256_many : public GadgetT
{
private:
	typedef sha256_compression_function_gadget_instance /*libsnark::sha256_compression_function_gadget<FieldT>*/ HashT;
	typedef libsnark::digest_variable<FieldT> DigestT;

	const std::vector<VariableArrayT> m_blocks;
	std::vector<libsnark::sha256_compression_function_gadget<FieldT>> first_hasher;
	std::vector<HashT> m_hashers;
	std::vector<DigestT> m_outputs;

public:
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
