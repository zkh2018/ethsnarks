#include "ethsnarks.hpp"

#include "utils.hpp"

#include "gadgets/subadd.hpp"

namespace ethsnarks {

subadd_gadget::subadd_gadget(
	ProtoboardT &in_pb,
	const size_t n_bits,
	const VariableT in_A,
	const VariableT in_B,
	const VariableT in_N,
	const std::string& annotation_prefix
) :
	GadgetT(in_pb, annotation_prefix),
	A(in_A),
	B(in_B),
	N(in_N),

	// Results
	X(make_variable(in_pb, FMT(this->annotation_prefix, ".X"))),
	Y(make_variable(in_pb, FMT(this->annotation_prefix, ".Y"))),

	// A-N comparison check
	N_lt_A(make_variable(in_pb, FMT(this->annotation_prefix, ".N < A"))),
	N_leq_A(make_variable(in_pb, FMT(this->annotation_prefix, ".N <= A"))),
	cmp_N_A(in_pb, n_bits, N, A, N_lt_A, N_leq_A, FMT(this->annotation_prefix, ".cmp_N_A")),

	// B+A comparison check
	B_lt_Y(make_variable(in_pb, FMT(this->annotation_prefix, ".B < Y"))),
	B_leq_Y(make_variable(in_pb, FMT(this->annotation_prefix, ".B <= Y"))),
	cmp_B_Y(in_pb, n_bits, N, A, N_lt_A, N_leq_A, FMT(this->annotation_prefix, ".cmp_B_Y"))
{

}


void subadd_gadget::generate_r1cs_constraints ()
{
	cmp_N_A.generate_r1cs_constraints();

	cmp_B_Y.generate_r1cs_constraints();

	this->pb.add_r1cs_constraint(
		ConstraintT(N_leq_A, FieldT::one(), FieldT::one()),
			FMT(this->annotation_prefix, ".N_leq_A == 1"));

	this->pb.add_r1cs_constraint(
		ConstraintT(B_leq_Y, FieldT::one(), FieldT::one()),
			FMT(this->annotation_prefix, ".B_leq_Y == 1"));
}


void subadd_gadget::generate_r1cs_witness ()
{
	this->pb.val(X) = this->pb.val(A) - this->pb.val(N);

	this->pb.val(Y) = this->pb.val(B) + this->pb.val(N);

	cmp_N_A.generate_r1cs_witness();

	cmp_B_Y.generate_r1cs_witness();
}

// namespace ethsnarks
}
