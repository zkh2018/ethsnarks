#include "jubjub/montgomery.hpp"

namespace ethsnarks
{


montgomery_addition::montgomery_addition(
	ProtoboardT &in_pb,
	const jubjub_params &in_params,
	const VariableT in_x1,
	const VariableT in_y1,
	const VariableT in_x2,
	const VariableT in_y2,
	const std::string& annotation_prefix
) :
	GadgetT(in_pb, annotation_prefix),
	m_params(in_params),
	m_x1(in_x1), m_y1(in_y1),
	m_x2(in_x2), m_y2(in_y2),
	m_lambda(make_variable(in_pb, FMT(this->annotation_prefix, ".lambda"))),
	m_x3(make_variable(in_pb, FMT(this->annotation_prefix, ".x3"))),
	m_y3(make_variable(in_pb, FMT(this->annotation_prefix, ".y3")))
{

}


void montgomery_addition::generate_r1cs_constraints ()
{
	this->pb.add_r1cs_constraint(
		ConstraintT(m_x2 - m_x1, m_lambda, m_y2 - m_y1),
			FMT(this->annotation_prefix, " ((x2 - x1) * λ) == (y2 - y1)"));

	this->pb.add_r1cs_constraint(
		ConstraintT(m_lambda, m_lambda, m_params.A + m_x1 + m_x2 + m_x3),
			FMT(this->annotation_prefix, " λ^2 == (A + x1 + x2 + x3)"));

	this->pb.add_r1cs_constraint(
		ConstraintT(m_x3 + m_x1, m_lambda, m_y3 + m_y1),
			FMT(this->annotation_prefix, " (x3 + x1) == λ * (y3 + y1)"));
}


void montgomery_addition::generate_r1cs_witness ()
{
	auto n = this->pb.val(m_y2) - this->pb.val(m_y1);
	auto d = this->pb.val(m_x2) - this->pb.val(m_x1);
	auto l = n * d.inverse();

	this->pb.val(m_lambda) = l;

	this->pb.val(m_x3) = (l*l) - m_params.A - this->pb.val(m_x1) - this->pb.val(m_x2);

	this->pb.val(m_y3) = -(this->pb.val(m_y1) - (l * (this->pb.val(m_x3) - this->pb.val(m_x1))));
}


const VariableT& montgomery_addition::result_x() {
	return m_x3;
}


const VariableT& montgomery_addition::result_y() {
	return m_y3;
}


// namespace ethsnarks
}
