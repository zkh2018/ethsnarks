#include "jubjub/eddsa.hpp"
#include "utils.hpp"

namespace ethsnarks {

namespace jubjub {


EdDSA_Verify::EdDSA_Verify(
    ProtoboardT& in_pb,
    const Params& in_params,
    const EdwardsPoint& in_base,    // B
    VariablePointT in_A,            // A
    VariablePointT in_R,            // R
    VariableArrayT in_s,            // s
    VariableArrayT in_msg,          // m
    const std::string& annotation_prefix
) :
	GadgetT(in_pb, annotation_prefix),

	// Variables
	m_B(in_base),
	m_A(in_A),
	m_R(in_R),
	m_s(in_s),
	m_msg(in_msg),

	// Gadgets
	m_validator_R(in_pb, in_params, in_R.x, in_R.y, FMT(this->annotation_prefix, ".validator_R")),
	m_msg_hashed(in_pb, in_params, "EdDSA_Verify.M", in_msg, FMT(this->annotation_prefix, ".msg_hashed")),
	m_msg_hashed_bits(in_pb, m_msg_hashed.result_y(), FMT(this->annotation_prefix, ".msg_hashed_bits")),
	m_lhs(in_pb, in_params, in_base.x, in_base.y, in_s, FMT(this->annotation_prefix, ".lhs")),
	m_R_x_bits(in_pb, in_R.x, FMT(this->annotation_prefix, ".R_x_bits")),
	m_R_y_bits(in_pb, in_R.y, FMT(this->annotation_prefix, ".R_y_bits")),
	m_A_x_bits(in_pb, in_A.x, FMT(this->annotation_prefix, ".A_x_bits")),
	m_A_y_bits(in_pb, in_A.y, FMT(this->annotation_prefix, ".A_y_bits")),
	m_hash_t(in_pb, in_params, "EdDSA_Verify.t", flatten({m_R_x_bits.result(), m_R_y_bits.result(), m_A_x_bits.result(), m_A_y_bits.result(), m_msg_hashed_bits.result()}), FMT(this->annotation_prefix, ".hash_t")),
	m_t_bits(in_pb, m_hash_t.result_y(), FMT(this->annotation_prefix, ".t_bits")),
	m_At(in_pb, in_params, in_A.x, in_A.y, m_t_bits.result(), FMT(this->annotation_prefix, ".At")),
	m_rhs(in_pb, in_params, m_R.x, m_R.y, m_At.result_x(), m_At.result_y(), FMT(this->annotation_prefix, ".rhs"))
{

}


void EdDSA_Verify::generate_r1cs_constraints()
{
	m_validator_R.generate_r1cs_constraints();
	m_msg_hashed.generate_r1cs_constraints();
	m_msg_hashed_bits.generate_r1cs_constraints();
	m_lhs.generate_r1cs_constraints();
	m_R_y_bits.generate_r1cs_constraints();
	m_A_y_bits.generate_r1cs_constraints();
	m_hash_t.generate_r1cs_constraints();
	m_t_bits.generate_r1cs_constraints();
	m_At.generate_r1cs_constraints();
	m_rhs.generate_r1cs_constraints();
}


void EdDSA_Verify::generate_r1cs_witness()
{
	m_validator_R.generate_r1cs_witness();
	m_msg_hashed.generate_r1cs_witness();
	m_msg_hashed_bits.generate_r1cs_witness();
	m_lhs.generate_r1cs_witness();
	m_R_y_bits.generate_r1cs_witness();
	m_A_y_bits.generate_r1cs_witness();
	m_hash_t.generate_r1cs_witness();
	m_t_bits.generate_r1cs_witness();
	m_At.generate_r1cs_witness();
	m_rhs.generate_r1cs_witness();
}


// namespace jubjub
}

// namespace ethsnarks
}
