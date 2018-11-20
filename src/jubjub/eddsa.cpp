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

	// IsValid(R)
	m_validator_R(in_pb, in_params, in_R.x, in_R.y, FMT(this->annotation_prefix, ".validator_R")),

	// M = H(m)
	m_msg_hashed(in_pb, in_params, "EdDSA_Verify.M", in_msg, FMT(this->annotation_prefix, ".msg_hashed")),

	// lhs = ScalarMult(B, s)
	m_lhs(in_pb, in_params, in_base.x, in_base.y, in_s, FMT(this->annotation_prefix, ".lhs")),

	// Convert X & Y coords to bits for hash function
	m_R_x_bits(in_pb, in_R.x, FMT(this->annotation_prefix, ".R_x_bits")),
	m_A_x_bits(in_pb, in_A.x, FMT(this->annotation_prefix, ".A_x_bits")),

	// hash_RAM = H(R.x,R.y,A.x,A.y,M.x,M.y)
	m_hash_RAM(in_pb, in_params, "EdDSA_Verify.RAM", flatten({
		m_R_x_bits.result(),
		m_A_x_bits.result(),
		m_msg_hashed.result(),
	}), FMT(this->annotation_prefix, ".hash_RAM")),

	// At = ScalarMult(A,t)
	m_At(in_pb, in_params, in_A.x, in_A.y, m_hash_RAM.result(), FMT(this->annotation_prefix, ".At")),

	// rhs = PointAdd(R, At)
	m_rhs(in_pb, in_params, in_R.x, in_R.y, m_At.result_x(), m_At.result_y(), FMT(this->annotation_prefix, ".rhs"))
{ }


void EdDSA_Verify::generate_r1cs_constraints()
{
	m_validator_R.generate_r1cs_constraints();
	m_msg_hashed.generate_r1cs_constraints();
	m_lhs.generate_r1cs_constraints();
	m_R_x_bits.generate_r1cs_constraints();
	m_A_x_bits.generate_r1cs_constraints();
	m_hash_RAM.generate_r1cs_constraints();
	m_At.generate_r1cs_constraints();
	m_rhs.generate_r1cs_constraints();
}


void EdDSA_Verify::generate_r1cs_witness()
{
	m_validator_R.generate_r1cs_witness();
	m_msg_hashed.generate_r1cs_witness();
	m_lhs.generate_r1cs_witness();
	m_R_x_bits.generate_r1cs_witness();
	m_A_x_bits.generate_r1cs_witness();
	m_hash_RAM.generate_r1cs_witness();
	m_At.generate_r1cs_witness();
	m_rhs.generate_r1cs_witness();
}


// namespace jubjub
}

// namespace ethsnarks
}
