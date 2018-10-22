#ifndef JUBJUB_MONTGOMERY_HPP_
#define JUBJUB_MONTGOMERY_HPP_

#include "ethsnarks.hpp"
#include "jubjub/curve.hpp"
#include "utils.hpp"

namespace ethsnarks
{


/**
* Implements Montgomery point addition in affine coordinates with 3 constraints
*
* 	P1+P2 = (x1,y1)+(x2,y2) = (x3,y3) = P3
*
* From the Wikipedia page on Montgomery_curve
*
* 	l = (y2 - y1) / (x2 - x1)
* 	m = y1 - (l*x1)
*	x3 = l^2 - A - x1 - x2
* 	y3 = (l*x1) + m
*
* Copied from https://github.com/zcash/librustzcash/blob/master/sapling-crypto/src/circuit/ecc.rs#L659
*/
class montgomery_addition : public GadgetT {
protected:
	const jubjub_params &m_params;

public:
	// Input variables
	const VariableT m_x1;
	const VariableT m_y1;
	const VariableT m_x2;
	const VariableT m_y2;

	// Intermediates
	const VariableT m_lambda;

	// Output variables
	const VariableT m_x3;
	const VariableT m_y3;

	montgomery_addition(
		ProtoboardT &in_pb,
		const jubjub_params &in_params,
		const VariableT in_x1,
		const VariableT in_y1,
		const VariableT in_x2,
		const VariableT in_y2,
		const std::string& annotation_prefix
	);

	void generate_r1cs_constraints();

	void generate_r1cs_witness();

	const VariableT& result_x();

	const VariableT& result_y();
};


// namespace ethsnarks
}

// JUBJUB_MONTGOMERY_HPP_
#endif