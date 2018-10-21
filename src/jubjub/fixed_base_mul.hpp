#ifndef ETHSNARKS_JUBJUB_FIXEDMULT_HPP_
#define ETHSNARKS_JUBJUB_FIXEDMULT_HPP_

#include "ethsnarks.hpp"
#include "jubjub/curve.hpp"
#include "gadgets/lookup_2bit.hpp"

namespace ethsnarks {

/**
* Implements scalar multiplication using a fixed base point and a 2-bit lookup window 
*/
class fixed_base_mul : GadgetT {
public:
	const VariableArrayT m_scalar;

	std::vector<FasterPointAddition> m_adders;
	std::vector<lookup_2bit> m_windows_x;
	std::vector<lookup_2bit> m_windows_y;

	fixed_base_mul(
		ProtoboardT &in_pb,
		const jubjub_params& in_params,
		const FieldT& in_base_x,
		const FieldT& in_base_y,
		const VariableArrayT in_scalar,
		const std::string &annotation_prefix
	) :
		GadgetT(in_pb, annotation_prefix)
	{
		int window_size_bits = 2;
		assert( in_scalar.size() % window_size_bits == 0 );
		int window_size_items = 1 << window_size_bits;
		int n_windows = in_scalar.size() / window_size_bits;

		FieldT x = in_base_x;
		FieldT y = in_base_y;

		// Precompute values for all lookup window tables
		for( int i = 0; i < n_windows; i++ )
		{
			std::vector<FieldT> lookup_x;
			std::vector<FieldT> lookup_y;

			// For each window, generate 4 points, in little endian:
			// When both bits are zero, infinity is used, which makes addition a no-op
			for( int j = 0; j < window_size_items; j++ )
			{
				// Zero
				if( j == 0 ) {
					lookup_x.emplace_back(0);
					lookup_y.emplace_back(1);
					continue;
				}
				else {
					lookup_x.emplace_back(x);
					lookup_y.emplace_back(y);
				}

				// Affine addition
				// TODO: move into library
				FieldT x1y2 = x * in_base_y;
				FieldT y1x2 = y * in_base_x;
				FieldT y1y2 = y * in_base_y;
				FieldT x1x2 = x * in_base_x;
				FieldT dx1x2y1y2 = in_params.d * x1x2 * y1y2;
				x = (x1y2 + y1x2) * (1 + dx1x2y1y2).inverse();
				y = (y1y2 - (in_params.a * x1x2)) * (1 - dx1x2y1y2).inverse();
			}

			auto bits_begin = in_scalar.cbegin() + (i * window_size_bits);
			const VariableArrayT window_bits( bits_begin, bits_begin + window_size_bits );
			m_windows_x.emplace_back(in_pb, lookup_x, window_bits, FMT(annotation_prefix, ".windows_x[%d]", i));
			m_windows_y.emplace_back(in_pb, lookup_y, window_bits, FMT(annotation_prefix, ".windows_y[%d]", i));
		}

		// Then setup adders
		for( int i = 1; i < n_windows; i++ )
		{
			if( i == 1 ) {				
				m_adders.emplace_back(
					in_pb, in_params,
					m_windows_x[i-1].result_x(),
					m_windows_y[i-1].result_y(),
					m_windows_x[i].result_x(),
					m_windows_y[i].result_y(),
					FMT(this->annotation_prefix, ".adders[%d]", i));
			}
			else {
				m_adders.emplace_back(
					in_pb, in_params,
					m_adders[i-1].result_x(),
					m_adders[i-1].result_y(),
					m_windows_x[i].result_x(),
					m_windows_y[i].result_y(),
					FMT(this->annotation_prefix, ".adders[%d]", i));
			}
		}
	}

	const VariableT& result_x() {
		return m_adders[ m_adders.size() - 1 ].result_x();
	}

	const VariableT& result_y() {
		return m_adders[ m_adders.size() - 1 ].result_y();
	}
};
	
// namespace ethsnarks
}

// ETHSNARKS_JUBJUB_FIXEDMULT_HPP_
#endif
