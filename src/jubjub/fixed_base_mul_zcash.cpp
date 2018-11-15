#include "jubjub/fixed_base_mul_zcash.hpp"


namespace ethsnarks {

namespace jubjub {

const static char chunk_size_bits = 3;
const static char lookup_size_bits = 2;
const static char chunks_per_base_point = 62;


fixed_base_mul_zcash::fixed_base_mul_zcash(
	ProtoboardT &in_pb,
	const Params& in_params,
	const std::vector<EdwardsPoint> base_points,
	const VariableArrayT in_scalar,
	const std::string &annotation_prefix
) :
	GadgetT(in_pb, annotation_prefix)
{
	assert( (in_scalar.size() % chunk_size_bits) == 0 );
	assert( float(in_scalar.size()) / float(chunk_size_bits * chunks_per_base_point) <= base_points.size());
	int window_size_items = 1 << lookup_size_bits;
	int n_windows = in_scalar.size() / chunk_size_bits;

	EdwardsPoint start = base_points[0];
	// Precompute values for all lookup window tables
	for( int i = 0; i < n_windows; i++ )
	{
		std::vector<FieldT> lookup_x;
		std::vector<FieldT> lookup_y;

		if (i % chunks_per_base_point == 0) {
			start = base_points[i/chunks_per_base_point];
		}

		// For each window, generate 4 points, in little endian:
		// (0,0) = 0 = start = base*2^4i
		// (1,0) = 1 = 2*start
		// (0,1) = 2 = 3*start
		// (1,1) = 3 = 4*start
		EdwardsPoint current = start;
		for( int j = 0; j < window_size_items; j++ )
		{
			if (j != 0) {
				current = current.add(start, in_params);
			}
			const auto montgomery = current.as_montgomery(in_params);
			lookup_x.emplace_back(montgomery.x);
			lookup_y.emplace_back(montgomery.y);

			const auto edward = montgomery.as_edwards(in_params);
			assert (edward.x == current.x);
			assert (edward.y == current.y);
		}

		const auto bits_begin = in_scalar.begin() + (i * chunk_size_bits);
		const VariableArrayT window_bits_x( bits_begin, bits_begin + lookup_size_bits );
		const VariableArrayT window_bits_y( bits_begin, bits_begin + chunk_size_bits );
		m_windows_x.emplace_back(in_pb, lookup_x, window_bits_x, FMT(annotation_prefix, ".windows_x[%d]", i));
		m_windows_y.emplace_back(in_pb, lookup_y, window_bits_y, FMT(annotation_prefix, ".windows_y[%d]", i));

		// current is at 2^2 * start, for next iteration start needs to be 2^4
		current = current.dbl(in_params);
		start = current.dbl(in_params);
	}

	// Chain adders within one segment together via montgomery adders
	for( int i = 1; i < n_windows; i++ )
	{
		if( i % chunks_per_base_point == 1 ) {				
			montgomery_adders.emplace_back(
				in_pb, in_params,
				m_windows_x[i-1].result(),
				m_windows_y[i-1].result(),
				m_windows_x[i].result(),
				m_windows_y[i].result(),
				FMT(this->annotation_prefix, ".mg_adders[%d]", i));
		}
		else {
			montgomery_adders.emplace_back(
				in_pb, in_params,
				montgomery_adders[i-2].result_x(),
				montgomery_adders[i-2].result_y(),
				m_windows_x[i].result(),
				m_windows_y[i].result(),
				FMT(this->annotation_prefix, ".mg_adders[%d]", i));
		}
	}

	// Convert every point at the end of a segment back to edwards format
	size_t segment_width = chunks_per_base_point - 1;
	for(size_t i = segment_width; i < montgomery_adders.size() - 1 /*we deal with the last one at the end*/; i += segment_width ) {
		point_converters.emplace_back(
			in_pb, in_params,
			montgomery_adders[i-1].result_x(),
			montgomery_adders[i-1].result_y(),
			FMT(this->annotation_prefix, ".point_conversion[%d]", i)
		);
	}
	// The last segment might be incomplete
	point_converters.emplace_back(
		in_pb, in_params,
		montgomery_adders.back().result_x(),
		montgomery_adders.back().result_y(),
		FMT(this->annotation_prefix, ".point_conversion_final")
	);

	// Chain adders of converted segment tails together
	for( size_t i = 1; i < point_converters.size(); i++ ) {
		if (i == 1) {
			edward_adders.emplace_back(
				in_pb, in_params,
				point_converters[i-1].result_x(),
				point_converters[i-1].result_y(),
				point_converters[i].result_x(),
				point_converters[i].result_y(),
				FMT(this->annotation_prefix, ".edward_adder[%d]", i)
			);
		} else {
			edward_adders.emplace_back(
				in_pb, in_params,
				edward_adders[i-2].result_x(),
				edward_adders[i-2].result_y(),
				point_converters[i].result_x(),
				point_converters[i].result_y(),
				FMT(this->annotation_prefix, ".edward_adder[%d]", i)
			);
		}
	}
}

void fixed_base_mul_zcash::generate_r1cs_constraints ()
{
	for( auto& lut_x : m_windows_x ) {
		lut_x.generate_r1cs_constraints();
	}

	for( auto& lut_y : m_windows_y ) {
		lut_y.generate_r1cs_constraints();
	}

	for( auto& adder : montgomery_adders ) {
		adder.generate_r1cs_constraints();
	}

	for( auto& converter : point_converters ) {
		converter.generate_r1cs_constraints();
	}

	for( auto& adder : edward_adders ) {
		adder.generate_r1cs_constraints();
	}
}

void fixed_base_mul_zcash::generate_r1cs_witness ()
{
	for( auto& lut_x : m_windows_x ) {
		lut_x.generate_r1cs_witness();
	}

	for( auto& lut_y : m_windows_y ) {
		lut_y.generate_r1cs_witness();
	}

	for( auto& adder : montgomery_adders ) {
		adder.generate_r1cs_witness();
	}

	for( auto& converter : point_converters ) {
		converter.generate_r1cs_witness();
	}

	for( auto& adder : edward_adders ) {
		adder.generate_r1cs_witness();
	}
}

const VariableT& fixed_base_mul_zcash::result_x() {
	return edward_adders.back().result_x();
}

const VariableT& fixed_base_mul_zcash::result_y() {
	return edward_adders.back().result_y();
}


// namespace jubjub
}

// namespace ethsnarks
}