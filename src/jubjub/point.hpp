#ifndef JUBJUB_POINT_HPP_
#define JUBJUB_POINT_HPP_

#include "ethsnarks.hpp"
#include "jubjub/params.hpp"


namespace ethsnarks {
	
namespace jubjub {


/**
* Affine point for performing calculations outside of zkSNARK circuits
*/
class Point
{
public:
	FieldT x;
	FieldT y;

	Point(const FieldT& in_x, const FieldT& in_y);

	const Point neg() const;

	static const Point from_y_always (const FieldT in_y, const Params& params);
};


// namespace jubjub
}

// namespace ethsnarks
}

// JUBJUB_POINT_HPP_
#endif
