#ifndef JUBJUB_POINT_HPP_
#define JUBJUB_POINT_HPP_

#include "ethsnarks.hpp"
#include "jubjub/params.hpp"


namespace ethsnarks {
	
namespace jubjub {


/**
* Affine point for performing calculations outside of zkSNARK circuits
*
* This also makes passing in an array of points easier
*
* 	e.g. {{FieldT("..."), FieldT("...")}, {...}}
*/
class Point
{
public:
	FieldT x;
	FieldT y;

	Point(const FieldT& in_x, const FieldT& in_y);

	const Point infinity() const;

	const Point neg() const;

	const Point dbl() const;

	const Point add(const Point& other) const;

	/**
	* Recover the X coordinate from the Y
	* This will increment Y until X can be recovered
	*/
	static const Point from_y_always (const FieldT in_y, const Params& params);

	static const Point from_hash( void *data, size_t n, const Params& params );
};


// namespace jubjub
}

// namespace ethsnarks
}

// JUBJUB_POINT_HPP_
#endif
