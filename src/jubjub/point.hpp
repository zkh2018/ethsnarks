#ifndef JUBJUB_EDWARDS_POINT_HPP_
#define JUBJUB_EDWARDS_POINT_HPP_

// Copyright (c) 2018 @HarryR
// Copyright (c) 2018 @fleupold
// License: LGPL-3.0+

#include "ethsnarks.hpp"
#include "jubjub/params.hpp"


namespace ethsnarks {

namespace jubjub {


class VariablePointT {
public:
    VariableT x;
    VariableT y;

    VariablePointT(const VariableT in_x, const VariableT in_y)
    : x(in_x), y(in_y)
    {}
};


class MontgomeryPoint;


/**
* Affine edwards point for performing calculations outside of zkSNARK circuits
*
* This also makes passing in an array of edwards points easier
*
*   e.g. {{FieldT("..."), FieldT("...")}, {...}}
*/
class EdwardsPoint
{
public:
    FieldT x;
    FieldT y;

    EdwardsPoint(const FieldT& in_x, const FieldT& in_y);

    const EdwardsPoint infinity() const;

    const EdwardsPoint neg() const;

    const EdwardsPoint dbl(const Params& params) const;

    const EdwardsPoint add(const EdwardsPoint& other, const Params& params) const;

    const MontgomeryPoint as_montgomery(const Params& params) const;

    /**
    * Recover the X coordinate from the Y
    * This will increment Y until X can be recovered
    */
    static const EdwardsPoint from_y_always (const FieldT in_y, const Params& params);

    static const EdwardsPoint from_hash( void *data, size_t n, const Params& params );

    /**
    * Determine the Y coordinate for a base point sequence
    */
    static const EdwardsPoint make_basepoint(const char *name, unsigned int sequence, const Params& in_params);

    /**
    * Return a sequence of base points for the given namespace
    */
    static const std::vector<EdwardsPoint> make_basepoints(const char *name, unsigned int n, const Params& in_params);
};



class MontgomeryPoint
{
public:
    FieldT x;
    FieldT y;

    MontgomeryPoint(const FieldT& in_x, const FieldT& in_y);

    const EdwardsPoint as_edwards(const Params& in_params) const;
};


// namespace jubjub
}

// namespace ethsnarks
}

// JUBJUB_EDWARDS_POINT_HPP_
#endif
