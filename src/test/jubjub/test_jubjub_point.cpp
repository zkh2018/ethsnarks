#include "jubjub/point.hpp"


using ethsnarks::FieldT;

namespace ethsnarks {


bool test_point_from_y(const FieldT& expected_x, const FieldT& in_y)
{
	const jubjub::Params params;
	const auto p = jubjub::Point::from_y_always(in_y, params);
	return expected_x == p.x;
}


// namespace ethsnarks
}


struct PointFromYTestCase {
	FieldT x;
	FieldT y;
};


int main( void )
{
	ethsnarks::ppT::init_public_params();

	std::vector<PointFromYTestCase> test_cases = {
		// 0
		{FieldT("20616554786359396897066290204264220576319536076538991133935783866206841138898"),
		 FieldT("10592275084648178561464128859907688344447649297734555224341876545305639835999")},

		// 1, verifies that Y coordinate is incremented after not finding a square root
		{FieldT("20616554786359396897066290204264220576319536076538991133935783866206841138898"),
		 FieldT("10592275084648178561464128859907688344447649297734555224341876545305639835998")},

		// 2
		{FieldT("11610117029953798428826613242669939481045605849364609771767823351326159443609"),
		 FieldT("3722409228507723418678713896319610332389736117851027921973860155000856891140")},

		// 3
		{FieldT("21680045038775759642189425577922609025982451102460978847266452551495203884482"),
		 FieldT("6168854640927408084732268325506202000962285527703379133980054444068219727690")},

		// 4
		{FieldT("18879782252170350866370777185563748782908354718484814019474117245310535071541"),
		 FieldT("2946855428411022359321514310392164228862398839132752152798293872913224129374")}
	};

	int i = 0;
	for( const auto& testcase : test_cases ) {
		if( ! ethsnarks::test_point_from_y(testcase.x, testcase.y) ) {
			std::cerr << "FAIL " << i << std::endl;
			return i + 1;
		}

		i += 1;
	}

	std::cout << "OK" << std::endl;
	return 0;
}