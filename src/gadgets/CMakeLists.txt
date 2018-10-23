add_library(ethsnarks_gadgets STATIC
	longsightl.cpp
	longsightl_constants.cpp

	merkle_tree.cpp

	one_of_n.cpp
	sha256_full.cpp
	shamir_poly.cpp

	lookup_2bit.cpp
	subadd.cpp
)