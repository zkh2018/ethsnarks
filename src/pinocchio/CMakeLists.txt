add_library(ethsnarks_pinocchio STATIC
	circuit_reader.cpp
)


add_executable(pinocchio main.cpp)
target_link_libraries(pinocchio ethsnarks_common ethsnarks_pinocchio)


add_executable(jsnark_test jsnark_test.cpp)
target_link_libraries(jsnark_test ethsnarks_common ethsnarks_pinocchio)
