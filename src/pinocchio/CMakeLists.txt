add_library(ethsnarks_pinocchio STATIC
	circuit_reader.cpp
)


add_executable(pinocchio run_libsnark.cpp)
target_link_libraries(pinocchio ethsnarks_common ethsnarks_pinocchio)
