add_library (
    prover_reference_functions STATIC
    prover_reference_functions.cpp
    prover_reference_include/prover_reference_functions.hpp
)

target_compile_features(prover_reference_functions PUBLIC cxx_std_11)

target_include_directories(prover_reference_functions PUBLIC prover_reference_include)

target_link_libraries(prover_reference_functions ethsnarks_common)
