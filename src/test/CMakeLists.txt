add_subdirectory(jubjub)
add_subdirectory(benchmark)

file(GLOB test_sources "*.cpp")

foreach(test_path ${test_sources})
	get_filename_component(test_name ${test_path} NAME)
	string(REPLACE ".cpp" "" test_executable ${test_name})
	add_executable(${test_executable} ${test_name})
	target_link_libraries(${test_executable} ethsnarks_common)
endforeach()

target_link_libraries(test_sha256_full_gadget crypto)
target_link_libraries(test_sha256_many crypto)
target_link_libraries(test_field_packing crypto)
target_link_libraries(test_hashpreimage crypto)
