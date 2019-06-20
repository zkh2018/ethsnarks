include_directories(.)

add_library(ethsnarks_common STATIC export.cpp import.cpp stubs.cpp utils.cpp)
target_link_libraries(ethsnarks_common ff nlohmann_json)
target_include_directories(ethsnarks_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(verify verify.cpp)
target_link_libraries(verify ethsnarks_gadgets)

add_library(ethsnarks_verify SHARED verify_dll.cpp)
target_link_libraries(ethsnarks_verify ethsnarks_common)

if( NOT ${ETHSNARKS_DISABLE_TESTS} )
	add_subdirectory(test)
endif()

add_subdirectory(r1cs_gg_ppzksnark_zok)
add_subdirectory(gadgets)
add_subdirectory(jubjub)

if( NOT ${ETHSNARKS_DISABLE_PINOCCHIO} )
	add_subdirectory(pinocchio)
endif()

if( NOT ${ETHSNARKS_DISABLE_UTILS} )
	add_subdirectory(utils)
endif()
