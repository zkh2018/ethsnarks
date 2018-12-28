file(GLOB gadget_sources "*.cpp")
add_library(ethsnarks_gadgets STATIC ${gadget_sources})
target_link_libraries(ethsnarks_gadgets ethsnarks_common OpenSSL::Crypto)
target_compile_features(ethsnarks_gadgets PUBLIC cxx_std_11)
