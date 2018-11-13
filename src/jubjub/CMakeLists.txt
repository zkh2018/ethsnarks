include_directories(.)

add_library(ethsnarks_jubjub STATIC
  curve.cpp
  pedersen_commitment.cpp
  fixed_base_mul.cpp
  conditional_point.cpp
  scalarmult.cpp
  adder.cpp
  doubler.cpp
  isoncurve.cpp
  commitment.cpp
  notloworder.cpp
)
