#include <cassert>
#include <cstdio>
#include <fstream>
#include "ethsnarks.hpp"

const size_t num_limbs = 4;

template<typename ppT>
void write_fq(FILE* output, ethsnarks::FqT x) {
  fwrite((void *) x.mont_repr.data, num_limbs * sizeof(mp_size_t), 1, output);
}

template<typename ppT>
void write_fr(FILE* output, ethsnarks::FieldT x) {
  fwrite((void *) x.mont_repr.data, num_limbs * sizeof(mp_size_t), 1, output);
}

template<typename ppT>
void write_fqe(FILE* output, ethsnarks::FqeT x) {
#if 0
  std::vector<ethsnarks::FqT> v = x.all_base_field_elements();
  size_t deg = ethsnarks::FqeT::extension_degree();
  for (size_t i = 0; i < deg; ++i) {
    write_fq<ppT>(output, v[i]);
  }
#endif
  // TODO: hard code to Fp2 avoid libff change now
  write_fq<ppT>(output, x.c0);
  write_fq<ppT>(output, x.c1);
}

template<typename ppT>
void write_g1(FILE* output, ethsnarks::G1T g) {
  if (g.is_zero())  {
    write_fq<ppT>(output, ethsnarks::FqT::zero());
    write_fq<ppT>(output, ethsnarks::FqT::zero());
    return;
  }

  g.to_affine_coordinates();
  write_fq<ppT>(output, g.X);
  write_fq<ppT>(output, g.Y);
}

template<typename ppT>
void write_g2(FILE* output, ethsnarks::G2T g) {
  if (g.is_zero())  {
    write_fqe<ppT>(output, ethsnarks::FqeT::zero());
    write_fqe<ppT>(output, ethsnarks::FqeT::zero());
    return;
  }

  g.to_affine_coordinates();
  write_fqe<ppT>(output, g.X);
  write_fqe<ppT>(output, g.Y);
}

template<typename ppT>
ethsnarks::FqT read_fq(FILE* input) {
  ethsnarks::FqT x;
  fread((void *) x.mont_repr.data, num_limbs * sizeof(mp_size_t), 1, input);
  return x;
}


template<typename ppT>
ethsnarks::FieldT read_fr(FILE* input) {
  ethsnarks::FieldT x;
  fread((void *) x.mont_repr.data, num_limbs * sizeof(mp_size_t), 1, input);
  return x;
}

template<typename ppT>
ethsnarks::G1T read_g1(FILE* input) {
  ethsnarks::FqT x = read_fq<ppT>(input);
  ethsnarks::FqT y = read_fq<ppT>(input);
  if (y == ethsnarks::FqT::zero()) {
    return ethsnarks::G1T::zero();
  }
  return ethsnarks::G1T(x, y, ethsnarks::FqT::one());
}


template<typename ppT>
ethsnarks::FqeT read_fqe(FILE* input) {
#if 0
  std::vector<ethsnarks::FqT> elts;
  size_t deg = ethsnarks::FqeT::extension_degree();
  for (size_t i = 0; i < deg; ++i) {
    elts.emplace_back(read_fq<ppT>(input));
  }
  return ethsnarks::FqeT(elts);
#endif
  // TODO: hard code to Fp2 avoid libff change now
  ethsnarks::FqT c0 = read_fq<ppT>(input);
  ethsnarks::FqT c1 = read_fq<ppT>(input);
  return ethsnarks::FqeT(c0, c1);
}

template<typename ppT>
ethsnarks::G2T read_g2(FILE* input) {
  ethsnarks::FqeT x = read_fqe<ppT>(input);
  ethsnarks::FqeT y = read_fqe<ppT>(input);
  if (y == ethsnarks::FqeT::zero()) {
    return ethsnarks::G2T::zero();
  }
  return ethsnarks::G2T(x, y, ethsnarks::FqeT::one());
}

size_t read_size_t(FILE* input) {
  size_t n;
  size_t sizeRead = fread((void *) &n, sizeof(size_t), 1, input);
  if (sizeRead != 1) {
    fputs("fread error", stderr);
    abort();
  }
  return n;
}

void write_size_t(FILE* output, size_t n) {
  fwrite((void *) &n, sizeof(size_t), 1, output);
}

