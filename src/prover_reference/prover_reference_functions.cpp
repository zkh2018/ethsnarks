#include <cassert>
#include <cstdio>
#include <fstream>
#include <libff/common/profiling.hpp>
#include <libff/common/rng.hpp>
#include <libff/common/utils.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/knowledge_commitment/kc_multiexp.hpp>
#include <libsnark/knowledge_commitment/knowledge_commitment.hpp>
#include <libsnark/reductions/r1cs_to_qap/r1cs_to_qap.hpp>
#include <libff/common/serialization.hpp>
#include <omp.h>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

#include <libfqfft/evaluation_domain/domains/basic_radix2_domain.hpp>

#include "prover_reference_include/prover_reference_functions.hpp"

using namespace libff;
using namespace libsnark;


//const multi_exp_method method = multi_exp_method_bos_coster;
const multi_exp_method method = multi_exp_method_BDLO12;
const size_t num_limbs = 4;

template<typename ppT>
void write_fq(FILE* output, Fq<ppT> x) {
  fwrite((void *) x.mont_repr.data, num_limbs * sizeof(mp_size_t), 1, output);
}

template<typename ppT>
void write_fr(FILE* output, Fr<ppT> x) {
  fwrite((void *) x.mont_repr.data, num_limbs * sizeof(mp_size_t), 1, output);
}

template<typename ppT>
void write_fqe(FILE* output, Fqe<ppT> x) {
#if 0
  std::vector<Fq<ppT>> v = x.all_base_field_elements();
  size_t deg = Fqe<ppT>::extension_degree();
  for (size_t i = 0; i < deg; ++i) {
    write_fq<ppT>(output, v[i]);
  }
#endif
  // TODO: hard code to Fp2 avoid libff change now
  write_fq<ppT>(output, x.c0);
  write_fq<ppT>(output, x.c1);
}

template<typename ppT>
void write_g1(FILE* output, G1<ppT> g) {
  if (g.is_zero())  {
    write_fq<ppT>(output, Fq<ppT>::zero());
    write_fq<ppT>(output, Fq<ppT>::zero());
    return;
  }

  g.to_affine_coordinates();
  write_fq<ppT>(output, g.X);
  write_fq<ppT>(output, g.Y);
}

template<typename ppT>
void write_g2(FILE* output, G2<ppT> g) {
  if (g.is_zero())  {
    write_fqe<ppT>(output, Fqe<ppT>::zero());
    write_fqe<ppT>(output, Fqe<ppT>::zero());
    return;
  }

  g.to_affine_coordinates();
  write_fqe<ppT>(output, g.X);
  write_fqe<ppT>(output, g.Y);
}


template<typename ppT>
Fq<ppT> read_fq(FILE* input) {
  Fq<ppT> x;
  fread((void *) x.mont_repr.data, num_limbs * sizeof(mp_size_t), 1, input);
  return x;
}

template<typename ppT>
Fr<ppT> read_fr(FILE* input) {
  Fr<ppT> x;
  fread((void *) x.mont_repr.data, num_limbs * sizeof(mp_size_t), 1, input);
  return x;
}

template<typename ppT>
G1<ppT> read_g1(FILE* input) {
  Fq<ppT> x = read_fq<ppT>(input);
  Fq<ppT> y = read_fq<ppT>(input);
  if (y == Fq<ppT>::zero()) {
    return G1<ppT>::zero();
  }
  return G1<ppT>(x, y, Fq<ppT>::one());
}

template<typename ppT>
Fqe<ppT> read_fqe(FILE* input) {
#if 0
  std::vector<Fq<ppT>> elts;
  size_t deg = Fqe<ppT>::extension_degree();
  for (size_t i = 0; i < deg; ++i) {
    elts.emplace_back(read_fq<ppT>(input));
  }
  return Fqe<ppT>(elts);
#endif
  // TODO: hard code to Fp2 avoid libff change now
  Fq<ppT> c0 = read_fq<ppT>(input);
  Fq<ppT> c1 = read_fq<ppT>(input);
  return Fqe<ppT>(c0, c1);
}

template<typename ppT>
G2<ppT> read_g2(FILE* input) {
  Fqe<ppT> x = read_fqe<ppT>(input);
  Fqe<ppT> y = read_fqe<ppT>(input);
  if (y == Fqe<ppT>::zero()) {
    return G2<ppT>::zero();
  }
  return G2<ppT>(x, y, Fqe<ppT>::one());
}

size_t read_size_t(FILE* input) {
  size_t n;
  fread((void *) &n, sizeof(size_t), 1, input);
  return n;
}

void write_size_t(FILE* output, size_t n) {
  fwrite((void *) &n, sizeof(size_t), 1, output);
}

template< typename EC >
struct ff_dict;

template<>
struct ff_dict<alt_bn128_libsnark::G1> {
    typedef Fq<alt_bn128_pp> FF;
    typedef G1<alt_bn128_pp> EC;
    static constexpr size_t ff_bytes = alt_bn128_r_limbs * sizeof(mp_limb_t);

    static FF read_ff(const char *&mem) {
        FF x;
        memcpy(x.mont_repr.data, mem, ff_bytes);
        mem += ff_bytes;
        return x;
    }

    static void write_ff(char *&mem, const FF &x) {
        memcpy(mem, x.mont_repr.data, ff_bytes);
        mem += ff_bytes;
    }
};

template<>
struct ff_dict<alt_bn128_libsnark::G2> {
    typedef Fqe<alt_bn128_pp> FF;
    typedef G2<alt_bn128_pp> EC;
    static constexpr size_t ff_bytes = 2 * ff_dict<alt_bn128_libsnark::G1>::ff_bytes;

    static FF read_ff(const char *&mem) {
        auto c0 = ff_dict<alt_bn128_libsnark::G1>::read_ff(mem);
        auto c1 = ff_dict<alt_bn128_libsnark::G1>::read_ff(mem);
        return FF(c0, c1);
    }

    static void write_ff(char *&mem, const FF &x) {
        ff_dict<alt_bn128_libsnark::G1>::write_ff(mem, x.c0);
        ff_dict<alt_bn128_libsnark::G1>::write_ff(mem, x.c1);
    }
};

template< typename EC >
typename ff_dict<EC>::EC read_pt(const char *&mem) {
    typedef ff_dict<EC> D;
    typedef typename D::FF FF;
    FF x = D::read_ff(mem);
    FF y = D::read_ff(mem);
    FF z = D::read_ff(mem);
    // Convert point representation from Jacobian to projective
    return typename D::EC(x, y, z);
}

template <typename G, typename Fr>
G multiexp(typename std::vector<Fr>::const_iterator scalar_start,
           typename std::vector<G>::const_iterator g_start, size_t length) {
#ifdef MULTICORE
  const size_t chunks =
      omp_get_max_threads(); // to override, set OMP_NUM_THREADS env var or call
                             // omp_set_num_threads()
#else
  const size_t chunks = 1;
#endif

  return libff::multi_exp_with_mixed_addition<G, Fr, method>(
      g_start, g_start + length, scalar_start, scalar_start + length, chunks);
}

class alt_bn128_libsnark::groth16_input {
public:
  std::shared_ptr<std::vector<Fr<alt_bn128_pp>>> w;
  std::shared_ptr<std::vector<Fr<alt_bn128_pp>>> ca, cb, cc;
  Fr<alt_bn128_pp> primary_input;
  Fr<alt_bn128_pp> r;

  groth16_input(FILE *inputs, size_t d, size_t orig_d, size_t m) {
    w = std::make_shared<std::vector<libff::Fr<alt_bn128_pp>>>(
        std::vector<libff::Fr<alt_bn128_pp>>());
    ca = std::make_shared<std::vector<libff::Fr<alt_bn128_pp>>>(
        std::vector<libff::Fr<alt_bn128_pp>>());
    cb = std::make_shared<std::vector<libff::Fr<alt_bn128_pp>>>(
        std::vector<libff::Fr<alt_bn128_pp>>());
    cc = std::make_shared<std::vector<libff::Fr<alt_bn128_pp>>>(
        std::vector<libff::Fr<alt_bn128_pp>>());

    for (size_t i = 0; i < m + 1; ++i) {
      w->emplace_back(read_fr<alt_bn128_pp>(inputs));
    }
    for (size_t i = 0; i < d + 1; ++i) {
      auto value = read_fr<alt_bn128_pp>(inputs);
      ca->emplace_back(value);
      if (i == orig_d) {
        primary_input = value;
      }
    }
    for (size_t i = 0; i < d + 1; ++i) {
      cb->emplace_back(read_fr<alt_bn128_pp>(inputs));
    }
    for (size_t i = 0; i < d + 1; ++i) {
      cc->emplace_back(read_fr<alt_bn128_pp>(inputs));
    }

    r = read_fr<alt_bn128_pp>(inputs);
  }
};

class alt_bn128_libsnark::groth16_params {
public:
  size_t d;
  size_t orig_d;
  size_t m;
  std::shared_ptr<std::vector<libff::G1<alt_bn128_pp>>> A, B1, L, H;
  std::shared_ptr<std::vector<libff::G2<alt_bn128_pp>>> B2;
  libff::G1<alt_bn128_pp> alpha_g1;
  libff::G1<alt_bn128_pp> beta_g1;
  libff::G2<alt_bn128_pp> beta_g2;

  groth16_params(FILE *params, size_t dd, size_t mm) {
    d = read_size_t(params);
    orig_d = read_size_t(params); 
    m = read_size_t(params);
    if (d != dd || m != mm) {
        fputs("Bad size read", stderr);
        abort();
    }

    A = std::make_shared<std::vector<libff::G1<alt_bn128_pp>>>(
        std::vector<libff::G1<alt_bn128_pp>>());
    B1 = std::make_shared<std::vector<libff::G1<alt_bn128_pp>>>(
        std::vector<libff::G1<alt_bn128_pp>>());
    L = std::make_shared<std::vector<libff::G1<alt_bn128_pp>>>(
        std::vector<libff::G1<alt_bn128_pp>>());
    H = std::make_shared<std::vector<libff::G1<alt_bn128_pp>>>(
        std::vector<libff::G1<alt_bn128_pp>>());
    B2 = std::make_shared<std::vector<libff::G2<alt_bn128_pp>>>(
        std::vector<libff::G2<alt_bn128_pp>>());
    for (size_t i = 0; i <= m; ++i) {
      A->emplace_back(read_g1<alt_bn128_pp>(params));
    }
    for (size_t i = 0; i <= m; ++i) {
      B1->emplace_back(read_g1<alt_bn128_pp>(params));
    }
    for (size_t i = 0; i <= m; ++i) {
      B2->emplace_back(read_g2<alt_bn128_pp>(params));
    }
    for (size_t i = 0; i < m - 1; ++i) {
      L->emplace_back(read_g1<alt_bn128_pp>(params));
    }
    for (size_t i = 0; i < d; ++i) {
      H->emplace_back(read_g1<alt_bn128_pp>(params));
    }
    alpha_g1 = read_g1<alt_bn128_pp>(params);
    beta_g1 = read_g1<alt_bn128_pp>(params);
    beta_g2 = read_g2<alt_bn128_pp>(params);
  }
};

struct alt_bn128_libsnark::evaluation_domain {
  std::shared_ptr<libfqfft::evaluation_domain<Fr<alt_bn128_pp>>> data;
};

struct alt_bn128_libsnark::field {
  Fr<alt_bn128_pp> data;
};

struct alt_bn128_libsnark::G1 {
  libff::G1<alt_bn128_pp> data;
};

struct alt_bn128_libsnark::G2 {
  libff::G2<alt_bn128_pp> data;
};

struct alt_bn128_libsnark::vector_Fr {
  std::shared_ptr<std::vector<Fr<alt_bn128_pp>>> data;
  size_t offset;
};

struct alt_bn128_libsnark::vector_G1 {
  std::shared_ptr<std::vector<libff::G1<alt_bn128_pp>>> data;
};
struct alt_bn128_libsnark::vector_G2 {
  std::shared_ptr<std::vector<libff::G2<alt_bn128_pp>>> data;
};


void alt_bn128_libsnark::init_public_params() {
  alt_bn128_pp::init_public_params();
}

void alt_bn128_libsnark::print_G1(alt_bn128_libsnark::G1 *a) { a->data.print(); }

void alt_bn128_libsnark::print_G1(alt_bn128_libsnark::vector_G1 *a) { a->data->at(0).print(); }

void alt_bn128_libsnark::print_G2(alt_bn128_libsnark::G2 *a) { a->data.print(); }

void alt_bn128_libsnark::print_G2(alt_bn128_libsnark::vector_G2 *a, size_t i) { a->data->at(i).print(); }

alt_bn128_libsnark::evaluation_domain *
alt_bn128_libsnark::get_evaluation_domain(size_t d) {
  return new evaluation_domain{
      .data = libfqfft::get_evaluation_domain<Fr<alt_bn128_pp>>(d)};
}

int alt_bn128_libsnark::G1_equal(alt_bn128_libsnark::G1 *a, alt_bn128_libsnark::G1 *b) {
  return a->data == b->data;
}

int alt_bn128_libsnark::G2_equal(alt_bn128_libsnark::G2 *a, alt_bn128_libsnark::G2 *b) {
  return a->data == b->data;
}

alt_bn128_libsnark::G1 *alt_bn128_libsnark::G1_add(alt_bn128_libsnark::G1 *a,
                                               alt_bn128_libsnark::G1 *b) {
  return new alt_bn128_libsnark::G1{.data = a->data + b->data};
}

alt_bn128_libsnark::G1 *alt_bn128_libsnark::G1_scale(field *a, G1 *b) {
  return new G1{.data = a->data * b->data};
}

alt_bn128_libsnark::G2 *alt_bn128_libsnark::G2_add(alt_bn128_libsnark::G2 *a,
                                               alt_bn128_libsnark::G2 *b) {
  return new alt_bn128_libsnark::G2{.data = a->data + b->data};
}

void alt_bn128_libsnark::vector_Fr_muleq(alt_bn128_libsnark::vector_Fr *H_tmp,
                                       alt_bn128_libsnark::vector_Fr *a,
                                       alt_bn128_libsnark::vector_Fr *b,
                                       size_t size) {
  size_t h_off = H_tmp->offset, a_off = a->offset, b_off = b->offset;
#ifdef MULTICORE
#pragma omp parallel for
#endif
  for (size_t i = 0; i < size; i++) {
    H_tmp->data->at(i + a_off) = a->data->at(i + a_off) * b->data->at(i + b_off);
  }
}

void alt_bn128_libsnark::vector_Fr_subeq(alt_bn128_libsnark::vector_Fr *a,
                                       alt_bn128_libsnark::vector_Fr *b,
                                       size_t size) {
  size_t a_off = a->offset, b_off = b->offset;
#ifdef MULTICORE
#pragma omp parallel for
#endif
  for (size_t i = 0; i < size; i++) {
    a->data->at(i + a_off) = a->data->at(i + a_off) - b->data->at(i + b_off);
  }
}
void alt_bn128_libsnark::vector_Fr_add(alt_bn128_libsnark::vector_Fr *coeff_H,
                                           alt_bn128_libsnark::vector_Fr *a,
                                           alt_bn128_libsnark::vector_Fr *b,
                                           size_t length) {
  size_t h_off = coeff_H->offset, a_off = a->offset, b_off = b->offset;
#ifdef MULTICORE
#pragma omp parallel for
#endif
  for (size_t i = 0; i < length; ++i) {
    coeff_H->data->at(i + h_off) = a->data->at(i + a_off) + b->data->at(i + b_off);
  }
}

alt_bn128_libsnark::vector_Fr *
alt_bn128_libsnark::vector_Fr_offset(alt_bn128_libsnark::vector_Fr *a,
                                   size_t offset) {
  return new vector_Fr{.data = a->data, .offset = offset};
}

void alt_bn128_libsnark::vector_Fr_copy_into(alt_bn128_libsnark::vector_Fr *src,
                                           alt_bn128_libsnark::vector_Fr *dst,
                                           size_t length) {
  std::cerr << "length is " << length << ", offset is " << src->offset
            << ", size of src is " << src->data->size() << ", size of dst is "
            << dst->data->size() << std::endl;
#ifdef MULTICORE
#pragma omp parallel for
#endif
  for (size_t i = 0; i < length; i++) {
    // std::cerr << "doing iteration " << i << std::endl;
    dst->data->at(i) = src->data->at(i);
  }
  // std::copy(src->data->begin(), src->data->end(), dst->data->begin() );
}

alt_bn128_libsnark::vector_Fr *alt_bn128_libsnark::vector_Fr_zeros(size_t length) {
  std::vector<Fr<alt_bn128_pp>> data(length, Fr<alt_bn128_pp>::zero());
  return new alt_bn128_libsnark::vector_Fr{
      .data = std::make_shared<std::vector<Fr<alt_bn128_pp>>>(data),
          .offset = 0};
}

void alt_bn128_libsnark::coefficients_for_H_to_mem(alt_bn128_libsnark::vector_Fr *coeff_H, uint8_t *H_coeff_mem, uint8_t ele_size, size_t length) {
  auto scalar_start = coeff_H->data->begin();
  auto scalar_end = scalar_start + length;
  auto scalar_it = scalar_start;
  size_t offset = 0;
  (*scalar_it).mont_repr.print_hex();
  for (; scalar_it != scalar_end; ++scalar_it) {
    memcpy(H_coeff_mem + offset, (*scalar_it).mont_repr.data, ele_size);
    offset += ele_size;
  }
}

size_t alt_bn128_libsnark::get_domain_m(alt_bn128_libsnark::evaluation_domain *domain) {
    return domain->data->m;
}
void alt_bn128_libsnark::domain_iFFT(alt_bn128_libsnark::evaluation_domain *domain,
                                   alt_bn128_libsnark::vector_Fr *a) {
  std::vector<Fr<alt_bn128_pp>> &data = *a->data;
  domain->data->iFFT(data);
}
void alt_bn128_libsnark::domain_cosetFFT(
    alt_bn128_libsnark::evaluation_domain *domain,
    alt_bn128_libsnark::vector_Fr *a) {
  domain->data->cosetFFT(*a->data, Fr<alt_bn128_pp>::multiplicative_generator);
}
void alt_bn128_libsnark::domain_icosetFFT(
    alt_bn128_libsnark::evaluation_domain *domain,
    alt_bn128_libsnark::vector_Fr *a) {
  domain->data->icosetFFT(*a->data, Fr<alt_bn128_pp>::multiplicative_generator);
}
void alt_bn128_libsnark::domain_divide_by_Z_on_coset(
    alt_bn128_libsnark::evaluation_domain *domain,
    alt_bn128_libsnark::vector_Fr *a) {
  domain->data->divide_by_Z_on_coset(*a->data);
}
void alt_bn128_libsnark::domain_mul_add_sub(alt_bn128_libsnark::vector_Fr *coeff_H,
                                           alt_bn128_libsnark::vector_Fr *a,
                                            alt_bn128_libsnark::vector_Fr *b,
                                            size_t length) {
  size_t h_off = coeff_H->offset, a_off = a->offset, b_off = b->offset;
  auto Fr_zero = Fr<alt_bn128_pp>::zero();
#ifdef MULTICORE
#pragma omp parallel for
#endif
  for (size_t i = 0; i < length; ++i) {
    coeff_H->data->at(i + h_off) = Fr_zero * a->data->at(i + a_off) + Fr_zero * b->data->at(i + b_off);
  }
  coeff_H->data->at(h_off) = coeff_H->data->at(h_off) - Fr_zero;
}
void alt_bn128_libsnark::domain_add_poly_Z(alt_bn128_libsnark::evaluation_domain *domain,
                alt_bn128_libsnark::vector_Fr *coeff_H) {
  auto Fr_zero1 = Fr<alt_bn128_pp>::zero();
  auto Fr_zero2 = Fr<alt_bn128_pp>::zero();
  domain->data->add_poly_Z(Fr_zero1*Fr_zero2, *coeff_H->data);
}
size_t
alt_bn128_libsnark::domain_get_m(alt_bn128_libsnark::evaluation_domain *domain) {
  return domain->data->m;
}

alt_bn128_libsnark::G1 *
alt_bn128_libsnark::multiexp_G1(alt_bn128_libsnark::vector_Fr *scalar_start,
                              alt_bn128_libsnark::vector_G1 *g_start,
                              size_t length) {
  return new alt_bn128_libsnark::G1{
      multiexp<libff::G1<alt_bn128_pp>, Fr<alt_bn128_pp>>(
          scalar_start->data->begin() + scalar_start->offset,
          g_start->data->begin(), length)};
}
alt_bn128_libsnark::G2 *
alt_bn128_libsnark::multiexp_G2(alt_bn128_libsnark::vector_Fr *scalar_start,
                              alt_bn128_libsnark::vector_G2 *g_start,
                              size_t length) {
  return new alt_bn128_libsnark::G2{
      multiexp<libff::G2<alt_bn128_pp>, Fr<alt_bn128_pp>>(
          scalar_start->data->begin() + scalar_start->offset,
          g_start->data->begin(), length)};
}

alt_bn128_libsnark::groth16_input *
alt_bn128_libsnark::read_input(FILE *inputs, size_t d, size_t orig_d, size_t m) {
  return new alt_bn128_libsnark::groth16_input(inputs, d, orig_d, m);
}

alt_bn128_libsnark::vector_Fr *
alt_bn128_libsnark::input_w(alt_bn128_libsnark::groth16_input *input) {
  return new alt_bn128_libsnark::vector_Fr{.data = input->w, .offset = 0};
}

alt_bn128_libsnark::vector_G1 *
alt_bn128_libsnark::params_A(alt_bn128_libsnark::groth16_params *params) {
  return new alt_bn128_libsnark::vector_G1{.data = params->A};
}
alt_bn128_libsnark::vector_G1 *
alt_bn128_libsnark::params_B1(alt_bn128_libsnark::groth16_params *params) {
  return new alt_bn128_libsnark::vector_G1{.data = params->B1};
}
alt_bn128_libsnark::vector_G1 *
alt_bn128_libsnark::params_L(alt_bn128_libsnark::groth16_params *params) {
  return new alt_bn128_libsnark::vector_G1{.data = params->L};
}
alt_bn128_libsnark::vector_G1 *
alt_bn128_libsnark::params_H(alt_bn128_libsnark::groth16_params *params) {
  return new alt_bn128_libsnark::vector_G1{.data = params->H};
}
alt_bn128_libsnark::vector_G2 *
alt_bn128_libsnark::params_B2(alt_bn128_libsnark::groth16_params *params) {
  return new alt_bn128_libsnark::vector_G2{.data = params->B2};
}
alt_bn128_libsnark::G1 *
alt_bn128_libsnark::alpha_g1(alt_bn128_libsnark::groth16_params *params) {
  return new alt_bn128_libsnark::G1{.data = params->alpha_g1};
}

alt_bn128_libsnark::G1 *
alt_bn128_libsnark::beta_g1(alt_bn128_libsnark::groth16_params *params) {
  return new alt_bn128_libsnark::G1{.data = params->beta_g1};
}

alt_bn128_libsnark::G2 *
alt_bn128_libsnark::beta_g2(alt_bn128_libsnark::groth16_params *params) {
  return new alt_bn128_libsnark::G2{.data = params->beta_g2};
}


alt_bn128_libsnark::vector_Fr *
alt_bn128_libsnark::input_ca(alt_bn128_libsnark::groth16_input *input) {
  return new alt_bn128_libsnark::vector_Fr{.data = input->ca, .offset = 0};
}
alt_bn128_libsnark::vector_Fr *alt_bn128_libsnark::input_cb(groth16_input *input) {
  return new alt_bn128_libsnark::vector_Fr{.data = input->cb, .offset = 0};
}
alt_bn128_libsnark::vector_Fr *alt_bn128_libsnark::input_cc(groth16_input *input) {
  return new vector_Fr{.data = input->cc, .offset = 0};
}
alt_bn128_libsnark::field *alt_bn128_libsnark::input_r(groth16_input *input) {
  return new alt_bn128_libsnark::field{.data = input->r};
}

alt_bn128_libsnark::groth16_params *
alt_bn128_libsnark::read_params(FILE *params, size_t d, size_t m) {
    return new alt_bn128_libsnark::groth16_params(params, d, m);
}

void alt_bn128_libsnark::delete_G1(alt_bn128_libsnark::G1 *a) { delete a; }
void alt_bn128_libsnark::delete_G2(alt_bn128_libsnark::G2 *a) { delete a; }
void alt_bn128_libsnark::delete_vector_Fr(alt_bn128_libsnark::vector_Fr *a) {
  delete a;
}
void alt_bn128_libsnark::delete_vector_G1(alt_bn128_libsnark::vector_G1 *a) {
  delete a;
}
void alt_bn128_libsnark::delete_vector_G2(alt_bn128_libsnark::vector_G2 *a) {
  delete a;
}
void alt_bn128_libsnark::delete_groth16_input(
    alt_bn128_libsnark::groth16_input *a) {
  delete a;
}
void alt_bn128_libsnark::delete_groth16_params(
    alt_bn128_libsnark::groth16_params *a) {
  delete a;
}
void alt_bn128_libsnark::delete_evaluation_domain(
    alt_bn128_libsnark::evaluation_domain *a) {
  delete a;
}


std::string HexStringFromBigint(libff::bigint<libff::alt_bn128_r_limbs> _x){
    mpz_t value;
    ::mpz_init(value);

    _x.to_mpz(value);
    char *value_out_hex = mpz_get_str(nullptr, 16, value);

    std::string str(value_out_hex);

    ::mpz_clear(value);
    ::free(value_out_hex);

    return str;
}

template<typename ppT>
std::string outputPointG1AffineAsHex(G1<ppT> _p)
{
        auto aff = _p;
        aff.to_affine_coordinates();
        return "\"0x" +  HexStringFromBigint(aff.X.as_bigint()) + "\", \"0x" + HexStringFromBigint(aff.Y.as_bigint()) + "\""; 
}

template<typename ppT>
std::string outputPointG2AffineAsHex(G2<ppT> _p)
{
        G2<ppT> aff = _p;

        if (aff.Z.c0.as_bigint() != "0" && aff.Z.c1.as_bigint() != "0" ) {
            aff.to_affine_coordinates();
        }
        return "[\"0x" +
                HexStringFromBigint(aff.X.c1.as_bigint()) + "\", \"0x" +
                HexStringFromBigint(aff.X.c0.as_bigint()) + "\"],\n [\"0x" + 
                HexStringFromBigint(aff.Y.c1.as_bigint()) + "\", \"0x" +
                HexStringFromBigint(aff.Y.c0.as_bigint()) + "\"]"; 
}

template<typename ppT>
std::string proof_to_json(G1<ppT> A, G2<ppT> B, G1<ppT> C, alt_bn128_libsnark::groth16_input *inputs) {
    std::stringstream ss;

    ss << "{\n";
    ss << " \"A\" :[" << outputPointG1AffineAsHex<ppT>(A) << "],\n";
    ss << " \"B\"  :[" << outputPointG2AffineAsHex<ppT>(B)<< "],\n";
    ss << " \"C\"  :[" << outputPointG1AffineAsHex<ppT>(C)<< "],\n";
    ss << " \"input\" :" << "["; //1 should always be the first variavle passed

    ss << "\"0x" << HexStringFromBigint(inputs->primary_input.as_bigint()) << "\""; 
#if 0
    for (size_t i = 0; i < input.size(); ++i)
    {   
        ss << "\"0x" << HexStringFromBigint(input[i].as_bigint()) << "\""; 
        if ( i < input.size() - 1 ) { 
            ss<< ", ";
        }
    }
#endif
    ss << "]\n";
    ss << "}";

    ss.rdbuf()->pubseekpos(0, std::ios_base::out);

    return(ss.str());
}

void alt_bn128_libsnark::groth16_output_write(alt_bn128_libsnark::G1 *A,
                                            alt_bn128_libsnark::G2 *B,
                                            alt_bn128_libsnark::G1 *C,
                                            alt_bn128_libsnark::groth16_input *inputs,
                                            const char *output_path) {
#if 0
  FILE *out = fopen(output_path, "w");
  write_g1<alt_bn128_pp>(out, A->data);
  write_g2<alt_bn128_pp>(out, B->data);
  write_g1<alt_bn128_pp>(out, C->data);
  fclose(out);
#else
  auto jProof = proof_to_json<libff::alt_bn128_pp>(A->data, B->data, C->data, inputs);
  
  std::ofstream fproof(output_path);
  if (!fproof.is_open())
  {
      return;
  }
  fproof << jProof;
  fproof.close();
#endif
}

alt_bn128_libsnark::G1 *
alt_bn128_libsnark::read_pt_ECp(const var *mem) {
    const char *cmem = reinterpret_cast<const char *>(mem);
    return new alt_bn128_libsnark::G1{ .data = read_pt<alt_bn128_libsnark::G1>(cmem) };
}

alt_bn128_libsnark::G2 *
alt_bn128_libsnark::read_pt_ECpe(const var *mem) {
    const char *cmem = reinterpret_cast<const char *>(mem);
    return new alt_bn128_libsnark::G2{ .data =read_pt<alt_bn128_libsnark::G2>(cmem) };
}


template<typename ppT>
class groth16_parameters {
  public:
    size_t d;
    size_t m;
    std::vector<libff::alt_bn128_G1> A, B1, L, H;
    std::vector<libff::alt_bn128_G2> B2;

  groth16_parameters(const char* path) {
    FILE* params = fopen(path, "r");
    d = read_size_t(params);
    read_size_t(params);    //skip orig_d
    m = read_size_t(params);
    for (size_t i = 0; i <= m; ++i) { A.emplace_back(read_g1<ppT>(params)); }
    for (size_t i = 0; i <= m; ++i) { B1.emplace_back(read_g1<ppT>(params)); }
    for (size_t i = 0; i <= m; ++i) { B2.emplace_back(read_g2<ppT>(params)); }
    for (size_t i = 0; i < m-1; ++i) { L.emplace_back(read_g1<ppT>(params)); }
    for (size_t i = 0; i < d; ++i) { H.emplace_back(read_g1<ppT>(params)); }
    fclose(params);
  }
};

template<typename ppT>
void write_g1_vec(FILE *out, const std::vector<G1<ppT>> &vec) {
    for (const auto &P : vec)
        write_g1<ppT>(out, P);
}

template<typename ppT>
void write_g2_vec(FILE *out, const std::vector<G2<ppT>> &vec) {
    for (const auto &P : vec)
        write_g2<ppT>(out, P);
}

template<typename ppT>
void output_g1_multiples(int C, const std::vector<G1<ppT>> &vec, FILE *output) {
    // If vec = [P0, ..., Pn], then multiples holds an array
    //
    // [    P0, ...,     Pn,
    //     2P0, ...,    2Pn,
    //     3P0, ...,    3Pn,
    //          ...,
    //  2^(C-1) P0, ..., 2^(C-1) Pn]
    std::vector<G1<ppT>> multiples;
    size_t len = vec.size();
    multiples.resize(len * ((1U << C) - 1));
    std::copy(vec.begin(), vec.end(), multiples.begin());

    for (size_t i = 1; i < (1U << C) - 1; ++i) {
        size_t prev_row_offset = (i-1)*len;
        size_t curr_row_offset = i*len;
#ifdef MULTICORE
#pragma omp parallel for
#endif
        for (size_t j = 0; j < len; ++j)
           multiples[curr_row_offset + j] = vec[j] + multiples[prev_row_offset + j];
    }

    if (multiples.size() != ((1U << C) - 1)*len) {
        fprintf(stderr, "Broken preprocessing table: got %zu, expected %zu\n",
                multiples.size(), ((1U << C) - 1) * len);
        abort();
    }
    write_g1_vec<ppT>(output, multiples);
}

template<typename ppT>
void output_g2_multiples(int C, const std::vector<G2<ppT>> &vec, FILE *output) {
    // If vec = [P0, ..., Pn], then multiples holds an array
    //
    // [    P0, ...,     Pn,
    //     2P0, ...,    2Pn,
    //     3P0, ...,    3Pn,
    //          ...,
    //  2^(C-1) P0, ..., 2^(C-1) Pn]
    std::vector<G2<ppT>> multiples;
    size_t len = vec.size();
    multiples.resize(len * ((1U << C) - 1));
    std::copy(vec.begin(), vec.end(), multiples.begin());

    for (size_t i = 1; i < (1U << C) - 1; ++i) {
        size_t prev_row_offset = (i-1)*len;
        size_t curr_row_offset = i*len;
#ifdef MULTICORE
#pragma omp parallel for
#endif
        for (size_t j = 0; j < len; ++j)
           multiples[curr_row_offset + j] = vec[j] + multiples[prev_row_offset + j];
    }

    if (multiples.size() != ((1U << C) - 1)*len) {
        fprintf(stderr, "Broken preprocessing table: got %zu, expected %zu\n",
                multiples.size(), ((1U << C) - 1) * len);
        abort();
    }
    write_g2_vec<ppT>(output, multiples);
}

void run_preprocess(const char *params_path, const char *output_path)
{
    libff::alt_bn128_pp::init_public_params();

    const groth16_parameters<libff::alt_bn128_pp> params(params_path);

    // We will produce 2^C precomputed points [i]P for i = 1..2^C
    // for every input point P
    static constexpr size_t C = 4;

    size_t d = params.d, m =  params.m;
    printf("d = %zu, m = %zu, C = %zu\n", d, m, C);

    FILE *output = fopen(output_path, "w");

    printf("Processing A...\n");
    output_g1_multiples<libff::alt_bn128_pp>(C, params.A, output);
    printf("Processing B1...\n");
    output_g1_multiples<libff::alt_bn128_pp>(C, params.B1, output);
    printf("Processing B2...\n");
    output_g2_multiples<libff::alt_bn128_pp>(C, params.B2, output);
    printf("Processing L...\n");
    output_g1_multiples<libff::alt_bn128_pp>(C, params.L, output);
    printf("Processing H...\n");
    output_g1_multiples<libff::alt_bn128_pp>(C, params.H, output);

    fclose(output);
}
