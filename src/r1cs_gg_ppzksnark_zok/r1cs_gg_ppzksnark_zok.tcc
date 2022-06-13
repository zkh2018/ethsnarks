/** @file
*****************************************************************************

Implementation of interfaces for a ppzkSNARK for R1CS.

See r1cs_gg_ppzksnark_zok.hpp .

*****************************************************************************
* @author     This file is part of libsnark, developed by SCIPR Lab
*             and contributors (see AUTHORS).
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/

#ifndef R1CS_GG_PPZKSNARK_TCC_
#define R1CS_GG_PPZKSNARK_TCC_

#include <algorithm>
#include <cassert>
#include <functional>
#include <iostream>
#include <sstream>
#include <thread>


#include <libff/algebra/scalar_multiplication/multiexp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <libsnark/knowledge_commitment/kc_multiexp.hpp>
#include <libsnark/reductions/r1cs_to_qap/r1cs_to_qap.hpp>

namespace libsnark {

/******************************** Proving key ********************************/

template<typename ppT>
bool r1cs_gg_ppzksnark_zok_proving_key<ppT>::operator==(const r1cs_gg_ppzksnark_zok_proving_key<ppT> &other) const
{
    return (this->alpha_g1 == other.alpha_g1 &&
            this->beta_g1 == other.beta_g1 &&
            this->beta_g2 == other.beta_g2 &&
            this->delta_g1 == other.delta_g1 &&
            this->delta_g2 == other.delta_g2 &&
            this->A_query == other.A_query &&
            this->B_query == other.B_query &&
            this->H_query == other.H_query &&
            this->L_query == other.L_query &&
            this->constraint_system == other.constraint_system);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppzksnark_zok_proving_key<ppT> &pk)
{
    out << pk.alpha_g1 << OUTPUT_NEWLINE;
    out << pk.beta_g1 << OUTPUT_NEWLINE;
    out << pk.beta_g2 << OUTPUT_NEWLINE;
    out << pk.delta_g1 << OUTPUT_NEWLINE;
    out << pk.delta_g2 << OUTPUT_NEWLINE;
    out << pk.A_query;
    out << pk.B_query;
    out << pk.H_query;
    out << pk.L_query;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppzksnark_zok_proving_key<ppT> &pk)
{
    in >> pk.alpha_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.beta_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.beta_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.delta_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.delta_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.A_query;
    in >> pk.B_query;
    in >> pk.H_query;
    in >> pk.L_query;

    return in;
}


/******************************** Proving key (no ZK) ********************************/

template<typename ppT>
bool r1cs_gg_ppzksnark_zok_proving_key_nozk<ppT>::operator==(const r1cs_gg_ppzksnark_zok_proving_key_nozk<ppT> &other) const
{
    return (this->alpha_g1 == other.alpha_g1 &&
            this->beta_g1 == other.beta_g1 &&
            this->beta_g2 == other.beta_g2 &&
            this->delta_g1 == other.delta_g1 &&
            this->delta_g2 == other.delta_g2 &&
            this->A_query == other.A_query &&
            this->B_query == other.B_query &&
            this->H_query == other.H_query &&
            this->L_query == other.L_query &&
            this->constraint_system == other.constraint_system);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppzksnark_zok_proving_key_nozk<ppT> &pk)
{
    out << pk.alpha_g1 << OUTPUT_NEWLINE;
    out << pk.beta_g1 << OUTPUT_NEWLINE;
    out << pk.beta_g2 << OUTPUT_NEWLINE;
    out << pk.delta_g1 << OUTPUT_NEWLINE;
    out << pk.delta_g2 << OUTPUT_NEWLINE;
    out << pk.A_query;
    out << pk.B_query;
    out << pk.H_query;
    out << pk.L_query;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppzksnark_zok_proving_key_nozk<ppT> &pk)
{
    std::cout << "Start loading pk" << std::endl;
    in >> pk.alpha_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.beta_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.beta_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.delta_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.delta_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.A_query;
    in >> pk.B_query;
    in >> pk.H_query;
    in >> pk.L_query;
    return in;
}

//**

template<typename ppT>
bool r1cs_gg_ppzksnark_zok_verification_key<ppT>::operator==(const r1cs_gg_ppzksnark_zok_verification_key<ppT> &other) const
{
    return (this->alpha_g1 == other.alpha_g1 &&
            this->beta_g2 == other.beta_g2 &&
            this->gamma_g2 == other.gamma_g2 &&
            this->delta_g2 == other.delta_g2 &&
            this->gamma_ABC_g1 == other.gamma_ABC_g1);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppzksnark_zok_verification_key<ppT> &vk)
{
    out << vk.alpha_g1 << OUTPUT_NEWLINE;
    out << vk.beta_g2 << OUTPUT_NEWLINE;
    out << vk.gamma_g2 << OUTPUT_NEWLINE;
    out << vk.delta_g2 << OUTPUT_NEWLINE;
    out << vk.gamma_ABC_g1 << OUTPUT_NEWLINE;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppzksnark_zok_verification_key<ppT> &vk)
{
    in >> vk.alpha_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.beta_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.gamma_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.delta_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.gamma_ABC_g1;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}

template<typename ppT>
bool r1cs_gg_ppzksnark_zok_processed_verification_key<ppT>::operator==(const r1cs_gg_ppzksnark_zok_processed_verification_key<ppT> &other) const
{
    return (this->vk_alpha_g1 == other.vk_alpha_g1 &&
            this->vk_beta_g2 == other.vk_beta_g2 &&
            this->vk_gamma_g2_precomp == other.vk_gamma_g2_precomp &&
            this->vk_delta_g2_precomp == other.vk_delta_g2_precomp &&
            this->gamma_ABC_g1 == other.gamma_ABC_g1);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppzksnark_zok_processed_verification_key<ppT> &pvk)
{
    out << pvk.vk_alpha_g1 << OUTPUT_NEWLINE;
    out << pvk.vk_beta_g2 << OUTPUT_NEWLINE;
    out << pvk.vk_gamma_g2_precomp << OUTPUT_NEWLINE;
    out << pvk.vk_delta_g2_precomp << OUTPUT_NEWLINE;
    out << pvk.gamma_ABC_g1 << OUTPUT_NEWLINE;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppzksnark_zok_processed_verification_key<ppT> &pvk)
{
    in >> pvk.vk_alpha_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pvk.vk_beta_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pvk.vk_gamma_g2_precomp;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pvk.vk_delta_g2_precomp;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pvk.gamma_ABC_g1;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}

template<typename ppT>
bool r1cs_gg_ppzksnark_zok_proof<ppT>::operator==(const r1cs_gg_ppzksnark_zok_proof<ppT> &other) const
{
    return (this->g_A == other.g_A &&
            this->g_B == other.g_B &&
            this->g_C == other.g_C);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppzksnark_zok_proof<ppT> &proof)
{
    out << proof.g_A << OUTPUT_NEWLINE;
    out << proof.g_B << OUTPUT_NEWLINE;
    out << proof.g_C << OUTPUT_NEWLINE;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppzksnark_zok_proof<ppT> &proof)
{
    in >> proof.g_A;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> proof.g_B;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> proof.g_C;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}

template<typename ppT>
r1cs_gg_ppzksnark_zok_verification_key<ppT> r1cs_gg_ppzksnark_zok_verification_key<ppT>::dummy_verification_key(const size_t input_size)
{
    r1cs_gg_ppzksnark_zok_verification_key<ppT> result;
    result.alpha_g1 = libff::G1<ppT>::random_element();
    result.beta_g2 = libff::G2<ppT>::random_element();
    result.gamma_g2 = libff::G2<ppT>::random_element();
    result.delta_g2 = libff::G2<ppT>::random_element();

    libff::G1<ppT> base = libff::G1<ppT>::random_element();
    libff::G1_vector<ppT> v;
    for (size_t i = 0; i < input_size; ++i)
    {
        v.emplace_back(libff::G1<ppT>::random_element());
    }

    result.gamma_ABC_g1 = accumulation_vector<libff::G1<ppT> >(std::move(base), std::move(v));

    return result;
}

template <typename ppT>
r1cs_gg_ppzksnark_zok_keypair<ppT> r1cs_gg_ppzksnark_zok_generator(const r1cs_gg_ppzksnark_zok_constraint_system<ppT> &r1cs)
{
    libff::enter_block("Call to r1cs_gg_ppzksnark_zok_generator");

    /* Generate secret randomness */
    const libff::Fr<ppT> t = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> alpha = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> beta = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> gamma = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> delta = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> gamma_inverse = gamma.inverse();
    const libff::Fr<ppT> delta_inverse = delta.inverse();

    /* A quadratic arithmetic program evaluated at t. */
    qap_instance_evaluation<libff::Fr<ppT> > qap = r1cs_to_qap_instance_map_with_evaluation(r1cs, t);

    libff::print_indent(); printf("* QAP number of variables: %zu\n", qap.num_variables());
    libff::print_indent(); printf("* QAP pre degree: %zu\n", r1cs.constraints.size());
    libff::print_indent(); printf("* QAP degree: %zu\n", qap.degree());
    libff::print_indent(); printf("* QAP number of input variables: %zu\n", qap.num_inputs());

    libff::enter_block("Compute query densities");
    size_t non_zero_At = 0;
    size_t non_zero_Bt = 0;
    for (size_t i = 0; i < qap.num_variables() + 1; ++i)
    {
        if (!qap.At[i].is_zero())
        {
            ++non_zero_At;
        }
        if (!qap.Bt[i].is_zero())
        {
            ++non_zero_Bt;
        }
    }
    libff::leave_block("Compute query densities");

    /* qap.{At,Bt,Ct,Ht} are now in unspecified state, but we do not use them later */
    libff::Fr_vector<ppT> At = std::move(qap.At);
    libff::Fr_vector<ppT> Bt = std::move(qap.Bt);
    libff::Fr_vector<ppT> Ct = std::move(qap.Ct);
    libff::Fr_vector<ppT> Ht = std::move(qap.Ht);

    /* The gamma inverse product component: (beta*A_i(t) + alpha*B_i(t) + C_i(t)) * gamma^{-1}. */
    libff::enter_block("Compute gamma_ABC for R1CS verification key");
    libff::Fr_vector<ppT> gamma_ABC;
    gamma_ABC.reserve(qap.num_inputs());

    const libff::Fr<ppT> gamma_ABC_0 = (beta * At[0] + alpha * Bt[0] + Ct[0]) * gamma_inverse;
    for (size_t i = 1; i < qap.num_inputs() + 1; ++i)
    {
        gamma_ABC.emplace_back((beta * At[i] + alpha * Bt[i] + Ct[i]) * gamma_inverse);
    }
    libff::leave_block("Compute gamma_ABC for R1CS verification key");

    /* The delta inverse product component: (beta*A_i(t) + alpha*B_i(t) + C_i(t)) * delta^{-1}. */
    libff::enter_block("Compute L query for R1CS proving key");
    libff::Fr_vector<ppT> Lt;
    Lt.reserve(qap.num_variables() - qap.num_inputs());

    const size_t Lt_offset = qap.num_inputs() + 1;
    for (size_t i = 0; i < qap.num_variables() - qap.num_inputs(); ++i)
    {
        Lt.emplace_back((beta * At[Lt_offset + i] + alpha * Bt[Lt_offset + i] + Ct[Lt_offset + i]) * delta_inverse);
    }
    libff::leave_block("Compute L query for R1CS proving key");

    /**
     * Note that H for Groth's proof system is degree d-2, but the QAP
     * reduction returns coefficients for degree d polynomial H (in
     * style of PGHR-type proof systems)
     */
    Ht.resize(Ht.size() - 2);

#ifdef MULTICORE
    const size_t chunks = omp_get_max_threads(); // to override, set OMP_NUM_THREADS env var or call omp_set_num_threads()
#else
    const size_t chunks = 1;
#endif

    libff::enter_block("Generating G1 MSM window table");
    const libff::G1<ppT> g1_generator = libff::G1<ppT>::random_element();
    const size_t g1_scalar_count = non_zero_At + non_zero_Bt + qap.num_variables();
    const size_t g1_scalar_size = libff::Fr<ppT>::size_in_bits();
    const size_t g1_window_size = libff::get_exp_window_size<libff::G1<ppT> >(g1_scalar_count);

    libff::print_indent(); printf("* G1 window: %zu\n", g1_window_size);
    libff::window_table<libff::G1<ppT> > g1_table = libff::get_window_table(g1_scalar_size, g1_window_size, g1_generator);
    libff::leave_block("Generating G1 MSM window table");

    libff::enter_block("Generating G2 MSM window table");
    const libff::G2<ppT> G2_gen = libff::G2<ppT>::random_element();
    const size_t g2_scalar_count = non_zero_Bt;
    const size_t g2_scalar_size = libff::Fr<ppT>::size_in_bits();
    size_t g2_window_size = libff::get_exp_window_size<libff::G2<ppT> >(g2_scalar_count);

    libff::print_indent(); printf("* G2 window: %zu\n", g2_window_size);
    libff::window_table<libff::G2<ppT> > g2_table = libff::get_window_table(g2_scalar_size, g2_window_size, G2_gen);
    libff::leave_block("Generating G2 MSM window table");

    libff::enter_block("Generate R1CS proving key");
    libff::G1<ppT> alpha_g1 = alpha * g1_generator;
    libff::G1<ppT> beta_g1 = beta * g1_generator;
    libff::G2<ppT> beta_g2 = beta * G2_gen;
    libff::G1<ppT> delta_g1 = delta * g1_generator;
    libff::G2<ppT> delta_g2 = delta * G2_gen;

    libff::enter_block("Generate queries");
    libff::enter_block("Compute the A-query", false);
    libff::G1_vector<ppT> A_query = batch_exp(g1_scalar_size, g1_window_size, g1_table, At);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(A_query);
#endif
    libff::leave_block("Compute the A-query", false);

    libff::enter_block("Compute the B-query", false);
    knowledge_commitment_vector<libff::G2<ppT>, libff::G1<ppT> > B_query = kc_batch_exp(libff::Fr<ppT>::size_in_bits(), g2_window_size, g1_window_size, g2_table, g1_table, libff::Fr<ppT>::one(), libff::Fr<ppT>::one(), Bt, chunks);
    // NOTE: if USE_MIXED_ADDITION is defined,
    // kc_batch_exp will convert its output to special form internally
    libff::leave_block("Compute the B-query", false);

    libff::enter_block("Compute the H-query", false);
    libff::G1_vector<ppT> H_query = batch_exp_with_coeff(g1_scalar_size, g1_window_size, g1_table, qap.Zt * delta_inverse, Ht);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(H_query);
#endif
    libff::leave_block("Compute the H-query", false);

    libff::enter_block("Compute the L-query", false);
    libff::G1_vector<ppT> L_query = batch_exp(g1_scalar_size, g1_window_size, g1_table, Lt);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(L_query);
#endif
    libff::leave_block("Compute the L-query", false);
    libff::leave_block("Generate queries");

    libff::leave_block("Generate R1CS proving key");

    libff::enter_block("Generate R1CS verification key");
    libff::G2<ppT> gamma_g2 = gamma * G2_gen;

    libff::enter_block("Encode gamma_ABC for R1CS verification key");
    libff::G1<ppT> gamma_ABC_g1_0 = gamma_ABC_0 * g1_generator;
    libff::G1_vector<ppT> gamma_ABC_g1_values = batch_exp(g1_scalar_size, g1_window_size, g1_table, gamma_ABC);
    libff::leave_block("Encode gamma_ABC for R1CS verification key");
    libff::leave_block("Generate R1CS verification key");

    libff::leave_block("Call to r1cs_gg_ppzksnark_zok_generator");

    accumulation_vector<libff::G1<ppT> > gamma_ABC_g1(std::move(gamma_ABC_g1_0), std::move(gamma_ABC_g1_values));

    r1cs_gg_ppzksnark_zok_verification_key<ppT> vk = r1cs_gg_ppzksnark_zok_verification_key<ppT>(alpha_g1,
                                                                                         beta_g2,
                                                                                         gamma_g2,
                                                                                         delta_g2,
                                                                                         gamma_ABC_g1);

    r1cs_gg_ppzksnark_zok_proving_key<ppT> pk = r1cs_gg_ppzksnark_zok_proving_key<ppT>(std::move(alpha_g1),
                                                                               std::move(beta_g1),
                                                                               std::move(beta_g2),
                                                                               std::move(delta_g1),
                                                                               std::move(delta_g2),
                                                                               std::move(A_query),
                                                                               std::move(B_query),
                                                                               std::move(H_query),
                                                                               std::move(L_query));

    //pk.print_size();
    //vk.print_size();

    return r1cs_gg_ppzksnark_zok_keypair<ppT>(std::move(pk), std::move(vk));
}

//#define GPU_MCL
template <typename ppT>
r1cs_gg_ppzksnark_zok_proof<ppT> r1cs_gg_ppzksnark_zok_prover(ProverContext<ppT>& context, const std::vector<libff::Fr<ppT>>& full_variable_assignment)
{
    gpu::warm_up();
    libff::enter_block("Call to cpu_r1cs_gg_ppzksnark_zok_prover");

    const std::shared_ptr<libfqfft::evaluation_domain<libff::Fr<ppT>>>& domain = context.domain;
    const r1cs_gg_ppzksnark_zok_proving_key_nozk<ppT>& pk = context.provingKey;
    const r1cs_constraint_system<libff::Fr<ppT>>& cs = *context.constraint_system;

    libff::enter_block("Compute the polynomial H");
    r1cs_to_qap_witness_map(
        context.domain,
        cs,
        full_variable_assignment,
        context.aA,
        context.aB,
        context.aH
    );

    /* We are dividing degree 2(d-1) polynomial by degree d polynomial
       and not adding a PGHR-style ZK-patch, so our H is degree d-2 */
    assert(!context.aH[domain->m-2].is_zero());
    assert(context.aH[domain->m-1].is_zero());
    assert(context.aH[domain->m].is_zero());
    libff::leave_block("Compute the polynomial H");

#ifdef DEBUG
    assert(full_variable_assignment.size() == cs.num_variables() + 1);
    assert(pk.A_query.domain_size() == cs.num_variables()+1);
    assert(pk.B_query.domain_size() == cs.num_variables()+1);
    assert(pk.H_query.size() == domain->m - 1);
    assert(pk.L_query.size() == cs.num_variables() - cs.num_inputs());
#endif


    libff::enter_block("Compute the proof");


    libff::enter_block("Compute evaluation to H-query", false);
    //libff::G1<ppT> evaluation_Ht = libff::multi_exp<libff::G1<ppT>,
    libff::G1<ppT> evaluation_Ht; 
#ifdef GPU_MCL
//#if false
    libff::GpuMclData gpu_mcl_data_ht;
    std::thread t3([&](){
        evaluation_Ht = libff::multi_exp_gpu_mcl<libff::G1<ppT>,
#else
        evaluation_Ht = libff::multi_exp<libff::G1<ppT>,
#endif
        libff::Fr<ppT>,
        libff::multi_exp_method_BDLO12>(
            pk.H_query.begin(),
            pk.H_query.begin() + (domain->m - 1),
            context.aH.begin(),
            context.aH.begin() + (domain->m - 1),
            context.scratch_exponents,
#ifdef GPU_MCL
            context.config,
            gpu_mcl_data_ht);
#else
            context.config);
#endif
        
#ifdef GPU_MCL
    });
#endif
    //t3.join();
    libff::leave_block("Compute evaluation to H-query", false);

    libff::enter_block("Compute evaluation to L-query", false);
     //libff::G1<ppT> evaluation_Lt = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
    libff::G1<ppT> evaluation_Lt; 
//#ifdef GPU_MCL
#if false
    std::thread t4([&](){
        evaluation_Lt = libff::multi_exp_with_mixed_addition_gpu_mcl<libff::G1<ppT>,
#else
        evaluation_Lt = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
#endif
        libff::Fr<ppT>,
        libff::multi_exp_method_BDLO12>(
            pk.L_query.begin(),
            pk.L_query.end(),
            full_variable_assignment.begin() + cs.num_inputs() + 1,
            full_variable_assignment.begin() + cs.num_variables() + 1,
            context.scratch_exponents,
            context.config);
//#ifdef GPU_MCL
#if false
    });
#endif
    //t1.join();
    //t3.join();
    //t4.join();
    libff::leave_block("Compute evaluation to L-query", false);


    libff::enter_block("Compute evaluation to A-query", false);
    ///libff::G1<ppT> evaluation_At = kc_multi_exp_with_mixed_addition<libff::G1<ppT>,
    libff::G1<ppT> evaluation_At;
#ifdef GPU_MCL
    libff::GpuMclData gpu_mcl_data_at;
///#if false
    std::thread t1([&](){
        evaluation_At = kc_multi_exp_with_mixed_addition_mcl<libff::G1<ppT>,
#else
        evaluation_At = kc_multi_exp_with_mixed_addition<libff::G1<ppT>,
#endif
        libff::Fr<ppT>,
        libff::multi_exp_method_BDLO12>(
            pk.A_query,
            full_variable_assignment.begin(),
            full_variable_assignment.begin() + cs.num_variables() + 1,
            context.scratch_exponents,

#ifdef GPU_MCL
            context.config,
            gpu_mcl_data_at);
#else
            context.config);
#endif
    
#ifdef GPU_MCL
    });
#endif
    //t1.join();
    libff::leave_block("Compute evaluation to A-query", false);

    libff::enter_block("Compute evaluation to B-query", false);
    libff::G2<ppT> evaluation_Bt;
    //std::thread t2([&](){
        evaluation_Bt = kc_multi_exp_with_mixed_addition<libff::G2<ppT>,
        //evaluation_Bt = gpu_kc_multi_exp_with_mixed_addition_g2_mcl<libff::G2<ppT>,
                  libff::Fr<ppT>,
                  libff::multi_exp_method_BDLO12>(
                      pk.B_query,
                      full_variable_assignment.begin(),
                      full_variable_assignment.begin() + cs.num_variables() + 1,
                      context.scratch_exponents,
                      context.config);
    //});
    libff::leave_block("Compute evaluation to B-query", false);
#ifdef GPU_MCL
    //t1.join();
    //t2.join();
    //t3.join();
    //t4.join();
    //gpu::sync_device();
#endif
    /* A = alpha + sum_i(a_i*A_i(t)) */
    libff::G1<ppT> g1_A = pk.alpha_g1 + evaluation_At;

    /* B = beta + sum_i(a_i*B_i(t)) */
    libff::G2<ppT> g2_B = pk.beta_g2 + evaluation_Bt;

    /* C = sum_i(a_i*((beta*A_i(t) + alpha*B_i(t) + C_i(t)) + H(t)*Z(t))/delta) */
    libff::G1<ppT> g1_C = evaluation_Ht + evaluation_Lt;

    libff::leave_block("Compute the proof");

    libff::leave_block("Call to r1cs_gg_ppzksnark_zok_prover");

    r1cs_gg_ppzksnark_zok_proof<ppT> proof = r1cs_gg_ppzksnark_zok_proof<ppT>(std::move(g1_A), std::move(g2_B), std::move(g1_C));
    proof.print_size();

    return proof;
}

#ifndef RUN_GPU_ALL
#define RUN_GPU_ALL
#endif

template <typename ppT>
r1cs_gg_ppzksnark_zok_proof<ppT> r1cs_gg_ppzksnark_zok_prover_gpu(ProverContext<ppT>& context, const std::vector<libff::Fr<ppT>>& full_variable_assignment)
{
    libff::enter_block("Call to gpu_r1cs_gg_ppzksnark_zok_prover");

    const std::shared_ptr<libfqfft::evaluation_domain<libff::Fr<ppT>>>& domain = context.domain;
    const r1cs_gg_ppzksnark_zok_proving_key_nozk<ppT>& pk = context.provingKey;
    const r1cs_constraint_system<libff::Fr<ppT>>& cs = *context.constraint_system;

    libff::enter_block("Compute the polynomial H");
    r1cs_to_qap_witness_map(
        context.domain,
        cs,
        full_variable_assignment,
        context.aA,
        context.aB,
        context.aH
    );

    /* We are dividing degree 2(d-1) polynomial by degree d polynomial
       and not adding a PGHR-style ZK-patch, so our H is degree d-2 */
    assert(!context.aH[domain->m-2].is_zero());
    assert(context.aH[domain->m-1].is_zero());
    assert(context.aH[domain->m].is_zero());
    libff::leave_block("Compute the polynomial H");

#ifdef DEBUG
    assert(full_variable_assignment.size() == cs.num_variables() + 1);
    assert(pk.A_query.domain_size() == cs.num_variables()+1);
    assert(pk.B_query.domain_size() == cs.num_variables()+1);
    assert(pk.H_query.size() == domain->m - 1);
    assert(pk.L_query.size() == cs.num_variables() - cs.num_inputs());
#endif

    gpu::warm_up();

    libff::enter_block("Compute the proof");

    libff::enter_block("gpu Compute evaluation to A,H,L-query", false);

    libff::G1<ppT> evaluation_At, evaluation_Ht, evaluation_Lt;
    std::thread t1([&](){
#ifdef RUN_GPU_ALL
        evaluation_At = gpu_kc_multi_exp_with_mixed_addition_g1<libff::G1<ppT>,
#else
      evaluation_At = kc_multi_exp_with_mixed_addition<libff::G1<ppT>,
#endif
        libff::Fr<ppT>,
        libff::multi_exp_method_BDLO12>(
            pk.A_query,
            full_variable_assignment.begin(),
            full_variable_assignment.begin() + cs.num_variables() + 1,
            context.scratch_exponents,
            context.config);
	});
    std::thread t2([&](){
#ifdef RUN_GPU_ALL
	evaluation_Ht = libff::multi_exp_gpu<libff::G1<ppT>,
#else
    evaluation_Ht = libff::multi_exp<libff::G1<ppT>,
#endif
        libff::Fr<ppT>,
        libff::multi_exp_method_BDLO12>(
            pk.H_query.begin(),
            pk.H_query.begin() + (domain->m - 1),
            context.aH.begin(),
            context.aH.begin() + (domain->m - 1),
            context.scratch_exponents,
            context.config);
	});

    std::thread t3([&](){
#ifdef RUN_GPU_ALL
	evaluation_Lt = libff::multi_exp_with_mixed_addition_gpu<libff::G1<ppT>,
#else
      evaluation_Lt = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
#endif

        libff::Fr<ppT>,
        libff::multi_exp_method_BDLO12>(
            pk.L_query.begin(),
            pk.L_query.end(),
            full_variable_assignment.begin() + cs.num_inputs() + 1,
            full_variable_assignment.begin() + cs.num_variables() + 1,
            context.scratch_exponents,
            context.config);
    });
    //t1.join();
    libff::leave_block("gpu Compute evaluation to A,H,L-query", false);

    libff::enter_block("Compute evaluation to B-query", false);
    libff::G2<ppT> evaluation_Bt;
    //evaluation_Bt = kc_multi_exp_with_mixed_addition<libff::G2<ppT>,
    evaluation_Bt = gpu_kc_multi_exp_with_mixed_addition_g2<libff::G2<ppT>,
                  libff::Fr<ppT>,
                  libff::multi_exp_method_BDLO12>(
                      pk.B_query,
                      full_variable_assignment.begin(),
                      full_variable_assignment.begin() + cs.num_variables() + 1,
                      context.scratch_exponents,
                      context.config);
    libff::leave_block("Compute evaluation to B-query", false);
    t1.join();
    t2.join();
    t3.join();

    /* A = alpha + sum_i(a_i*A_i(t)) */
    libff::G1<ppT> g1_A = pk.alpha_g1 + evaluation_At;

    /* B = beta + sum_i(a_i*B_i(t)) */
    libff::G2<ppT> g2_B = pk.beta_g2 + evaluation_Bt;

    /* C = sum_i(a_i*((beta*A_i(t) + alpha*B_i(t) + C_i(t)) + H(t)*Z(t))/delta) */
    libff::G1<ppT> g1_C = evaluation_Ht + evaluation_Lt;

    libff::leave_block("Compute the proof");

    libff::leave_block("Call to r1cs_gg_ppzksnark_zok_prover");

    r1cs_gg_ppzksnark_zok_proof<ppT> proof = r1cs_gg_ppzksnark_zok_proof<ppT>(std::move(g1_A), std::move(g2_B), std::move(g1_C));
    proof.print_size();

    return proof;
}

template <typename ppT>
r1cs_gg_ppzksnark_zok_processed_verification_key<ppT> r1cs_gg_ppzksnark_zok_verifier_process_vk(const r1cs_gg_ppzksnark_zok_verification_key<ppT> &vk)
{
    libff::enter_block("Call to r1cs_gg_ppzksnark_zok_verifier_process_vk");

    r1cs_gg_ppzksnark_zok_processed_verification_key<ppT> pvk;
    pvk.vk_alpha_g1 = vk.alpha_g1;
    pvk.vk_beta_g2 = vk.beta_g2;
    pvk.vk_gamma_g2_precomp = ppT::precompute_G2(vk.gamma_g2);
    pvk.vk_delta_g2_precomp = ppT::precompute_G2(vk.delta_g2);
    pvk.gamma_ABC_g1 = vk.gamma_ABC_g1;

    libff::leave_block("Call to r1cs_gg_ppzksnark_zok_verifier_process_vk");

    return pvk;
}

template <typename ppT>
bool r1cs_gg_ppzksnark_zok_online_verifier_weak_IC(const r1cs_gg_ppzksnark_zok_processed_verification_key<ppT> &pvk,
                                               const r1cs_gg_ppzksnark_zok_primary_input<ppT> &primary_input,
                                               const r1cs_gg_ppzksnark_zok_proof<ppT> &proof)
{
    libff::enter_block("Call to r1cs_gg_ppzksnark_zok_online_verifier_weak_IC");
    assert(pvk.gamma_ABC_g1.domain_size() >= primary_input.size());

    libff::enter_block("Accumulate input");
    const accumulation_vector<libff::G1<ppT> > accumulated_IC = pvk.gamma_ABC_g1.template accumulate_chunk<libff::Fr<ppT> >(primary_input.begin(), primary_input.end(), 0);
    const libff::G1<ppT> &acc = accumulated_IC.first;
    libff::leave_block("Accumulate input");

    bool result = true;

    libff::enter_block("Check if the proof is well-formed");
    if (!proof.is_well_formed())
    {
        if (!libff::inhibit_profiling_info)
        {
            libff::print_indent(); printf("At least one of the proof elements does not lie on the curve.\n");
        }
        result = false;
    }
    libff::leave_block("Check if the proof is well-formed");

    libff::enter_block("Online pairing computations");
    libff::enter_block("Check QAP divisibility");
    const libff::G1_precomp<ppT> proof_g_A_precomp = ppT::precompute_G1(proof.g_A);
    const libff::G2_precomp<ppT> proof_g_B_precomp = ppT::precompute_G2(proof.g_B);
    const libff::G1_precomp<ppT> proof_g_C_precomp = ppT::precompute_G1(proof.g_C);
    const libff::G1_precomp<ppT> acc_precomp = ppT::precompute_G1(acc);

    const libff::Fqk<ppT> QAP1 = ppT::miller_loop(proof_g_A_precomp,  proof_g_B_precomp);
    const libff::Fqk<ppT> QAP2 = ppT::double_miller_loop(
        acc_precomp, pvk.vk_gamma_g2_precomp,
        proof_g_C_precomp, pvk.vk_delta_g2_precomp);
    const libff::GT<ppT> QAP = ppT::final_exponentiation(QAP1 * QAP2.unitary_inverse());

    libff::GT<ppT> vk_alpha_g1_beta_g2 = ppT::reduced_pairing(pvk.vk_alpha_g1, pvk.vk_beta_g2);

    if (QAP != vk_alpha_g1_beta_g2)
    {
        if (!libff::inhibit_profiling_info)
        {
            libff::print_indent(); printf("QAP divisibility check failed.\n");
        }
        result = false;
    }
    libff::leave_block("Check QAP divisibility");
    libff::leave_block("Online pairing computations");

    libff::leave_block("Call to r1cs_gg_ppzksnark_zok_online_verifier_weak_IC");

    return result;
}

template<typename ppT>
bool r1cs_gg_ppzksnark_zok_verifier_weak_IC(const r1cs_gg_ppzksnark_zok_verification_key<ppT> &vk,
                                        const r1cs_gg_ppzksnark_zok_primary_input<ppT> &primary_input,
                                        const r1cs_gg_ppzksnark_zok_proof<ppT> &proof)
{
    libff::enter_block("Call to r1cs_gg_ppzksnark_zok_verifier_weak_IC");
    r1cs_gg_ppzksnark_zok_processed_verification_key<ppT> pvk = r1cs_gg_ppzksnark_zok_verifier_process_vk<ppT>(vk);
    bool result = r1cs_gg_ppzksnark_zok_online_verifier_weak_IC<ppT>(pvk, primary_input, proof);
    libff::leave_block("Call to r1cs_gg_ppzksnark_zok_verifier_weak_IC");
    return result;
}

template<typename ppT>
bool r1cs_gg_ppzksnark_zok_online_verifier_strong_IC(const r1cs_gg_ppzksnark_zok_processed_verification_key<ppT> &pvk,
                                                 const r1cs_gg_ppzksnark_zok_primary_input<ppT> &primary_input,
                                                 const r1cs_gg_ppzksnark_zok_proof<ppT> &proof)
{
    bool result = true;
    libff::enter_block("Call to r1cs_gg_ppzksnark_zok_online_verifier_strong_IC");

    if (pvk.gamma_ABC_g1.domain_size() != primary_input.size())
    {
        libff::print_indent(); printf("Input length differs from expected (got %zu, expected %zu).\n", primary_input.size(), pvk.gamma_ABC_g1.domain_size());
        result = false;
    }
    else
    {
        result = r1cs_gg_ppzksnark_zok_online_verifier_weak_IC(pvk, primary_input, proof);
    }

    libff::leave_block("Call to r1cs_gg_ppzksnark_zok_online_verifier_strong_IC");
    return result;
}

template<typename ppT>
bool r1cs_gg_ppzksnark_zok_verifier_strong_IC(const r1cs_gg_ppzksnark_zok_verification_key<ppT> &vk,
                                          const r1cs_gg_ppzksnark_zok_primary_input<ppT> &primary_input,
                                          const r1cs_gg_ppzksnark_zok_proof<ppT> &proof)
{
    libff::enter_block("Call to r1cs_gg_ppzksnark_zok_verifier_strong_IC");
    r1cs_gg_ppzksnark_zok_processed_verification_key<ppT> pvk = r1cs_gg_ppzksnark_zok_verifier_process_vk<ppT>(vk);
    bool result = r1cs_gg_ppzksnark_zok_online_verifier_strong_IC<ppT>(pvk, primary_input, proof);
    libff::leave_block("Call to r1cs_gg_ppzksnark_zok_verifier_strong_IC");
    return result;
}

template<typename ppT>
bool r1cs_gg_ppzksnark_zok_affine_verifier_weak_IC(const r1cs_gg_ppzksnark_zok_verification_key<ppT> &vk,
                                               const r1cs_gg_ppzksnark_zok_primary_input<ppT> &primary_input,
                                               const r1cs_gg_ppzksnark_zok_proof<ppT> &proof)
{
    libff::enter_block("Call to r1cs_gg_ppzksnark_zok_affine_verifier_weak_IC");
    assert(vk.gamma_ABC_g1.domain_size() >= primary_input.size());

    libff::affine_ate_G2_precomp<ppT> pvk_vk_gamma_g2_precomp = ppT::affine_ate_precompute_G2(vk.gamma_g2);
    libff::affine_ate_G2_precomp<ppT> pvk_vk_delta_g2_precomp = ppT::affine_ate_precompute_G2(vk.delta_g2);

    libff::enter_block("Accumulate input");
    const accumulation_vector<libff::G1<ppT> > accumulated_IC = vk.gamma_ABC_g1.template accumulate_chunk<libff::Fr<ppT> >(primary_input.begin(), primary_input.end(), 0);
    const libff::G1<ppT> &acc = accumulated_IC.first;
    libff::leave_block("Accumulate input");

    bool result = true;

    libff::enter_block("Check if the proof is well-formed");
    if (!proof.is_well_formed())
    {
        if (!libff::inhibit_profiling_info)
        {
            libff::print_indent(); printf("At least one of the proof elements does not lie on the curve.\n");
        }
        result = false;
    }
    libff::leave_block("Check if the proof is well-formed");

    libff::enter_block("Check QAP divisibility");
    const libff::affine_ate_G1_precomp<ppT> proof_g_A_precomp = ppT::affine_ate_precompute_G1(proof.g_A);
    const libff::affine_ate_G2_precomp<ppT> proof_g_B_precomp = ppT::affine_ate_precompute_G2(proof.g_B);
    const libff::affine_ate_G1_precomp<ppT> proof_g_C_precomp = ppT::affine_ate_precompute_G1(proof.g_C);
    const libff::affine_ate_G1_precomp<ppT> acc_precomp = ppT::affine_ate_precompute_G1(acc);

    const libff::Fqk<ppT> QAP_miller = ppT::affine_ate_e_times_e_over_e_miller_loop(
        acc_precomp, pvk_vk_gamma_g2_precomp,
        proof_g_C_precomp, pvk_vk_delta_g2_precomp,
        proof_g_A_precomp,  proof_g_B_precomp);
    const libff::GT<ppT> QAP = ppT::final_exponentiation(QAP_miller.unitary_inverse());

    libff::GT<ppT> vk_alpha_g1_beta_g2 = ppT::reduced_pairing(vk.alpha_g1, vk.beta_g2);

    if (QAP != vk_alpha_g1_beta_g2)
    {
        if (!libff::inhibit_profiling_info)
        {
            libff::print_indent(); printf("QAP divisibility check failed.\n");
        }
        result = false;
    }
    libff::leave_block("Check QAP divisibility");

    libff::leave_block("Call to r1cs_gg_ppzksnark_zok_affine_verifier_weak_IC");

    return result;
}

} // libsnark
#endif // R1CS_GG_PPZKSNARK_TCC_
