// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <libsnark/gadgetlib1/protoboard.hpp>

#include <sstream>  // stringstream

#include "utils.hpp"
#include "import.hpp"
#include "export.hpp"
#include "serialization.hpp"

#include "r1cs_gg_ppzksnark_zok/r1cs_gg_ppzksnark_zok.hpp"

namespace ethsnarks {

bool stub_verify( const char *vk_json, const char *proof_json )
{
    ppT::init_public_params();

    std::stringstream vk_stream;
    vk_stream << vk_json;
    auto vk = vk_from_json(vk_stream);

    std::stringstream proof_stream;
    proof_stream << proof_json;
    auto proof_pair = proof_from_json(proof_stream);

    auto status = libsnark::r1cs_gg_ppzksnark_zok_verifier_strong_IC <ppT> (vk, proof_pair.first, proof_pair.second);
    if( status )
        return true;

    return false;
}


std::string stub_prove_from_pb( ProtoboardT& pb, const char *pk_file )
{
    auto proving_key = ethsnarks::loadFromFile<ethsnarks::ProvingKeyT>(pk_file);
    // TODO: verify if proving key was loaded correctly, if not return NULL

    auto primary_input = pb.primary_input();
    auto proof = libsnark::r1cs_gg_ppzksnark_zok_prover<ethsnarks::ppT>(proving_key, primary_input, pb.auxiliary_input());
    return ethsnarks::proof_to_json(proof, primary_input);
}


int stub_genkeys_from_pb( ProtoboardT& pb, const char *pk_file, const char *vk_file )
{
    const auto constraints = pb.get_constraint_system();
    auto keypair = libsnark::r1cs_gg_ppzksnark_zok_generator<ppT>(constraints);
    vk2json_file(keypair.vk, vk_file);
    writeToFile<decltype(keypair.pk)>(pk_file, keypair.pk);

    return 0;
}

void write_params_file( ProvingKeyT &pk, const char *params_path, size_t orig_d, size_t m)
{
    auto params = fopen(params_path, "w");
    size_t d = pk.H_query.size();   //domain->m
    // Write parameters
    write_size_t(params, d);
    write_size_t(params, orig_d);
    write_size_t(params, m);
    for (size_t i = 0; i <= m; ++i) {
      write_g1<ppT>(params, pk.A_query[i]);
    }

    for (size_t i = 0; i <= m; ++i) {
      write_g1<ppT>(params, pk.B_query[i].h);
    }

    for (size_t i = 0; i <= m; ++i) {
      write_g2<ppT>(params, pk.B_query[i].g);
    }

    for (size_t i = 0; i < m-1; ++i) {
      write_g1<ppT>(params, pk.L_query[i]);
    }

    for (size_t i = 0; i < d; ++i) {
      write_g1<ppT>(params, pk.H_query[i]);
    }

    // alpha_g1
    write_g1<ppT>(params, pk.alpha_g1);
    // beta_g1
    write_g1<ppT>(params, pk.beta_g1);
    // beta_g2
    write_g2<ppT>(params, pk.beta_g2);
    fclose(params);
}

int stub_genkeys_params_from_pb( ProtoboardT& pb, const char *pk_file, const char *vk_file, const char *params_file )
{
    const auto constraints = pb.get_constraint_system();
    auto keypair = libsnark::r1cs_gg_ppzksnark_zok_generator<ppT>(constraints);
    vk2json_file(keypair.vk, vk_file);
    writeToFile<decltype(keypair.pk)>(pk_file, keypair.pk);
    size_t d = pb.num_constraints();
    size_t m = pb.get_constraint_system().num_variables();
    write_params_file(keypair.pk, params_file, d, m);
    return 0;
}

int stub_write_input_from_pb( ProtoboardT& pb, const char *pk_file,  const char *input_path )
{
    libff::enter_block("Call to stub_write_input_from_pb");

    libff::enter_block("Call to load pk file");
    auto proving_key = ethsnarks::loadFromFile<ethsnarks::ProvingKeyT>(pk_file);
    libff::leave_block("Call to load pk file");

    auto constraint_system = proving_key.constraint_system;
    auto primary_input = pb.primary_input();
    auto auxiliary_input = pb.auxiliary_input();
    size_t d = constraint_system.num_constraints();
    size_t m = constraint_system.num_variables();
    size_t num_input = constraint_system.num_inputs();

    const std::shared_ptr<libfqfft::evaluation_domain<FieldT> > domain = libfqfft::get_evaluation_domain<FieldT>(d + num_input + 1);

    auto full_variable_assignment = primary_input;
    full_variable_assignment.insert(full_variable_assignment.end(), auxiliary_input.begin(), auxiliary_input.end());

    // Write input
    auto inputs = fopen(input_path, "w");
    write_fr<ppT>(inputs, ethsnarks::FieldT::one());
    for (size_t i = 0; i < m; ++i) {
      write_fr<ppT>(inputs, full_variable_assignment[i]);
    }

    std::vector<FieldT> ca(domain->m, FieldT::zero()), cb(domain->m, FieldT::zero()), cc(domain->m, FieldT::zero());
    for (size_t i = 0; i <= num_input; ++i)
    {
        ca[i+d] = (i > 0 ? full_variable_assignment[i-1] : FieldT::one());
    }
#ifdef MULTICORE
#pragma omp parallel for
#endif
    for (size_t i = 0; i < d; ++i)
    {
#if 1
        ca[i] += constraint_system.constraints[i].a.evaluate(full_variable_assignment);
#else
        ca[i] += keypair.pk.constraint_system.constraints[i].a.evaluate(full_variable_assignment);
#endif
    }
    for (size_t i = 0; i < domain->m; ++i) {
      write_fr<ppT>(inputs, ca[i]);
    }
#ifdef MULTICORE
#pragma omp parallel for
#endif
    for (size_t i = 0; i < d; ++i)
    {
#if 1
        cb[i] += constraint_system.constraints[i].b.evaluate(full_variable_assignment);
#else
        cb[i] += keypair.pk.constraint_system.constraints[i].b.evaluate(full_variable_assignment);
#endif
    }
    for (size_t i = 0; i < domain->m; ++i) {
      write_fr<ppT>(inputs, cb[i]);
    }
#ifdef MULTICORE
#pragma omp parallel for
#endif
    for (size_t i = 0; i < d; ++i)
    {
#if 1
        cc[i] += constraint_system.constraints[i].c.evaluate(full_variable_assignment);
#else
        cc[i] += keypair.pk.constraint_system.constraints[i].c.evaluate(full_variable_assignment);
#endif
    }

    for (size_t i = 0; i < domain->m; ++i) {
      write_fr<ppT>(inputs, cc[i]);
    }

    const libff::Fr<ppT> r = libff::Fr<ppT>::random_element();
    write_fr<ppT>(inputs, r);

    fclose(inputs);
    libff::leave_block("Call to stub_write_input_from_pb");

    return 1;
}

int stub_main_verify( const char *prog_name, int argc, const char **argv )
{
    if( argc < 3 )
    {
        std::cerr << "Usage: " << prog_name << " " << argv[0] << " <vk.json> <proof.json>" << std::endl;
        return 1;
    }

    auto vk_json_file = argv[1];
    auto proof_json_file = argv[2];

    // Read verifying key file
    std::stringstream vk_stream;
    std::ifstream vk_input(vk_json_file);
    if( ! vk_input ) {
        std::cerr << "Error: cannot open " << vk_json_file << std::endl;
        return 2;
    }
    vk_stream << vk_input.rdbuf();
    vk_input.close();

    // Read proof file
    std::stringstream proof_stream;
    std::ifstream proof_input(proof_json_file);
    if( ! proof_input ) {
        std::cerr << "Error: cannot open " << proof_json_file << std::endl;
        return 2;
    }
    proof_stream << proof_input.rdbuf();
    proof_input.close();

    // Then verify if proof is correct
    auto vk_str = vk_stream.str();
    auto proof_str = proof_stream.str();
    if( stub_verify( vk_str.c_str(), proof_str.c_str() ) )
    {
        return 0;
    }

    std::cerr << "Error: failed to verify proof!" << std::endl;

    return 1;
}


bool stub_test_proof_verify( const ProtoboardT &in_pb )
{
    auto constraints = in_pb.get_constraint_system();
    auto keypair = libsnark::r1cs_gg_ppzksnark_zok_generator<ppT>(constraints);

    auto primary_input = in_pb.primary_input();
    auto auxiliary_input = in_pb.auxiliary_input();
    auto proof = libsnark::r1cs_gg_ppzksnark_zok_prover<ppT>(keypair.pk, primary_input, auxiliary_input);

    return libsnark::r1cs_gg_ppzksnark_zok_verifier_strong_IC <ppT> (keypair.vk, primary_input, proof);
}


}
// namespace ethsnarks
