// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <libsnark/gadgetlib1/protoboard.hpp>

#include <sstream>  // stringstream

#include "utils.hpp"
#include "import.hpp"
#include "export.hpp"

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


ethsnarks::ProvingKeyT load_proving_key( const char *pk_file )
{
    return ethsnarks::loadFromFile<ethsnarks::ProvingKeyT>(pk_file);
}


std::string prove(ProverContextT& context, ProtoboardT& pb)
{
    auto primary_input = pb.primary_input();
    auto proof = libsnark::r1cs_gg_ppzksnark_zok_prover<ethsnarks::ppT>(context, pb.values);
    return ethsnarks::proof_to_json(proof, primary_input);
}

static unsigned int roundUpToNearestPowerOf2(unsigned int v)
{
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v++;
    return v;
}

const std::shared_ptr<libfqfft::evaluation_domain<FieldT>> get_domain ( ProtoboardT& pb, const ethsnarks::ProvingKeyT& proving_key, const libsnark::Config& config )
{
    const auto& cs = pb.constraint_system;
    std::shared_ptr<libfqfft::evaluation_domain<FieldT>> result;
    unsigned int domain_size = roundUpToNearestPowerOf2(cs.num_constraints() + cs.num_inputs() + 1);
    if (config.fft.compare("basic_radix2") == 0)
    {
        result.reset(new libfqfft::basic_radix2_domain<FieldT>(domain_size));
    }
    else
    {
        result.reset(new libfqfft::recursive_domain<FieldT>(domain_size, config));
    }
    return result;
}

int stub_genkeys_from_pb( ProtoboardT& pb, const char *pk_file, const char *vk_file )
{
    const auto& constraints = pb.constraint_system;
    auto keypair = libsnark::r1cs_gg_ppzksnark_zok_generator<ppT>(constraints);
    vk2json_file(keypair.vk, vk_file);

    auto pk = ProvingKeyT(keypair.pk);
    writeToFile<ProvingKeyT>(pk_file, pk);

    return 0;
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
    auto& constraints = in_pb.constraint_system;
    auto keypair = libsnark::r1cs_gg_ppzksnark_zok_generator<ppT>(constraints);

    auto pk = ProvingKeyT(keypair.pk);
    ProverContextT context(pk);
    // context.provingKey = keypair.pk;
    context.config = libsnark::Config();

    auto proof = libsnark::r1cs_gg_ppzksnark_zok_prover<ppT>(context, in_pb.values);

    return libsnark::r1cs_gg_ppzksnark_zok_verifier_strong_IC <ppT> (keypair.vk, in_pb.primary_input(), proof);
}


}
// namespace ethsnarks
