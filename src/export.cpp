// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <fstream>
#include <iostream>
#include <cassert>
#include <iomanip>


#include "ethsnarks.hpp"

namespace ethsnarks {


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


std::string outputPointG1AffineAsHex(G1T _p)
{
        auto aff = _p;
        aff.to_affine_coordinates();
        return "\"0x" +  HexStringFromBigint(aff.X.as_bigint()) + "\", \"0x" + HexStringFromBigint(aff.Y.as_bigint()) + "\""; 
}


std::string outputPointG2AffineAsHex(G2T _p)
{
        G2T aff = _p;

        if (aff.Z.c0.as_bigint() != "0" && aff.Z.c1.as_bigint() != "0" ) {
            aff.to_affine_coordinates();
        }
        return "[\"0x" +
                HexStringFromBigint(aff.X.c1.as_bigint()) + "\", \"0x" +
                HexStringFromBigint(aff.X.c0.as_bigint()) + "\"],\n [\"0x" + 
                HexStringFromBigint(aff.Y.c1.as_bigint()) + "\", \"0x" +
                HexStringFromBigint(aff.Y.c0.as_bigint()) + "\"]"; 
}


std::string proof_to_json(ProofT &proof, PrimaryInputT &input) {
    std::stringstream ss;

    ss << "{\n";
    ss << " \"A\" :[" << outputPointG1AffineAsHex(proof.g_A) << "],\n";
    ss << " \"B\"  :[" << outputPointG2AffineAsHex(proof.g_B)<< "],\n";
    ss << " \"C\"  :[" << outputPointG1AffineAsHex(proof.g_C)<< "],\n";
    ss << " \"input\" :" << "["; //1 should always be the first variavle passed

    for (size_t i = 0; i < input.size(); ++i)
    {   
        ss << "\"0x" << HexStringFromBigint(input[i].as_bigint()) << "\""; 
        if ( i < input.size() - 1 ) { 
            ss<< ", ";
        }
    }
    ss << "]\n";
    ss << "}";

    ss.rdbuf()->pubseekpos(0, std::ios_base::out);

    return(ss.str());
}


std::string vk2json(VerificationKeyT &vk )
{
    std::stringstream ss;
    unsigned icLength = vk.gamma_ABC_g1.rest.indices.size() + 1;
    
    ss << "{\n";
    ss << " \"alpha\" :[" << outputPointG1AffineAsHex(vk.alpha_g1) << "],\n";
    ss << " \"beta\"  :[" << outputPointG2AffineAsHex(vk.beta_g2) << "],\n";
    ss << " \"gamma\" :[" << outputPointG2AffineAsHex(vk.gamma_g2) << "],\n";
    ss << " \"delta\" :[" << outputPointG2AffineAsHex(vk.delta_g2)<< "],\n";

    ss <<  "\"gammaABC\" :[[" << outputPointG1AffineAsHex(vk.gamma_ABC_g1.first) << "]";
    
    for (size_t i = 1; i < icLength; ++i)
    {   
        auto vkICi = outputPointG1AffineAsHex(vk.gamma_ABC_g1.rest.values[i - 1]);
        ss << ",[" <<  vkICi << "]";
    } 
    ss << "]";
    ss << "}";
    return ss.str();
}


void vk2json_file(VerificationKeyT &vk, const std::string &path )
{
    std::ofstream fh;
    fh.open(path, std::ios::binary);
    fh << vk2json(vk);
    fh.flush();
    fh.close();
}

std::string bigintToString(libff::bigint<libff::alt_bn128_r_limbs> _x, unsigned int base)
{
    mpz_t value;
    ::mpz_init(value);

    _x.to_mpz(value);
    char *value_out_hex = mpz_get_str(nullptr, base, value);

    std::string str(value_out_hex);

    ::mpz_clear(value);
    ::free(value_out_hex);

    return str;
}

void constraint2json(linear_combination<FieldT> constraints, std::ofstream &fh)
{
    fh << "{";
    uint count = 0;
    // if (!(constraints.terms.size() == 1 && lt.index == 0 && lt.coeff == 0))
    for (const linear_term<FieldT>& lt : constraints.terms)
    {
        if (count != 0)
        {
            fh << ",";
        }
        fh << '"' << lt.index << '"' << ": " << '"' << bigintToString(lt.coeff.as_bigint(), 10) << '"';
        count++;
    }
    fh << "}";
}

bool r1cs2json(libsnark::protoboard<FieldT>& pb, const std::string& path)
{
    libsnark::r1cs_constraint_system<FieldT> constraints = pb.get_constraint_system();
    std::ofstream fh(path);
    fh << "{\n";
    fh << " \"nPubInputs\": " << constraints.primary_input_size << ",\n";
    fh << " \"nOutputs\": " << 0 << ",\n";
    fh << " \"nVars\": " << pb.num_variables() + 1 << ",\n";
    fh << " \"nConstraints\": " << pb.num_constraints() << ",\n";
    fh << " \"constraints\": [\n";
    for (size_t c = 0; c < constraints.num_constraints(); ++c)
    {
        fh << "  [";
        constraint2json(constraints.constraints[c].a, fh);
        fh << ",";
        constraint2json(constraints.constraints[c].b, fh);
        fh << ",";
        constraint2json(constraints.constraints[c].c, fh);
        if (c == constraints.num_constraints() - 1)
        {
            fh << "]\n";
        }
        else
        {
            fh << "],\n";
        }
    }
    fh << " ]\n}";
    fh.close();
    return true;
}

bool witness2json(libsnark::protoboard<FieldT>& pb, const std::string& path)
{
    std::stringstream ss;
    std::ofstream fh(path);
    fh << "[\n";
    for (size_t i = 0; i <= pb.num_variables(); i++)
    {
        fh << " \"" << bigintToString(pb.val(i).as_bigint(), 10) << '"';
        if (i < pb.num_variables())
        {
            fh << ",\n";
        }
    }
    fh << "\n]";
    fh.close();
    return true;
}

bool pk_bellman2ethsnarks(const ProtoboardT& pb, const std::string& bellman_pk_file, const std::string& pk_file)
{
    ethsnarks::ProvingKeyT proving_key;
    proving_key.constraint_system = pb.get_constraint_system();

    // Read the bellman pk JSON file
    std::ifstream file(bellman_pk_file);
    if (!file.is_open())
    {
        std::cerr << "Cannot open input file: " << bellman_pk_file << std::endl;
    }
    json input;
    file >> input;
    file.close();

    /* A */
    for (unsigned int i = 0; i < input["A"].size(); i++)
    {
        proving_key.A_query.push_back(readG1(input["A"][i]));
    }

    /* B */
    libsnark::knowledge_commitment_vector<libff::G2<ppT>, libff::G1<ppT>> B_query;
    B_query.domain_size_ = proving_key.A_query.size();
    B_query.values.reserve(B_query.domain_size_);
    B_query.indices.reserve(B_query.domain_size_);
    for (unsigned int i = 0; i < input["B1"].size(); i++)
    {
        auto g1 = readG1(input["B1"][i]);
        auto g2 = readG2(input["B2"][i]);
        if (!g1.is_zero())
        {
            B_query.values.emplace_back(libsnark::knowledge_commitment<libff::G2<ppT>, libff::G1<ppT>>(g2, g1));
            B_query.indices.emplace_back(i);
        }
    }
    proving_key.B_query = B_query;

    /* L */
    for (unsigned int i = 2; i < input["C"].size(); i++)
    {
        proving_key.L_query.push_back(readG1(input["C"][i]));
    }

    /* H */
    for (unsigned int i = 0; i < input["hExps"].size(); i++)
    {
        proving_key.H_query.push_back(readG1(input["hExps"][i]));
    }

    /* vk */
    proving_key.alpha_g1 = readG1(input["vk_alfa_1"]);
    proving_key.beta_g1 = readG1(input["vk_beta_1"]);
    proving_key.beta_g2 = readG2(input["vk_beta_2"]);
    proving_key.delta_g1 = readG1(input["vk_delta_1"]);
    proving_key.delta_g2 = readG2(input["vk_delta_2"]);

    writeToFile<ethsnarks::ProvingKeyT>(pk_file, proving_key);

    return true;
}

}
// namespace ethsnarks
