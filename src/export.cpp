// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <fstream>
#include <iostream>
#include <cassert>
#include <iomanip>


#include "ethsnarks.hpp"
#include "libff/algebra/curves/mcl_bn128/mcl_bn128_pp.hpp"
#include "utils.hpp"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace ethsnarks {


std::string HexStringFromBigint(LimbT _x){
    mpz_t value;
    ::mpz_init(value);

    _x.to_mpz(value);
    char *value_out_hex = mpz_get_str(nullptr, 16, value);

    std::string str(value_out_hex);

    ::mpz_clear(value);
    ::free(value_out_hex);

    return str;
}

std::string bigintToString(LimbT _x, unsigned int base = 10)
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

std::string toHex(const std::string& _x){
    return HexStringFromBigint(LimbT(_x.c_str()));
}


std::string outputPointG1AffineAsHex(G1T _p)
{
#ifdef CURVE_ALT_BN128
    auto aff = _p;
    aff.to_affine_coordinates();
    return "\"0x" +  HexStringFromBigint(aff.X.as_bigint()) + "\", \"0x" + HexStringFromBigint(aff.Y.as_bigint()) + "\"";
#elif CURVE_MCL_BN128
    auto aff = _p;
    aff.to_affine_coordinates();
    return "\"0x" + toHex(aff.pt.x.getStr()) + "\", \"0x" + toHex(aff.pt.y.getStr()) + "\"";
#endif
}


std::string outputPointG2AffineAsHex(G2T _p)
{
#ifdef CURVE_ALT_BN128
    G2T aff = _p;

    if (aff.Z.c0.as_bigint() != "0" && aff.Z.c1.as_bigint() != "0" ) {
        aff.to_affine_coordinates();
    }
    return "[\"0x" +
            HexStringFromBigint(aff.X.c1.as_bigint()) + "\", \"0x" +
            HexStringFromBigint(aff.X.c0.as_bigint()) + "\"],\n [\"0x" +
            HexStringFromBigint(aff.Y.c1.as_bigint()) + "\", \"0x" +
            HexStringFromBigint(aff.Y.c0.as_bigint()) + "\"]";
#elif CURVE_MCL_BN128
    G2T aff = _p;

    if (aff.pt.z.a.getStr() != "0" && aff.pt.z.b.getStr() != "0" ) {
        aff.to_affine_coordinates();
    }
    return "[\"0x" +
            toHex(aff.pt.x.b.getStr()) + "\", \"0x" +
            toHex(aff.pt.x.a.getStr()) + "\"],\n [\"0x" +
            toHex(aff.pt.y.b.getStr()) + "\", \"0x" +
            toHex(aff.pt.y.a.getStr()) + "\"]";
    return "0x";
#endif
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

void constraint2json(libsnark::linear_combination_light<FieldT> constraints, std::ofstream &fh)
{
    fh << "{";
    uint count = 0;
    for (const libsnark::linear_term_light<FieldT>& lt : constraints.getTerms())
    {
        if (count != 0)
        {
            fh << ",";
        }
        fh << '"' << lt.index << '"' << ": " << '"' << bigintToString(lt.getCoeff().as_bigint(), 10) << '"';
        count++;
    }
    fh << "}";
}

bool r1cs2json(libsnark::protoboard<FieldT>& pb, const std::string& path)
{
    const libsnark::r1cs_constraint_system<FieldT>& constraints = pb.constraint_system;
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
        constraint2json(constraints.constraints[c]->getA(), fh);
        fh << ",";
        constraint2json(constraints.constraints[c]->getB(), fh);
        fh << ",";
        constraint2json(constraints.constraints[c]->getC(), fh);
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

G1T readG1(const json& input)
{
    assert(input.size() == 3);
#ifdef CURVE_ALT_BN128
    auto x = FqT(input[0].get<std::string>().c_str());
    auto y = FqT(input[1].get<std::string>().c_str());
    auto z = FqT(input[2].get<std::string>().c_str());
    auto g1 = G1T(x, y, z);
    return g1;
#elif CURVE_MCL_BN128
    return G1T(input[0].get<std::string>(), input[1].get<std::string>(), input[2].get<std::string>());
#endif
}

G2T readG2(const json& input)
{
    assert(input.size() == 3);
    assert(input[0].size() == 2);
    assert(input[1].size() == 2);
    assert(input[2].size() == 2);
#ifdef CURVE_ALT_BN128
    auto x2 = libff::alt_bn128_Fq2(
        libff::alt_bn128_Fq(input[0][0].get<std::string>().c_str()),
        libff::alt_bn128_Fq(input[0][1].get<std::string>().c_str())
    );
    auto y2 = libff::alt_bn128_Fq2(
        libff::alt_bn128_Fq(input[1][0].get<std::string>().c_str()),
        libff::alt_bn128_Fq(input[1][1].get<std::string>().c_str())
    );
    auto z2 = libff::alt_bn128_Fq2(
        libff::alt_bn128_Fq(input[2][0].get<std::string>().c_str()),
        libff::alt_bn128_Fq(input[2][1].get<std::string>().c_str())
    );
    auto g2 = libff::alt_bn128_G2(x2, y2, z2);
    return g2;
#elif CURVE_MCL_BN128
    return G2T(
        input[0][0].get<std::string>(), input[0][1].get<std::string>(),
        input[1][0].get<std::string>(), input[1][1].get<std::string>(),
        input[2][0].get<std::string>(), input[2][1].get<std::string>()
    );
#endif
}

bool pk_bellman2ethsnarks(const std::string& bellman_pk_file, const std::string& pk_file)
{
    libsnark::r1cs_gg_ppzksnark_zok_proving_key<ethsnarks::ppT> proving_key;

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

    // Write to nozk format immediately
    auto pk_nozk = ProvingKeyT(proving_key);
    writeToFile<ProvingKeyT>(pk_file, pk_nozk);

    return true;
}

libff::mcl_bn128_G1 G1T_alt2mcl(const libff::alt_bn128_G1& alt)
{
    return libff::mcl_bn128_G1(
        bigintToString(alt.X.as_bigint()),
        bigintToString(alt.Y.as_bigint()),
        bigintToString(alt.Z.as_bigint())
    );
}

libff::mcl_bn128_G2 G2T_alt2mcl(const libff::alt_bn128_G2& alt)
{
    return libff::mcl_bn128_G2(
        bigintToString(alt.X.c0.as_bigint()), bigintToString(alt.X.c1.as_bigint()),
        bigintToString(alt.Y.c0.as_bigint()), bigintToString(alt.Y.c1.as_bigint()),
        bigintToString(alt.Z.c0.as_bigint()), bigintToString(alt.Z.c1.as_bigint())
    );
}

bool pk_alt2mcl(const std::string& alt_pk_file, const std::string& mcl_pk_file)
{
    libff::alt_bn128_pp::init_public_params();
    auto proving_key = ethsnarks::loadFromFile<libsnark::r1cs_gg_ppzksnark_zok_proving_key<libff::alt_bn128_pp>>(alt_pk_file);
    typedef libsnark::r1cs_gg_ppzksnark_zok_proving_key<libff::mcl_bn128_pp> MCLProvingKey;
    MCLProvingKey mlc_proving_key;

    /* A */
    for (unsigned int i = 0; i < proving_key.A_query.size(); i++)
    {
        mlc_proving_key.A_query.push_back(G1T_alt2mcl(proving_key.A_query[i]));
    }

    /* B */
    libsnark::knowledge_commitment_vector<libff::G2<libff::mcl_bn128_pp>, libff::G1<libff::mcl_bn128_pp>> B_query;
    B_query.domain_size_ = proving_key.B_query.domain_size_;
    for (unsigned int i = 0; i < proving_key.B_query.values.size(); i++)
    {
        auto g1 = G1T_alt2mcl(proving_key.B_query.values[i].h);
        auto g2 = G2T_alt2mcl(proving_key.B_query.values[i].g);
        B_query.values.emplace_back(libsnark::knowledge_commitment<libff::G2<libff::mcl_bn128_pp>, libff::G1<libff::mcl_bn128_pp>>(g2, g1));
    }
    for (unsigned int i = 0; i < proving_key.B_query.indices.size(); i++)
    {
        B_query.indices.emplace_back(proving_key.B_query.indices[i]);
    }
    mlc_proving_key.B_query = B_query;

    /* L */
    for (unsigned int i = 0; i < proving_key.L_query.size(); i++)
    {
        mlc_proving_key.L_query.push_back(G1T_alt2mcl(proving_key.L_query[i]));
    }

    /* H */
    for (unsigned int i = 0; i < proving_key.H_query.size(); i++)
    {
        mlc_proving_key.H_query.push_back(G1T_alt2mcl(proving_key.H_query[i]));
    }

    /* vk */
    mlc_proving_key.alpha_g1 = G1T_alt2mcl(proving_key.alpha_g1);
    mlc_proving_key.beta_g1 = G1T_alt2mcl(proving_key.beta_g1);
    mlc_proving_key.beta_g2 = G2T_alt2mcl(proving_key.beta_g2);
    mlc_proving_key.delta_g1 = G1T_alt2mcl(proving_key.delta_g1);
    mlc_proving_key.delta_g2 = G2T_alt2mcl(proving_key.delta_g2);

    ethsnarks::writeToFile<MCLProvingKey>(mcl_pk_file, mlc_proving_key);
    return true;
}

bool pk_mcl2nozk(const std::string& mcl_pk_file, const std::string& nozk_pk_file)
{   
    libff::mcl_bn128_pp::init_public_params();
    typedef libsnark::r1cs_gg_ppzksnark_zok_proving_key<libff::mcl_bn128_pp> MCLProvingKey;
    MCLProvingKey pk_zk = ethsnarks::loadFromFile<MCLProvingKey>(mcl_pk_file.c_str());
    using ProvingKeyT_mcl = libsnark::r1cs_gg_ppzksnark_zok_proving_key_nozk<libff::mcl_bn128_pp>; 
    auto pk_nozk = ProvingKeyT_mcl(pk_zk);
    writeToFile<ProvingKeyT_mcl>(nozk_pk_file.c_str(), pk_nozk);
    return true;
}


}
// namespace ethsnarks
