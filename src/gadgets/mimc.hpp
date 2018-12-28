#ifndef ETHSNARKS_MIMC_HPP_
#define ETHSNARKS_MIMC_HPP_

#include "ethsnarks.hpp"
#include "utils.hpp"
#include <openssl/sha.h>


namespace ethsnarks {


/*
* First round
*
*            x    k
*            |    |
*            |    |
*           (+)---|     X[0] = x + k
*            |    |
*          (n^7)  |     Y[0] = X[0]^7
*            |    |
******************************************
* Second round
*            |    |
*           (+)---|     X[1] = Z[0] + k  
*            |    |
*    C[0] --(+)   |     Y[1] = X[1] + C[0]
*            |    |
*          (n^7)  |     W[1] = Y[1]^7
*            |    |
******************************************
* i'th round
*            |    |
*           (+)---|     X[i] = Z[i-1] + k  
*            |    |
*    C[i] --(+)   |     Y[i] = X[i] + C[i]
*            |    |
*          (n^7)  |     W[i] = Y[i]^7
*            |    |
******************************************
* Last round
*            |    |
*           (+)---'     X[i] = X[i-1] + k
*            |
*          result
*/



class MiMCe7_round : public GadgetT {
protected:
    const VariableT& x;
    const VariableT& k;
    const FieldT& C;
    const VariableT a;
    const VariableT b;
    const VariableT c;
    const VariableT d;

public:
    MiMCe7_round(
        ProtoboardT& pb,
        const VariableT& in_x,
        const VariableT& in_k,
        const FieldT& in_C,
        const std::string &annotation_prefix
    ) :
        GadgetT(pb, annotation_prefix),
        x(in_x), k(in_k), C(in_C),
        a(make_variable(pb, FMT(annotation_prefix, ".a"))),
        b(make_variable(pb, FMT(annotation_prefix, ".b"))),
        c(make_variable(pb, FMT(annotation_prefix, ".c"))),
        d(make_variable(pb, FMT(annotation_prefix, ".d")))
    { }

    const VariableT& result()
    {
        return d;
    }

    void generate_constraints()
    {
        auto t = x + k + C;       
        this->pb.add_r1cs_constraint(ConstraintT(t, t, a), ".a = t*t"); // x^2
        this->pb.add_r1cs_constraint(ConstraintT(a, a, b), ".b = a*a"); // x^4
        this->pb.add_r1cs_constraint(ConstraintT(a, b, c), ".c = a*b"); // x^6
        this->pb.add_r1cs_constraint(ConstraintT(t, c, d), ".d = c*t"); // x^7
    }

    void generate_witness()
    {
        const auto t = this->pb.val(x) + this->pb.val(k) + C;

        const auto val_a = t * t;
        this->pb.val(a) = val_a;

        const auto val_b = val_a * val_a;
        this->pb.val(b) = val_b;

        const auto val_c = val_a * val_b;
        this->pb.val(c) = val_c;

        this->pb.val(d) = val_c * t;
    }
};


class MiMCe7_gadget : public GadgetT
{
protected:
    std::vector<MiMCe7_round> m_rounds;
    const VariableT k;

public:
    MiMCe7_gadget(
        ProtoboardT& pb,
        const VariableT& x,
        const VariableT& in_k,
        const std::vector<FieldT>& in_round_constants,
        const std::string& annotation_prefix
    ) :
        GadgetT(pb, annotation_prefix),
        k(in_k)
    {
        m_rounds.reserve(in_round_constants.size());

        for( size_t i = 0; i < in_round_constants.size(); i++ )
        {
            const auto round_x = (i == 0 ? x : m_rounds.back().result() );

            m_rounds.emplace_back(pb, round_x, in_k, in_round_constants[i], FMT(annotation_prefix, ".round[%d]", i));
        }
    }

    const libsnark::linear_combination<FieldT> result ()
    {
        return m_rounds.back().result() + k;
    }

    const FieldT result_value() {
        return pb.val(m_rounds.back().result()) + pb.val(k);
    }

    void generate_constraints()
    {
        for( auto& gadget : m_rounds )
        {
            gadget.generate_constraints();
        }
    }

    void generate_witness()
    {
        for( auto& gadget : m_rounds )
        {
            gadget.generate_witness();
        }
    }

    static void constants_fill( std::vector<FieldT>& round_constants, const char* seed = "mimc", int round_count = 91 )
    {
        round_constants.reserve(round_count);

        libff::bigint<FieldT::num_limbs> item;
        assert( sizeof(item.data) == SHA256_DIGEST_LENGTH );

        unsigned char* output_digest = (unsigned char*)item.data;

        for( int i = 0; i < round_count; i++ )
        {
            SHA256_CTX ctx;
            SHA256_Init(&ctx);
            if( i == 0 ) {
                SHA256_Update(&ctx, seed, strlen(seed));
            }
            else {
                SHA256_Update(&ctx, output_digest, SHA256_DIGEST_LENGTH);
            }
            SHA256_Final(output_digest, &ctx);
            
            round_constants.emplace_back( item );
        }
    }
};


// namespace ethsnarks
}

// ETHSNARKS_MIMC_HPP_
#endif
