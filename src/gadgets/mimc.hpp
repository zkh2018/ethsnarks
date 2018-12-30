#ifndef ETHSNARKS_MIMC_HPP_
#define ETHSNARKS_MIMC_HPP_

#include "ethsnarks.hpp"
#include "utils.hpp"
#include "gadgets/onewayfunction.hpp"
#include "sha3.h"
#include <mutex>


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
    const VariableT x;
    const VariableT k;
    const FieldT& C;
    const bool add_k_to_result;
    const VariableT a;
    const VariableT b;
    const VariableT c;
    const VariableT d;

public:
    MiMCe7_round(
        ProtoboardT& pb,
        const VariableT in_x,
        const VariableT in_k,
        const FieldT& in_C,
        const bool in_add_k_to_result,
        const std::string &annotation_prefix
    ) :
        GadgetT(pb, annotation_prefix),
        x(in_x), k(in_k), C(in_C),
        add_k_to_result(in_add_k_to_result),
        a(make_variable(pb, FMT(annotation_prefix, ".a"))),
        b(make_variable(pb, FMT(annotation_prefix, ".b"))),
        c(make_variable(pb, FMT(annotation_prefix, ".c"))),
        d(make_variable(pb, FMT(annotation_prefix, ".d")))
    { }

    const VariableT result() const
    {
        return d;
    }

    void generate_r1cs_constraints()
    {
        auto t = x + k + C;       
        this->pb.add_r1cs_constraint(ConstraintT(t, t, a), ".a = t*t"); // x^2
        this->pb.add_r1cs_constraint(ConstraintT(a, a, b), ".b = a*a"); // x^4
        this->pb.add_r1cs_constraint(ConstraintT(a, b, c), ".c = a*b"); // x^6

        if( add_k_to_result )
        {
            this->pb.add_r1cs_constraint(ConstraintT(t, c, d - k), ".d = (c*t) + k"); // x^7
        }
        else {
            this->pb.add_r1cs_constraint(ConstraintT(t, c, d), ".d = c*t"); // x^7
        }
    }

    void generate_r1cs_witness() const
    {
        const auto val_k = this->pb.val(k);
        const auto t = this->pb.val(x) + val_k + C;

        const auto val_a = t * t;
        this->pb.val(a) = val_a;

        const auto val_b = val_a * val_a;
        this->pb.val(b) = val_b;

        const auto val_c = val_a * val_b;
        this->pb.val(c) = val_c;

        const FieldT result = (val_c * t) + (add_k_to_result ? val_k : FieldT::zero());
        this->pb.val(d) = result;
    }
};


class MiMCe7_gadget : public GadgetT
{
protected:
    std::vector<MiMCe7_round> m_rounds;
    const VariableT k;

    void _setup_gadgets(
        const VariableT in_x,
        const VariableT in_k,
        const std::vector<FieldT>& in_round_constants)
    {
        m_rounds.reserve(in_round_constants.size());

        for( size_t i = 0; i < in_round_constants.size(); i++ )
        {
            const auto round_x = (i == 0 ? in_x : m_rounds.back().result() );

            bool is_last = (i == (in_round_constants.size() - 1));

            m_rounds.emplace_back(this->pb, round_x, in_k, in_round_constants[i], is_last, FMT(annotation_prefix, ".round[%d]", i));
        }   
    }

public:
    MiMCe7_gadget(
        ProtoboardT& pb,
        const VariableT in_x,
        const VariableT in_k,
        const std::vector<FieldT>& in_round_constants,
        const std::string& annotation_prefix
    ) :
        GadgetT(pb, annotation_prefix),
        k(in_k)
    {
        _setup_gadgets(in_x, in_k, in_round_constants);
    }

    MiMCe7_gadget(
        ProtoboardT& pb,
        const VariableT in_x,
        const VariableT in_k,
        const std::string& annotation_prefix
    ) :
        GadgetT(pb, annotation_prefix),
        k(in_k)
    {
        _setup_gadgets(in_x, in_k, static_constants());
    }

    const VariableT result () const
    {
        return m_rounds.back().result();
    }

    void generate_r1cs_constraints()
    {
        for( auto& gadget : m_rounds )
        {
            gadget.generate_r1cs_constraints();
        }
    }

    void generate_r1cs_witness() const
    {
        for( auto& gadget : m_rounds )
        {
            gadget.generate_r1cs_witness();
        }
    }

    static const std::vector<FieldT>& static_constants ()
    {
        static bool filled = false;
        static std::vector<FieldT> round_constants;
        static std::mutex fill_lock;

        if( ! filled )
        {
            fill_lock.lock();
            constants_fill(round_constants);
            filled = true;
            fill_lock.unlock();
        }

        return round_constants;
    }

    static void constants_fill( std::vector<FieldT>& round_constants, const char* seed = "mimc", int round_count = 91 )
    {
        // XXX: replace '32' with digest size in bytes
        const size_t DIGEST_SIZE_BYTES = 32;

        round_constants.reserve(round_count);

        unsigned char output_digest[DIGEST_SIZE_BYTES];

        for( int i = 0; i < round_count; i++ )
        {
            sha3_context ctx;
            sha3_Init256(&ctx);
            if( i == 0 ) {
                sha3_Update(&ctx, seed, strlen(seed));
            }
            else {
                sha3_Update(&ctx, output_digest, DIGEST_SIZE_BYTES);
            }
            auto result = sha3_Finalize(&ctx);
            memcpy(output_digest, result, DIGEST_SIZE_BYTES);

            // Import bytes as big-endian
            mpz_t result_as_num;
            mpz_init(result_as_num);
            mpz_import(result_as_num,       // rop
                       DIGEST_SIZE_BYTES,   // count
                       1,                   // order
                       1,                   // size
                       0,                   // endian
                       0,                   // nails
                       output_digest);      // op

            // Convert to bigint
            libff::bigint<FieldT::num_limbs> item(result_as_num);
            assert( sizeof(item.data) == DIGEST_SIZE_BYTES );
            mpz_clear(result_as_num);

            /*
            // Debug constants generation
            for( auto x : output_digest ) {
                printf("%02X", x);
            }
            printf(" ");
            item.print();
            */
            
            round_constants.emplace_back( item );
        }
    }

    static const std::vector<FieldT> constants( const char* seed = "mimc", int round_count = 91 )
    {
        std::vector<FieldT> round_constants;

        constants_fill(round_constants, seed, round_count);

        return round_constants;
    }
};


class MiMCe7_hash_MiyaguchiPreneel_gadget : public MiyaguchiPreneel_OWF<MiMCe7_gadget>
{
public:
    using MiyaguchiPreneel_OWF<MiMCe7_gadget>::MiyaguchiPreneel_OWF;
};


class MiMCe7_hash_MerkleDamgard_gadget : public MerkleDamgard_OWF<MiMCe7_gadget>
{
public:
    using MerkleDamgard_OWF<MiMCe7_gadget>::MerkleDamgard_OWF;
};


// generic aliases for 'MiMC', masks specific implementation
using MiMC_hash_gadget = MiMCe7_hash_MiyaguchiPreneel_gadget;
using MiMC_gadget = MiMCe7_gadget;


const FieldT mimc( const std::vector<FieldT>& round_constants, const FieldT& x, const FieldT& k )
{
    ProtoboardT pb;

    VariableT var_x = make_variable(pb, x, "x");
    VariableT var_k = make_variable(pb, k, "k");
    pb.set_input_sizes(2);

    MiMCe7_gadget the_gadget(pb, var_x, var_k, round_constants, "the_gadget");
    the_gadget.generate_r1cs_witness();
    the_gadget.generate_r1cs_constraints();

    return pb.val(the_gadget.result());
}


const FieldT mimc( const FieldT& x, const FieldT& k )
{
    return mimc(MiMCe7_gadget::static_constants(), x, k);
}


// namespace ethsnarks
}

// ETHSNARKS_MIMC_HPP_
#endif
