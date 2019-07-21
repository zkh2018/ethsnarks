#include "websnark.hpp"


namespace ethsnarks {


static inline void websnark_write_u32( std::ostream &out, uint32_t val)
{
    out.write((const char *)&val, sizeof(val));
}


/** Write a 32bit unsigned integer to a specific position within the file
*   then return to the current position */
static void websnark_write_u32_at( std::ofstream &out, size_t position, uint32_t val )
{
    long pos_before = out.tellp();
    assert( pos_before != -1 );

    out.seekp(position);
    websnark_write_u32(out, val);
    out.seekp(pos_before);
}


/** Write the current position to an absolute position within the file
*   Then return to the current position after writing */
static inline void websnark_write_pointer_at( std::ofstream &out, size_t position )
{
    websnark_write_u32_at(out, position, out.tellp());
}


static inline size_t websnark_write_u32_later( std::ofstream &out )
{
    long position = out.tellp();
    assert( position != -1 );

    websnark_write_u32(out, 0);
    return position;
}


template<typename T>
static void websnark_write( std::ostream &out, const T &value )
{
    const auto mont_repr = value.mont_repr;
    out.write((char*)mont_repr.data, sizeof(mont_repr.data[0]) * decltype(mont_repr)::N);
}


static inline void websnark_write_Fq( std::ostream &out, const FqT &value )
{
    websnark_write<decltype(value)>(out, value);
}


static inline void websnark_write_Fr( std::ostream &out, const FieldT &value )
{
    websnark_write<decltype(value)>(out, value);
}


static void websnark_write_g1( std::ostream &out, const G1T &point )
{
    G1T affine_point(point);
    affine_point.to_affine_coordinates();
    websnark_write_Fq(out, point.X);
    websnark_write_Fq(out, point.Y);
}


static void websnark_write_g2( std::ostream &out, const G2T &point )
{
    G2T affine_point(point);
    affine_point.to_affine_coordinates();
    websnark_write_Fq(out, point.X.c0);
    websnark_write_Fq(out, point.X.c1);
    websnark_write_Fq(out, point.Y.c0);
    websnark_write_Fq(out, point.Y.c1);
}


static void websnark_write_poly( std::ostream &out, const std::map<size_t,FieldT> &poly )
{
    // Output numbers of terms in the polynomial
    websnark_write_u32( out, poly.size() );

    // Then output the variable index, followed by the coefficient
    for( const auto &pair : poly )
    {
        websnark_write_u32( out, pair.first );
        websnark_write_Fr( out, pair.second );
    }
}


static inline size_t websnark_polysize( size_t field_size, const std::map<size_t,FieldT> &poly )
{
    return ((field_size + sizeof(uint32_t)) * poly.size()) + sizeof(uint32_t);
}


// From: https://graphics.stanford.edu/~seander/bithacks.html#IntegerLog
// Find the log base 2 of an N-bit integer in `O(lg(N))` operations
static uint32_t websnark_log2( uint32_t v )
{
    const unsigned int b[] = {0x2, 0xC, 0xF0, 0xFF00, 0xFFFF0000};
    const unsigned int S[] = {1, 2, 4, 8, 16};

    unsigned int r = 0; // result of log2(v) will go here
    for (int i = 4; i >= 0; i--) // unroll for speed...
    {
        if (v & b[i])
        {
            v >>= S[i];
            r |= S[i];
        }
    }

    return r;
}


static uint32_t websnark_domain_size( const ProvingKeyT &provingKey )
{
    const auto &cs = provingKey.constraint_system;

    // From: https://github.com/iden3/snarkjs/blob/448dc345adf6854455a6278fd5797a05dc535956/src/setup_groth.js#L49
    const auto domainBits = websnark_log2( cs.num_constraints() + cs.num_inputs() ) + 1;
    return (1 << domainBits);
}


static size_t websnark_length( const ProvingKeyT &provingKey, const libsnark::qap_instance<FieldT> &qap )
{   
    const auto &cs = provingKey.constraint_system;
    const auto num_vars = qap.num_variables();
    const uint32_t domainSize = websnark_domain_size(provingKey);

    const size_t Fq_size_bytes = (FqT::size_in_bits() + (8 - (FqT::size_in_bits() % 8))) / 8;
    const size_t Fr_size_bytes = (FieldT::size_in_bits() + (8 - (FieldT::size_in_bits() % 8))) / 8;
    const size_t g1_size = (Fq_size_bytes*2);
    const size_t g2_size = (Fq_size_bytes*4);

    std::cerr << "websnark_length: nvars " << num_vars << std::endl;
    std::cerr << "websnark_length: websnark domainSize " << domainSize << std::endl;
    std::cerr << "websnark_length: g1_size " << g1_size << std::endl;
    std::cerr << "websnark_length: g2_size " << g2_size << std::endl;
    std::cerr << "websnark_length: Fq_size_bytes " << Fq_size_bytes << std::endl;
    std::cerr << "websnark_length: Fr_size_bytes " << Fr_size_bytes << std::endl;

    size_t sum = 0;

    // Header size
    sum += 3 * sizeof(uint32_t);

    // Offsets to fields
    sum += 7 * sizeof(uint32_t);    

    // alpha (G1), beta (G1), delta (G1)
    sum += 3 * g1_size;

    // beta (G2), delta (G2)
    sum += 2 * g2_size;

    std::cerr << "websnark_length: after fixed-length portion: " << sum << std::endl;

    // A polynomials
    for( size_t i = 0; i < num_vars; i++ ) {
        sum += websnark_polysize(Fr_size_bytes, qap.A_in_Lagrange_basis[i]);
    }
    std::cerr << "websnark_length: after A poly: " << sum << std::endl;

    // B polynomials
    for( size_t i = 0; i < num_vars; i++ ) {    
        sum += websnark_polysize(Fr_size_bytes, qap.B_in_Lagrange_basis[i]);
    }
    std::cerr << "websnark_length: after B poly: " << sum << std::endl;

    sum += num_vars * g1_size;  // A points
    std::cerr << "websnark_length: after A points: " << sum << std::endl;

    sum += num_vars * g1_size;  // B points (G1)
    std::cerr << "websnark_length: after B (G1) points: " << sum << std::endl;

    sum += num_vars * g2_size;  // B points (G2)
    std::cerr << "websnark_length: after B (G2) points: " << sum << std::endl;

    sum += (num_vars - cs.num_inputs() - 1) * g1_size;  // L points (G1)
    std::cerr << "websnark_length: after C (G1) points: " << sum << std::endl;

    sum += domainSize * g1_size; // H points (G1)
    std::cerr << "websnark_length: after H (G1) points: " << sum << std::endl;

    return sum;
}


void websnark_write( std::ofstream &out, const ProvingKeyT &provingKey )
{
    const auto &cs = provingKey.constraint_system;
    const auto &qap = libsnark::r1cs_to_qap_instance_map<FieldT>(cs);
    const auto expected_length = websnark_length(provingKey, qap);

    const uint32_t domain_size = websnark_domain_size(provingKey);


    std::cerr << "websnark_write: A size: " << provingKey.A_query.size() << std::endl;
    std::cerr << "websnark_write: B size: " << provingKey.B_query.size() << std::endl;
    std::cerr << "websnark_write: B domain size: " << provingKey.B_query.domain_size() << std::endl;
    std::cerr << "websnark_write: L size: " << provingKey.L_query.size() << std::endl;
    std::cerr << "websnark_write: H size: " << provingKey.H_query.size() << std::endl;
    std::cerr << "websnark_write: QAP degree: " << qap.degree() << std::endl;
    std::cerr << "websnark_write: QAP vars: " << qap.num_variables() << std::endl;
    std::cerr << "websnark_write: QAP inputs: " << qap.num_inputs() << std::endl;

    // Write Header
    websnark_write_u32(out, cs.num_variables() );   // number of signals
    websnark_write_u32(out, cs.num_inputs() );      // number of public inputs
    websnark_write_u32(out, domain_size );

    // Pointers to fields (absolute position within file)
    const auto pos_pols_A = websnark_write_u32_later(out);
    const auto pos_pols_B = websnark_write_u32_later(out);
    const auto pos_points_A = websnark_write_u32_later(out);
    const auto pos_points_B1 = websnark_write_u32_later(out);
    const auto pos_points_B2 = websnark_write_u32_later(out);
    const auto pos_points_C = websnark_write_u32_later(out);
    const auto pos_points_H = websnark_write_u32_later(out);

    // Individual points (alpha, beta, delta)
    websnark_write_g1(out, provingKey.alpha_g1);
    websnark_write_g1(out, provingKey.beta_g1);
    websnark_write_g1(out, provingKey.delta_g1);
    websnark_write_g2(out, provingKey.beta_g2);
    websnark_write_g2(out, provingKey.delta_g2);
    std::cerr << "websnark_write: after fixed-length portion: " << out.tellp() << std::endl;

    // write A polynomials
    websnark_write_pointer_at(out, pos_pols_A);
    for( const auto &poly : qap.A_in_Lagrange_basis ) {
        websnark_write_poly(out, poly);
    }
    std::cerr << "websnark_write: A poly length: " << qap.A_in_Lagrange_basis.size() << std::endl;
    std::cerr << "websnark_write: after A poly: " << out.tellp() << std::endl;

    // Write B polynomials
    websnark_write_pointer_at(out, pos_pols_B);
    std::cerr << "websnark_write: B_in_Lagrange_basis len " << qap.B_in_Lagrange_basis.size() << std::endl;
    for( const auto &poly : qap.B_in_Lagrange_basis ) {
        websnark_write_poly(out, poly);
    }
    std::cerr << "websnark_write: B poly length: " << qap.B_in_Lagrange_basis.size() << std::endl;
    std::cerr << "websnark_write: after B poly: " << out.tellp() << std::endl;

    // Write A points (G1), length: number of signals
    websnark_write_pointer_at(out, pos_points_A);
    for( const auto &point : provingKey.A_query ) {
        websnark_write_g1(out, point);
    }
    std::cerr << "websnark_write: number of A points " << provingKey.A_query.size() << std::endl;
    std::cerr << "websnark_write: after A points: " << out.tellp() << std::endl;

    // write B points (G1), length: number of signals
    std::cerr << "websnark_write: B_query.domain_size() " << provingKey.B_query.domain_size() << std::endl;
    websnark_write_pointer_at(out, pos_points_B1);
    for( unsigned i = 0; i < cs.num_variables(); i++ ) {
        const auto kc = provingKey.B_query[i];
        websnark_write_g1(out, kc.h);
    }
    std::cerr << "websnark_write: number of B (G1) points " << provingKey.B_query.size() << std::endl;
    std::cerr << "websnark_write: after B (G1) points: " << out.tellp() << std::endl;
    assert( provingKey.B_query.size() == cs.num_variables() );

    // write B points (G2), length: number of signals
    websnark_write_pointer_at(out, pos_points_B2);
    for( unsigned i = 0; i < cs.num_variables(); i++ ) {
        const auto kc = provingKey.B_query[i];
        websnark_write_g2(out, kc.g);
    }
    std::cerr << "websnark_write: after B (G2) points: " << out.tellp() << std::endl;
    assert( provingKey.B_query.size() == cs.num_variables() );

    // write C points, length: (number of signals - number of inputs - 1)
    websnark_write_pointer_at(out, pos_points_C);
    for( const auto &point : provingKey.L_query ) {
        websnark_write_g1(out, point);
    }
    std::cerr << "websnark_write: after C (G1) points: " << out.tellp() << std::endl;
    std::cerr << "websnark_write: L_query size = " << provingKey.L_query.size() << std::endl;
    std::cerr << "websnark_write: expected L_query size = " << (qap.num_variables() - qap.num_inputs() - 1) << std::endl;
    //assert( provingKey.L_query.size() == (cs.num_variables() - cs.num_inputs() - 1) );

    // write H points, length: domain_size
    
    websnark_write_pointer_at(out, pos_points_H);
    for( const auto &point : provingKey.H_query ) {
        websnark_write_g1(out, point);
    }    
    std::cerr << "websnark_write: after H (G1) points: " << out.tellp() << std::endl;
    std::cerr << "websnark_write: H_query size: " << provingKey.H_query.size() << std::endl;
    std::cerr << "websnark_write: expected H_query size: " << domain_size << std::endl;
    assert( provingKey.H_query.size() == domain_size );

    std::cerr << "websnark_write: expected_length " << expected_length << std::endl;
    std::cerr << "websnark_write: actual length " << out.tellp() << std::endl;
    //assert( out.tellp() == expected_length );
}


bool websnark_write( const std::string &filename, const ProvingKeyT &provingKey )
{
    std::ofstream ofs (filename, std::ofstream::binary);
    if( ! ofs.is_open() ) {
        return false;
    }   

    websnark_write(ofs, provingKey);
    ofs.close();
    return true;
}


void websnark_write(
    std::ofstream &out,
    const libsnark::r1cs_primary_input<FieldT> &primary_input,
    const libsnark::r1cs_auxiliary_input<FieldT> &auxiliary_input )
{
    for( const auto &f : primary_input ) {
        websnark_write_Fr(out, f);
    }

    for( const auto &f : auxiliary_input ) {
        websnark_write_Fr(out, f);
    }
}


bool websnark_write(
    const std::string &filename,
    const libsnark::r1cs_primary_input<FieldT> &primary_input,
    const libsnark::r1cs_auxiliary_input<FieldT> &auxiliary_input )
{
    std::ofstream ofs (filename, std::ofstream::binary);
    if( ! ofs.is_open() ) {
        return false;
    }   

    websnark_write(ofs, primary_input, auxiliary_input);
    ofs.close();
    return true;
}


// namespace ethsnarks
}
