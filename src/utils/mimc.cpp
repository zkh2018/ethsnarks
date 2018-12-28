#include "gadgets/mimc.hpp"
#include "utils.hpp"

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/positional_options.hpp>

namespace po = boost::program_options;

using std::cout;
using std::cerr;
using std::endl;
using std::string;
using ethsnarks::FieldT;


int main( int argc, char **argv )
{
	ethsnarks::ppT::init_public_params();

	po::options_description desc("Options");
	po::positional_options_description p;
	p.add("command", 1);
	p.add("subargs", -1);

	int rounds = 91;
	string seed = "mimc";
	string key_opt("0");
	string cmd = "help";
	std::vector<string> subargs;

	desc.add_options()
		("help", "display usage information")
		("rounds,r", po::value<int>(&rounds)->default_value(91), "number of rounds")
		("seed,s", po::value<decltype(seed)>(&seed)->default_value("mimc"), "seed for round constants")
		("key,k", po::value<decltype(key_opt)>(&key_opt), "initial key")
		("command", po::value<decltype(cmd)>(&cmd), "Sub-command")
		("subargs", po::value<decltype(subargs)>(&subargs), "Arguments for command")
	;

	po::variables_map vm;
	auto parsed = po::command_line_parser(argc, argv)
					 .options(desc).positional(p).allow_unregistered().run();
	po::store(parsed, vm);
	po::notify(vm);

	FieldT key(key_opt.c_str());

	std::vector<FieldT> round_constants;
    ethsnarks::MiMCe7_gadget::constants_fill(round_constants, seed.c_str());

	if( cmd == "constants" ) {
		for( const auto& c_i : round_constants )
		{
			c_i.print();
		}
	}
	else if( cmd == "encrypt" )
	{
		int i = 0;

		for( const auto& w : subargs )
		{
			const FieldT x(w.c_str());
			cout << "key ";
			key.print();

			const auto result = ethsnarks::mimc(round_constants, x, key);
			cout << i << " ";
			result.print();

			key = ethsnarks::mimc(round_constants, key, key);

			i += 1;
		}
	}
	else if( cmd == "hash" )
	{
		FieldT result = key;
		for( const auto& w : subargs )
		{
			const FieldT x(w.c_str());
			result = ethsnarks::mimc(round_constants, x, result);
		}
		result.print();
	}
	else
	{
		cerr << "Usage: " << argv[0] << " <constants|encrypt|hash> [args ...]" << endl << endl;
		cerr << desc << endl;
		return 1;
	}

	return 0;
}