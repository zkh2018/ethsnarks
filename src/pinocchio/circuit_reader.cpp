/*
MIT License

Copyright (c) 2015 Ahmed Kosba

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "circuit_reader.hpp"
#include "utils.hpp"
#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"

#include <fstream>


using std::istringstream;
using std::ifstream;
using std::string;
using std::cout;
using std::endl;
using std::make_shared;

using libff::enter_block;
using libff::leave_block;

using libsnark::generate_boolean_r1cs_constraint;

using ethsnarks::make_variable;
using ethsnarks::ConstraintT;


void readIds(char* str, std::vector<unsigned int>& vec){
	istringstream iss_i(str, istringstream::in);
	unsigned int id;
	while (iss_i >> id) {
		vec.push_back(id);
	}
}


FieldT readFieldElementFromHex(char* inputStr){
	char constStrDecimal[150];
	mpz_t integ;
	mpz_init_set_str(integ, inputStr, 16);
	mpz_get_str(constStrDecimal, 10, integ);
	mpz_clear(integ);
	FieldT f = FieldT(constStrDecimal);
	return f;

}


CircuitReader::CircuitReader(
	char* arithFilepath,
	char* inputsFilepath,
	ProtoboardT& in_pb
) :
	pb(in_pb)
{

	this->pb = pb;
	numWires = 0;
	numInputs = numNizkInputs = numOutputs = 0;

	parseAndEval(arithFilepath, inputsFilepath);
	constructCircuit(arithFilepath);
	mapValuesToProtoboard();
}

void CircuitReader::parseAndEval(char* arithFilepath, char* inputsFilepath) {

	enter_block("Parsing and Evaluating the circuit");

	ifstream arithfs(arithFilepath, ifstream::in);
	ifstream inputfs(inputsFilepath, ifstream::in);
	string line;

	if (!arithfs.good()) {
		printf("Unable to open circuit file %s \n", arithFilepath);
		exit(-1);
	}

	getline(arithfs, line);
	int ret = sscanf(line.c_str(), "total %u", &numWires);

	if (ret != 1) {
		printf("File Format Does not Match\n");
		exit(-1);
	}

	wireValues.resize(numWires);

	if (!inputfs.good()) {
		printf("Unable to open input file %s \n", inputsFilepath);
		exit(-1);
	}
	else {
		char* inputStr;
		while (getline(inputfs, line)) {
			if (line.length() == 0) {
				continue;
			}
			Wire wireId;
			inputStr = new char[line.size()];
			if (2 == sscanf(line.c_str(), "%u %s", &wireId, inputStr)) {
				wireValues[wireId] = readFieldElementFromHex(inputStr);
			} else {
				printf("Error in Input\n");
				exit(-1);
			}
			delete[] inputStr;
		}
		inputfs.close();
	}

	char type[200];
	char* inputStr;
	char* outputStr;
	unsigned int numGateInputs, numGateOutputs;

	Wire wireId;

	FieldT oneElement = FieldT::one();
	FieldT zeroElement = FieldT::zero();
	FieldT negOneElement = FieldT(-1);

	// Parse the circuit: few lines were imported from Pinocchio's code.

	while (getline(arithfs, line)) {
		if (line.length() == 0) {
			continue;
		}
		inputStr = new char[line.size()];
		outputStr = new char[line.size()];

		if (line[0] == '#') {
			continue;
		}
		else if (1 == sscanf(line.c_str(), "input %u", &wireId)) {
			numInputs++;
			varNew(wireId, "input");
			inputWireIds.push_back(wireId);
		}
		else if (1 == sscanf(line.c_str(), "nizkinput %u", &wireId)) {
			numNizkInputs++;
			varNew(wireId, "nizkinput");
			nizkWireIds.push_back(wireId);
		}
		else if (1 == sscanf(line.c_str(), "output %u", &wireId)) {
			numOutputs++;
			varNew(wireId, "output");
			outputWireIds.push_back(wireId);
		}
		else if (5 == sscanf(line.c_str(), "%s in %u <%[^>]> out %u <%[^>]>", type,
						&numGateInputs, inputStr, &numGateOutputs, outputStr)) {

			istringstream iss_i(inputStr, istringstream::in);
			std::vector<FieldT> inValues;
			std::vector<Wire> outWires;
			Wire inWireId;
			while (iss_i >> inWireId) {
				inValues.push_back(wireValues[inWireId]);
			}
			readIds(outputStr, outWires);

			short opcode;
			FieldT constant;
			if (strcmp(type, "add") == 0) {
				opcode = ADD_OPCODE;
			}
			else if (strcmp(type, "mul") == 0) {
				opcode = MUL_OPCODE;
			}
			else if (strcmp(type, "xor") == 0) {
				opcode = XOR_OPCODE;
			}
			else if (strcmp(type, "or") == 0) {
				opcode = OR_OPCODE;
			}
			else if (strcmp(type, "assert") == 0) {
				opcode = CONSTRAINT_OPCODE;
			}
			else if (strcmp(type, "pack") == 0) {
				opcode = PACK_OPCODE;
			}
			else if (strcmp(type, "zerop") == 0) {
				opcode = NONZEROCHECK_OPCODE;
			}
			else if (strcmp(type, "split") == 0) {
				opcode = SPLIT_OPCODE;
			}
			else if (strstr(type, "const-mul-neg-")) {
				opcode = MULCONST_OPCODE;
				char* constStr = type + sizeof("const-mul-neg-") - 1;
				constant = readFieldElementFromHex(constStr) * negOneElement;
			}
			else if (strstr(type, "const-mul-")) {
				opcode = MULCONST_OPCODE;
				char* constStr = type + sizeof("const-mul-") - 1;
				constant = readFieldElementFromHex(constStr);
			}
			else {
				printf("Error: unrecognized line: %s\n", line.c_str());
				exit(-1);
			}

	
			if (opcode == ADD_OPCODE) {
				FieldT sum;
				for (auto &v : inValues)
					sum += v;
				wireValues[outWires[0]] = sum;
			}
			else if (opcode == MUL_OPCODE) {
				wireValues[outWires[0]] = inValues[0] * inValues[1];
			}
			else if (opcode == XOR_OPCODE) {
				wireValues[outWires[0]] =
						(inValues[0] == inValues[1]) ? zeroElement : oneElement;
			}
			else if (opcode == OR_OPCODE) {
				wireValues[outWires[0]] =
						(inValues[0] == zeroElement
								&& inValues[1] == zeroElement) ?
								zeroElement : oneElement;
			}
			else if (opcode == NONZEROCHECK_OPCODE) {
				wireValues[outWires[1]] = (inValues[0] == zeroElement) ? zeroElement : oneElement;
			}
			else if (opcode == PACK_OPCODE) {
				FieldT sum;
				FieldT two = oneElement;
				for (auto &v : inValues) {
					sum += two * v;
					two += two;
				}
				wireValues[outWires[0]] = sum;
			}
			else if (opcode == SPLIT_OPCODE) {
				int size = outWires.size();
				FieldT& inVal = inValues[0];
				for (int i = 0; i < size; i++) {
					wireValues[outWires[i]] = inVal.as_bigint().test_bit(i);
				}
			}
			else if (opcode == MULCONST_OPCODE) {
				wireValues[outWires[0]] = constant * inValues[0];
			}
		}
		else {
			printf("Error: unrecognized line: %s\n", line.c_str());
			assert(0);
		}
		delete[] inputStr;
		delete[] outputStr;
	}
	arithfs.close();

	leave_block("Parsing and Evaluating the circuit");
}

void CircuitReader::constructCircuit(char* arithFilepath) {

	cout << "Translating Constraints ... " << endl;
	unsigned int i;

	char type[200];
	char* inputStr;
	char* outputStr;
	string line;
	unsigned int numGateInputs, numGateOutputs;

	ifstream ifs2(arithFilepath, ifstream::in);

	if (!ifs2.good()) {
		printf("Unable to open circuit file:\n");
		exit(5);
	}

	enter_block("Translating constraints");

	getline(ifs2, line);
	sscanf(line.c_str(), "total %d", &numWires);

	int lineCount = 0;
	while (getline(ifs2, line)) {
		lineCount++;

		if (line.length() == 0) {
			continue;
		}
		inputStr = new char[line.size()];
		outputStr = new char[line.size()];

		if (5 == sscanf(line.c_str(), "%s in %d <%[^>]> out %d <%[^>]>", type,
						&numGateInputs, inputStr, &numGateOutputs, outputStr)) {

			std::vector<Wire> inWires;
			readIds(inputStr, inWires);
			if( numGateInputs != inWires.size() ) {
				std::cerr << "Error parsing line: " << line << std::endl;
				std::cerr << " input gate mismatch, expected " << numGateInputs << " got " << inWires.size() << std::endl;
				exit(6);
			}

			std::vector<Wire> outWires;
			readIds(outputStr, outWires);
			if( numGateOutputs != outWires.size() ) {
				std::cerr << "Error parsing line: " << line << std::endl;
				std::cerr << " output gate mismatch, expected " << numGateOutputs << " got " << outWires.size() << std::endl;
				exit(6);
			}

			if (strcmp(type, "add") == 0) {
				assert(numGateOutputs == 1);
				handleAddition(inputStr, outputStr);
			}
			else if (strcmp(type, "mul") == 0) {
				assert(numGateInputs == 2 && numGateOutputs == 1);
				addMulConstraint(inputStr, outputStr);
			}
			else if (strcmp(type, "xor") == 0) {
				assert(numGateInputs == 2 && numGateOutputs == 1);
				addXorConstraint(inputStr, outputStr);
			}
			else if (strcmp(type, "or") == 0) {
				assert(numGateInputs == 2 && numGateOutputs == 1);
				addOrConstraint(inputStr, outputStr);
			}
			else if (strcmp(type, "assert") == 0) {
				assert(numGateInputs == 2 && numGateOutputs == 1);
				addAssertionConstraint(inputStr, outputStr);
			}
			else if (strstr(type, "const-mul-neg-")) {
				assert(numGateInputs == 1 && numGateOutputs == 1);
				handleMulNegConst(type, inputStr, outputStr);
			}
			else if (strstr(type, "const-mul-")) {
				assert(numGateInputs == 1 && numGateOutputs == 1);
				handleMulConst(type, inputStr, outputStr);
			}
			else if (strcmp(type, "zerop") == 0) {
				assert(numGateInputs == 1 && numGateOutputs == 2);
				addNonzeroCheckConstraint(inputStr, outputStr);
			}
			else if (strstr(type, "split")) {
				assert(numGateInputs == 1);
				addSplitConstraint(inputStr, outputStr, numGateOutputs);
			}
			else if (strstr(type, "pack")) {
				assert(numGateOutputs == 1);
				addPackConstraint(inputStr, outputStr, numGateInputs);
			}
		}
		else {
//			assert(0);
		}
		delete[] inputStr;
		delete[] outputStr;
	}

	ifs2.close();

	leave_block("Translating constraints");
}

void CircuitReader::mapValuesToProtoboard()
{
	enter_block("Assigning values");

	for( auto& iter : variableMap )
	{
		pb.val(iter.second) = wireValues[iter.first];
	}

	for( auto& item : zerop_items )
	{
		auto& X = wireGet(item.in_wire_id);
		// X * M = Y
		// Y == 0 || Y == 1
		if( pb.lc_val(X) != 0 ) {
			// M = 1/X
			pb.val(item.aux_var) = FieldT::one() * pb.lc_val(X).inverse();
		}
		else {
			// M = 0
			pb.val(item.aux_var) = 0;
		}
	}

	if (!pb.is_satisfied()) {
		printf("Protoboard Not Satisfied");
		assert(0);
	}

	leave_block("Assigning values");
}


bool CircuitReader::wireExists( Wire wire_id )
{
	return wireLC.find(wire_id) != wireLC.end();
}


LinearCombinationT& CircuitReader::wireGet( Wire wire_id )
{
	if( ! wireExists(wire_id) )
	{
		auto& v = varGet(wire_id);
		wireLC.emplace(wire_id, LinearCombinationT(v));
	}

	return wireLC[wire_id];
}


bool CircuitReader::varExists( Wire wire_id )
{
	return variableMap.find(wire_id) != variableMap.end();
}


VariableT& CircuitReader::varNew( Wire wire_id, const std::string &annotation )
{
	VariableT v;
	v.allocate(this->pb, annotation);
	variableMap.emplace(wire_id, v);
	return variableMap[wire_id];
}


VariableT& CircuitReader::varGet( Wire wire_id, const std::string &annotation )
{
	if ( ! varExists(wire_id) ) {
		return varNew(wire_id, annotation);
	}
	return variableMap[wire_id];
}


void CircuitReader::addMulConstraint(char* inputStr, char* outputStr) {

	Wire outputWireId, inWireId1, inWireId2;

	istringstream iss_i(inputStr, istringstream::in);
	iss_i >> inWireId1;
	iss_i >> inWireId2;
	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;

	auto& l1 = wireGet(inWireId1);
	auto& l2 = wireGet(inWireId2);
	auto& outvar = varGet(outputWireId, "mul out");

	pb.add_r1cs_constraint(ConstraintT(l1, l2, outvar));
}

void CircuitReader::addXorConstraint(char* inputStr, char* outputStr) {

	Wire outputWireId, inWireId1, inWireId2;

	istringstream iss_i(inputStr, istringstream::in);
	iss_i >> inWireId1;
	iss_i >> inWireId2;
	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;

	auto& l1 = wireGet(inWireId1);
	auto& l2 = wireGet(inWireId2);
	auto& outvar = varGet(outputWireId, "xor out");

	pb.add_r1cs_constraint(ConstraintT(2 * l1, l2, l1 + l2 - outvar));
}

void CircuitReader::addOrConstraint(char* inputStr, char* outputStr) {

	Wire outputWireId, inWireId1, inWireId2;

	istringstream iss_i(inputStr, istringstream::in);
	iss_i >> inWireId1;
	iss_i >> inWireId2;
	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;

	auto& l1 = wireGet(inWireId1);
	auto& l2 = wireGet(inWireId2);
	auto& outvar = varGet(outputWireId, "or out");

	pb.add_r1cs_constraint(ConstraintT(l1, l2, l1 + l2 - outvar));
}

void CircuitReader::addAssertionConstraint(char* inputStr, char* outputStr) {

	Wire outputWireId, inWireId1, inWireId2;

	istringstream iss_i(inputStr, istringstream::in);
	iss_i >> inWireId1;
	iss_i >> inWireId2;
	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;

	auto& l1 = wireGet(inWireId1);
	auto& l2 = wireGet(inWireId2);
	auto& l3 = wireGet(outputWireId);

	pb.add_r1cs_constraint(ConstraintT(l1, l2, l3));
}

void CircuitReader::addSplitConstraint(char* inputStr, char* outputStr,
		unsigned short n) {

	Wire inWireId;
	istringstream iss_i(inputStr, istringstream::in);
	iss_i >> inWireId;

	auto& l = wireGet(inWireId);

	istringstream iss_o(outputStr, istringstream::in);

	LinearCombinationT sum;
	auto two_i = FieldT::one();

	for (int i = 0; i < n; i++) {
		Wire bitWireId;
		iss_o >> bitWireId;
		auto &out_bit_var = varGet(bitWireId, "bit out");
		generate_boolean_r1cs_constraint<FieldT>(pb, out_bit_var);
		sum.add_term(libsnark::linear_term<FieldT>(out_bit_var, two_i));
		two_i += two_i;
	}

	pb.add_r1cs_constraint(ConstraintT(l, 1, sum));
}


void CircuitReader::addPackConstraint(char* inputStr, char* outputStr, unsigned short n) {

	Wire outputWireId;
	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;

	istringstream iss_i(inputStr, istringstream::in);
	LinearCombinationT sum;
	auto two_i = FieldT::one();
	for (int i = 0; i < n; i++) {
		Wire bitWireId;
		iss_i >> bitWireId;
		auto& l = wireGet(bitWireId);

		//sum.add_term(*l * two_i);
		// the following should be equivalent to the above
		for( auto& term : (l * two_i) ) {
			sum.add_term(term);
		}

		two_i += two_i;
	}

	auto& outvar = varGet(outputWireId, "pack out");

	pb.add_r1cs_constraint(ConstraintT(outvar, 1, sum));
}


/**
* Zero Equality Gate
* 
* Another useful type of comparison functionality is checking
* whether a value is equal to zero. e.g.
*
*	Y = (X != 0) ? 1 : 0
*
* This is equivalent to satisfying the following two constraints:
*
*	X * (M - Y) = 0
*
* and
*
*	(1 - Y) * X = 0
*
* For some value M, where M should be (1.0/X), or the modulo inverse of X.
*/
void CircuitReader::addNonzeroCheckConstraint(char* inputStr, char* outputStr)
{
	Wire outputWireId, inWireId;

	istringstream iss_i(inputStr, istringstream::in);
	iss_i >> inWireId;
	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;

	auto& X = wireGet(inWireId);
	auto& Y = varGet(outputWireId, "zerop out");
	VariableT M;
	M.allocate(this->pb, "zerop aux");

	pb.add_r1cs_constraint(ConstraintT(X, 1 - Y, 0));
	pb.add_r1cs_constraint(ConstraintT(X, M, Y));

	zerop_items.push_back({inWireId, M});
}

void CircuitReader::handleAddition(char* inputStr, char* outputStr) {

	Wire inWireId, outputWireId;
	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;

	istringstream iss_i(inputStr, istringstream::in);
	iss_i >> inWireId;

	auto& outwire = wireGet(outputWireId);
	while (iss_i >> inWireId) {
		auto& l = wireGet(inWireId);
		for( auto& term : l ) {
			outwire.add_term(term);
		}
	}
}

void CircuitReader::handleMulConst(char* type, char* inputStr, char* outputStr) {

	char* constStr = type + sizeof("const-mul-") - 1;
	Wire outputWireId, inWireId;

	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;
	istringstream iss_i(inputStr, istringstream::in);
	iss_i >> inWireId;

	auto& l = wireGet(inWireId);
	auto& outwire = wireGet(outputWireId);

	auto v = l * readFieldElementFromHex(constStr);
	for( auto& term : v ) {
		outwire.add_term(term);
	}
}

void CircuitReader::handleMulNegConst(char* type, char* inputStr, char* outputStr)
{
	char* constStr = type + sizeof("const-mul-neg-") - 1;
	Wire outputWireId, inWireId;
	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;
	istringstream iss_i(inputStr, istringstream::in);
	iss_i >> inWireId;

	auto& l = wireGet(inWireId);
	auto& outwire = wireGet(outputWireId);

	auto v = l * (readFieldElementFromHex(constStr) * FieldT(-1));
	for( auto& term : v ) {
		outwire.add_term(term);
	}
}
