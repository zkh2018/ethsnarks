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

	wireLinearCombinations.clear();
	wireValues.clear();
	variables.clear();
	variableMap.clear();
	zeropMap.clear();
	zeroPwires.clear();
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
	wireUseCounters.resize(numWires);
	wireLinearCombinations.resize(numWires);

	if (!inputfs.good()) {
		printf("Unable to open input file %s \n", inputsFilepath);
		exit(-1);
	} else {
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
		} else if (1 == sscanf(line.c_str(), "input %u", &wireId)) {
			numInputs++;
			inputWireIds.push_back(wireId);
		} else if (1 == sscanf(line.c_str(), "nizkinput %u", &wireId)) {
			numNizkInputs++;
			nizkWireIds.push_back(wireId);
		} else if (1 == sscanf(line.c_str(), "output %u", &wireId)) {
			numOutputs++;
			outputWireIds.push_back(wireId);
			wireUseCounters[wireId]++;
		} else if (5
				== sscanf(line.c_str(), "%s in %u <%[^>]> out %u <%[^>]>", type,
						&numGateInputs, inputStr, &numGateOutputs, outputStr)) {

			istringstream iss_i(inputStr, istringstream::in);
			std::vector<FieldT> inValues;
			std::vector<Wire> outWires;
			Wire inWireId;
			while (iss_i >> inWireId) {
				wireUseCounters[inWireId]++;
				inValues.push_back(wireValues[inWireId]);
			}
			readIds(outputStr, outWires);

			short opcode;
			FieldT constant;
			if (strcmp(type, "add") == 0) {
				opcode = ADD_OPCODE;
			} else if (strcmp(type, "mul") == 0) {
				opcode = MUL_OPCODE;
			} else if (strcmp(type, "xor") == 0) {
				opcode = XOR_OPCODE;
			} else if (strcmp(type, "or") == 0) {
				opcode = OR_OPCODE;
			} else if (strcmp(type, "assert") == 0) {
				wireUseCounters[outWires[0]]++;
				opcode = CONSTRAINT_OPCODE;
			} else if (strcmp(type, "pack") == 0) {
				opcode = PACK_OPCODE;
			} else if (strcmp(type, "zerop") == 0) {
				opcode = NONZEROCHECK_OPCODE;
			} else if (strcmp(type, "split") == 0) {
				opcode = SPLIT_OPCODE;
			} else if (strstr(type, "const-mul-neg-")) {
				opcode = MULCONST_OPCODE;
				char* constStr = type + sizeof("const-mul-neg-") - 1;
				constant = readFieldElementFromHex(constStr) * negOneElement;
			} else if (strstr(type, "const-mul-")) {
				opcode = MULCONST_OPCODE;
				char* constStr = type + sizeof("const-mul-") - 1;
				constant = readFieldElementFromHex(constStr);
			} else {
				printf("Error: unrecognized line: %s\n", line.c_str());
				exit(-1);
			}

	
			if (opcode == ADD_OPCODE) {
				FieldT sum;
				for (auto &v : inValues)
					sum += v;
				wireValues[outWires[0]] = sum;
			} else if (opcode == MUL_OPCODE) {
				wireValues[outWires[0]] = inValues[0] * inValues[1];
			} else if (opcode == XOR_OPCODE) {
				wireValues[outWires[0]] =
						(inValues[0] == inValues[1]) ? zeroElement : oneElement;
			} else if (opcode == OR_OPCODE) {
				wireValues[outWires[0]] =
						(inValues[0] == zeroElement
								&& inValues[1] == zeroElement) ?
								zeroElement : oneElement;
			} else if (opcode == NONZEROCHECK_OPCODE) {
				wireValues[outWires[1]] =
						(inValues[0] == zeroElement) ? zeroElement : oneElement;
			} else if (opcode == PACK_OPCODE) {
				FieldT sum, coeff;
				FieldT two = oneElement;
				for (auto &v : inValues) {
					sum += two * v;
					two += two;
				}
				wireValues[outWires[0]] = sum;
			} else if (opcode == SPLIT_OPCODE) {
				int size = outWires.size();
				FieldT& inVal = inValues[0];
				for (int i = 0; i < size; i++) {
					wireValues[outWires[i]] = inVal.as_bigint().test_bit(i);
				}
			} else if (opcode == MULCONST_OPCODE) {
				wireValues[outWires[0]] = constant * inValues[0];
			}
		} else {
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

	currentVariableIdx = currentLinearCombinationIdx = 0;
	for (i = 0; i < numInputs; i++) {
		VariableT v;
		v.allocate(pb, "input");
		variables.push_back(v);
		variableMap[inputWireIds[i]] = currentVariableIdx;
		currentVariableIdx++;
	}
	for (i = 0; i < numOutputs; i++) {
		VariableT v;
		v.allocate(pb, "output");
		variables.push_back(v);
		variableMap[outputWireIds[i]] = currentVariableIdx;
		currentVariableIdx++;
	}
	for (i = 0; i < numNizkInputs; i++) {
		VariableT v;
		v.allocate(pb, "nizk input");
		variables.push_back(v);
		variableMap[nizkWireIds[i]] = currentVariableIdx;
		currentVariableIdx++;
	}

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

	// Parse the circuit: few lines were imported from Pinocchio's code.

	getline(ifs2, line);
	sscanf(line.c_str(), "total %d", &numWires);

	int lineCount = 0;
	while (getline(ifs2, line)) {
		lineCount++;
//		if (lineCount % 100000 == 0) {
//			printf("At Line:: %d\n", lineCount);
//		}

		if (line.length() == 0) {
			continue;
		}
		inputStr = new char[line.size()];
		outputStr = new char[line.size()];

		if (5 == sscanf(line.c_str(), "%s in %d <%[^>]> out %d <%[^>]>", type,
						&numGateInputs, inputStr, &numGateOutputs, outputStr)) {
			if (strcmp(type, "add") == 0) {
				assert(numGateOutputs == 1);
				handleAddition(inputStr, outputStr);
			} else if (strcmp(type, "mul") == 0) {
				assert(numGateInputs == 2 && numGateOutputs == 1);
				addMulConstraint(inputStr, outputStr);
			} else if (strcmp(type, "xor") == 0) {
				assert(numGateInputs == 2 && numGateOutputs == 1);
				addXorConstraint(inputStr, outputStr);
			} else if (strcmp(type, "or") == 0) {
				assert(numGateInputs == 2 && numGateOutputs == 1);
				addOrConstraint(inputStr, outputStr);
			} else if (strcmp(type, "assert") == 0) {
				assert(numGateInputs == 2 && numGateOutputs == 1);
				addAssertionConstraint(inputStr, outputStr);
			} else if (strstr(type, "const-mul-neg-")) {
				assert(numGateInputs == 1 && numGateOutputs == 1);
				handleMulNegConst(type, inputStr, outputStr);
			} else if (strstr(type, "const-mul-")) {
				assert(numGateInputs == 1 && numGateOutputs == 1);
				handleMulConst(type, inputStr, outputStr);
			} else if (strcmp(type, "zerop") == 0) {
				assert(numGateInputs == 1 && numGateOutputs == 2);
				addNonzeroCheckConstraint(inputStr, outputStr);
			} else if (strstr(type, "split")) {
				assert(numGateInputs == 1);
				addSplitConstraint(inputStr, outputStr, numGateOutputs);
			} else if (strstr(type, "pack")) {
				assert(numGateOutputs == 1);
				addPackConstraint(inputStr, outputStr, numGateInputs);
			}
		} else {
//			assert(0);
		}
		delete[] inputStr;
		delete[] outputStr;
		clean();
	}

	ifs2.close();

	printf("\tConstraint translation done\n");
}

void CircuitReader::mapValuesToProtoboard() {

	int zeropGateIndex = 0;
	for (WireMap::iterator iter = variableMap.begin();
			iter != variableMap.end(); ++iter) {
		Wire wireId = iter->first;
		pb.val(variables[variableMap[wireId]]) = wireValues[wireId];
		if (zeropMap.find(wireId) != zeropMap.end()) {
			auto l = *zeroPwires[zeropGateIndex++];
			if (pb.lc_val(l) == 0) {
				pb.val(variables[zeropMap[wireId]]) = 0;
			} else {
				pb.val(variables[zeropMap[wireId]]) = pb.lc_val(l).inverse();
			}
		}
	}
	if (!pb.is_satisfied()) {
		printf("Protoboard Not Satisfied");
		assert(0);
	}
	printf("Assignment of values done .. \n");

}

int CircuitReader::find(Wire wireId, LinearCombinationPtr& lc,
		bool intentionToEdit) {

	LinearCombinationPtr p = wireLinearCombinations[wireId];
	if (p) {
		wireUseCounters[wireId]--;
		if (wireUseCounters[wireId] == 0) {
			toClean.push_back(wireId);
			lc = p;
		} else {
			if (intentionToEdit) {
				lc = make_shared<LinearCombination>(*p);
			} else {
				lc = p;
			}
		}
		return 1;
	} else {
		wireUseCounters[wireId]--;
		lc = make_shared<LinearCombination>(
				LinearCombination(variables[variableMap[wireId]]));
		if (wireUseCounters[wireId] == 0) {
			toClean.push_back(wireId);
		}
		return 2;
	}
}

void CircuitReader::clean() {

	for (Wire wireId : toClean) {
		wireLinearCombinations[wireId].reset();
	}
	toClean.clear();
}

void CircuitReader::addMulConstraint(char* inputStr, char* outputStr) {

	Wire outputWireId, inWireId1, inWireId2;

	istringstream iss_i(inputStr, istringstream::in);
	iss_i >> inWireId1;
	iss_i >> inWireId2;
	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;

	LinearCombinationPtr l1, l2;
	find(inWireId1, l1);
	find(inWireId2, l2);

	if (variableMap.find(outputWireId) == variableMap.end()) {
		VariableT v;
		v.allocate(pb, "mul out");
		variables.push_back(v);
		variableMap[outputWireId] = currentVariableIdx;
		pb.add_r1cs_constraint(ConstraintT(*l1, *l2, variables[currentVariableIdx]));
		currentVariableIdx++;
	} else {
		pb.add_r1cs_constraint(ConstraintT(*l1, *l2, variables[variableMap[outputWireId]]));
	}
}

void CircuitReader::addXorConstraint(char* inputStr, char* outputStr) {

	Wire outputWireId, inWireId1, inWireId2;

	istringstream iss_i(inputStr, istringstream::in);
	iss_i >> inWireId1;
	iss_i >> inWireId2;
	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;

	LinearCombinationPtr lp1, lp2;
	find(inWireId1, lp1);
	find(inWireId2, lp2);
	LinearCombination l1, l2;
	l1 = *lp1;
	l2 = *lp2;
	if (variableMap.find(outputWireId) == variableMap.end()) {
		VariableT v;
		v.allocate(pb, "xor out");
		variables.push_back(v);
		variableMap[outputWireId] = currentVariableIdx;
		pb.add_r1cs_constraint(ConstraintT(2 * l1, l2,
				l1 + l2 - variables[currentVariableIdx]));
		currentVariableIdx++;
	} else {
		pb.add_r1cs_constraint(ConstraintT(2 * l1, l2,
				l1 + l2 - variables[variableMap[outputWireId]]));
	}
}

void CircuitReader::addOrConstraint(char* inputStr, char* outputStr) {

	Wire outputWireId, inWireId1, inWireId2;

	istringstream iss_i(inputStr, istringstream::in);
	iss_i >> inWireId1;
	iss_i >> inWireId2;
	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;

	LinearCombinationPtr lp1, lp2;
	find(inWireId1, lp1);
	find(inWireId2, lp2);
	LinearCombination l1, l2;
	l1 = *lp1;
	l2 = *lp2;
	if (variableMap.find(outputWireId) == variableMap.end()) {
		VariableT v;
		v.allocate(pb, "or out");
		variables.push_back(v);
		variableMap[outputWireId] = currentVariableIdx;
		pb.add_r1cs_constraint(ConstraintT(l1, l2, l1 + l2 - variables[currentVariableIdx]));
		currentVariableIdx++;
	} else {
		pb.add_r1cs_constraint(ConstraintT(l1, l2,
				l1 + l2 - variables[variableMap[outputWireId]]));
	}
}

void CircuitReader::addAssertionConstraint(char* inputStr, char* outputStr) {

	Wire outputWireId, inWireId1, inWireId2;

	istringstream iss_i(inputStr, istringstream::in);
	iss_i >> inWireId1;
	iss_i >> inWireId2;
	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;

	LinearCombinationPtr lp1, lp2, lp3;
	find(inWireId1, lp1);
	find(inWireId2, lp2);
	find(outputWireId, lp3);

	LinearCombination l1, l2, l3;
	l1 = *lp1;
	l2 = *lp2;
	l3 = *lp3;
	pb.add_r1cs_constraint(ConstraintT(l1, l2, l3));

}

void CircuitReader::addSplitConstraint(char* inputStr, char* outputStr,
		unsigned short n) {

	Wire inWireId;
	istringstream iss_i(inputStr, istringstream::in);
	iss_i >> inWireId;

	LinearCombinationPtr l;
	find(inWireId, l);

	istringstream iss_o(outputStr, istringstream::in);

	LinearCombination sum;
	auto two_i = FieldT::one();

	for (int i = 0; i < n; i++) {
		Wire bitWireId;
		iss_o >> bitWireId;
		VariableT* vptr;
		if (variableMap.find(bitWireId) == variableMap.end()) {
			VariableT v;
			v.allocate(pb, "bit out");
			variables.push_back(v);
			variableMap[bitWireId] = currentVariableIdx;
			vptr = &variables[currentVariableIdx];
			currentVariableIdx++;
		} else {
			vptr = &variables[variableMap[bitWireId]];
		}
		generate_boolean_r1cs_constraint<FieldT>(pb, *vptr);
		sum.add_term(libsnark::linear_term<FieldT>(*vptr, two_i));
		two_i += two_i;
	}


	pb.add_r1cs_constraint(ConstraintT(*l, 1, sum));
}

void CircuitReader::addPackConstraint(char* inputStr, char* outputStr,
		unsigned short n) {

	Wire outputWireId;
	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;

	istringstream iss_i(inputStr, istringstream::in);
	LinearCombination sum;
	auto two_i = FieldT::one();
	for (int i = 0; i < n; i++) {
		Wire bitWireId;
		iss_i >> bitWireId;
		LinearCombinationPtr l;
		find(bitWireId, l);

		//sum.add_term(*l * two_i);

		// the following should be equivalent to the above
		for( auto& term : (*l * two_i) ) {
			sum.add_term(term);
		}

		two_i += two_i;
	}

	VariableT* vptr;
	if (variableMap.find(outputWireId) == variableMap.end()) {
		VariableT v;
		v.allocate(pb, "pack out");
		variables.push_back(v);
		variableMap[outputWireId] = currentVariableIdx;
		vptr = &variables[currentVariableIdx];
		currentVariableIdx++;
	}
	else {
		vptr = &variables[variableMap[outputWireId]];
	}

	pb.add_r1cs_constraint(ConstraintT(*vptr, 1, sum));

}

void CircuitReader::addNonzeroCheckConstraint(char* inputStr, char* outputStr)
{
	Wire outputWireId, inWireId;

	istringstream iss_i(inputStr, istringstream::in);
	iss_i >> inWireId;
	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;
	iss_o >> outputWireId;

	LinearCombinationPtr l;

	find(inWireId, l);
	VariableT *vptr;
	if (variableMap.find(outputWireId) == variableMap.end()) {
		VariableT v;
		v.allocate(pb, "zerop out");
		variables.push_back(v);
		variableMap[outputWireId] = currentVariableIdx;
		vptr = &variables[currentVariableIdx];
		currentVariableIdx++;
	} else {
		vptr = &variables[variableMap[outputWireId]];
	}
	VariableT w;
	w.allocate(pb, "zerop aux");
	variables.push_back(w);
	pb.add_r1cs_constraint(ConstraintT(*l, 1 - *vptr, 0));
	pb.add_r1cs_constraint(ConstraintT(*l, variables[currentVariableIdx], *vptr)),

	zeroPwires.push_back(l);
	zeropMap[outputWireId] = currentVariableIdx;
	currentVariableIdx++;

}

void CircuitReader::handleAddition(char* inputStr, char* outputStr) {

	Wire inWireId, outputWireId;
	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;

	istringstream iss_i(inputStr, istringstream::in);
	LinearCombinationPtr s, l;
	iss_i >> inWireId;
	find(inWireId, l, true);
	s = l;
	while (iss_i >> inWireId) {
		find(inWireId, l);
		for( auto& term : *l ) {
			s->add_term(term);
		}
		//*s += *l;
	}
	wireLinearCombinations[outputWireId] = s;
}

void CircuitReader::handleMulConst(char* type, char* inputStr, char* outputStr) {

	char* constStr = type + sizeof("const-mul-") - 1;
	Wire outputWireId, inWireId;

	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;
	istringstream iss_i(inputStr, istringstream::in);
	iss_i >> inWireId;
	LinearCombinationPtr l;
	find(inWireId, l, true);

	auto v = *l * readFieldElementFromHex(constStr);
	for( auto& term : v ) {
		wireLinearCombinations[outputWireId]->add_term(term);
	}
	//wireLinearCombinations[outputWireId] = make_shared<LinearCombination>(v);
}

void CircuitReader::handleMulNegConst(char* type, char* inputStr, char* outputStr)
{
	char* constStr = type + sizeof("const-mul-neg-") - 1;
	Wire outputWireId, inWireId;
	istringstream iss_o(outputStr, istringstream::in);
	iss_o >> outputWireId;
	istringstream iss_i(inputStr, istringstream::in);
	iss_i >> inWireId;

	LinearCombinationPtr l;
	find(inWireId, l, true);

	/*
	wireLinearCombinations[outputWireId] = l;
	*(wireLinearCombinations[outputWireId]) *= readFieldElementFromHex(
			constStr);
	*(wireLinearCombinations[outputWireId]) *= FieldT(-1); //TODO: make shared FieldT constants
	*/
	auto v = *l * readFieldElementFromHex(constStr) * FieldT(-1);
	for( auto& term : v ) {
		wireLinearCombinations[outputWireId]->add_term(term);
	}
	//wireLinearCombinations[outputWireId] = make_shared<LinearCombination>(*l * readFieldElementFromHex(constStr) * FieldT(-1));
}
