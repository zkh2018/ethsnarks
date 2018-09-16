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

#include "ethsnarks.hpp"

#include "libsnark/gadgetlib1/pb_variable.hpp"

typedef unsigned int Wire;
typedef std::vector<Wire> InputWires;
typedef std::vector<Wire> OutputWires;

using ethsnarks::FieldT;
using ethsnarks::ProtoboardT;
using ethsnarks::VariableT;
using ethsnarks::LinearCombinationT;


#define ADD_OPCODE 1
#define MUL_OPCODE 2
#define SPLIT_OPCODE 3
#define NONZEROCHECK_OPCODE 4
#define PACK_OPCODE 5
#define MULCONST_OPCODE 6
#define XOR_OPCODE 7
#define OR_OPCODE 8
#define CONSTRAINT_OPCODE 9

struct ZeroEqualityItem {
	Wire in_wire_id;
	VariableT aux_var;
};

class CircuitReader {
public:
	CircuitReader(char* arithFilepath, char* inputsFilepath, ProtoboardT& in_pb);

	int getNumInputs() { return numInputs;}
	int getNumOutputs() { return numOutputs;}
	std::vector<Wire> getInputWireIds() const { return inputWireIds; }
	std::vector<Wire> getOutputWireIds() const { return outputWireIds; }

private:
	ProtoboardT& pb;

	std::map<Wire,LinearCombinationT> wireLC;
	std::map<Wire,VariableT> variableMap;

	std::vector<ZeroEqualityItem> zerop_items;

	std::vector<FieldT> wireValues;

	std::vector<Wire> inputWireIds;
	std::vector<Wire> nizkWireIds;
	std::vector<Wire> outputWireIds;

	unsigned int numWires;
	unsigned int numInputs, numNizkInputs, numOutputs;

	void parseAndEval(char* arithFilepath, char* inputsFilepath);
	void constructCircuit(char*);  // Second Pass:
	void mapValuesToProtoboard();

	bool wireExists( Wire wireId );
	LinearCombinationT& wireGet( Wire wire_id );

	bool varExists( Wire wire_id );
	VariableT& varNew( Wire wire_id, const std::string &annotation="");
	VariableT& varGet( Wire wire_id, const std::string &annotation="");

	void addMulConstraint(InputWires& inputs, OutputWires& outputs);
	void addXorConstraint(InputWires& inputs, OutputWires& outputs);

	void addOrConstraint(InputWires& inputs, OutputWires& outputs);
	void addAssertionConstraint(InputWires& inputs, OutputWires& outputs);

	void addSplitConstraint(InputWires& inputs, OutputWires& outputs);
	void addPackConstraint(InputWires& inputs, OutputWires& outputs);
	void addNonzeroCheckConstraint(InputWires& inputs, OutputWires& outputs);

	void handleAddition(InputWires& inputs, OutputWires& outputs);
	void handleMulConst(InputWires& inputs, OutputWires& outputs, const char*);
	void handleMulNegConst(InputWires& inputs, OutputWires& outputs, const char*);

};

