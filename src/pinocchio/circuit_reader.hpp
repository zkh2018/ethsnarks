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

namespace ethsnarks {

typedef unsigned int Wire;
typedef std::vector<Wire> InputWires;
typedef std::vector<Wire> OutputWires;

typedef std::vector<FieldT> FieldArrayT;


typedef std::vector<LinearCombinationT> LinearCombinationsT;


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
	ethsnarks::VariableT aux_var;
};


/*
class CircuitReader;
class circuit_operation : public GadgetT {
public:
	circuit_operation( CircuitReader& circuit );
	virtual ~circuit_operation();

	virtual size_t inputCount() const;
	virtual size_t outputCount() const;
	virtual size_t auxCount() const;

	virtual void witness( const FieldArrayT &inputs, VariableArrayT &outputs, FieldArrayT &aux_vars );

	virtual void constrain( const LinearCombinationsT &inputs, const LinearCombinationsT &outputs, const LinearCombinationsT &aux );
};
*/


class CircuitReader : public GadgetT {
public:
	CircuitReader(ProtoboardT& in_pb, const char* arithFilepath, const char* inputsFilepath);

	int getNumInputs() { return numInputs;}
	int getNumOutputs() { return numOutputs;}
	std::vector<Wire> getInputWireIds() const { return inputWireIds; }
	std::vector<Wire> getOutputWireIds() const { return outputWireIds; }

	void generate_r1cs_constraints() {}
	void generate_r1cs_witness() {}
	void parseInputs( const char *inputsFilepath );

protected:
	std::map<Wire,LinearCombinationT> wireLC;
	std::map<Wire,VariableT> variableMap;

	std::vector<ZeroEqualityItem> zerop_items;

	std::vector<FieldT> wireValues;

	std::vector<Wire> inputWireIds;
	std::vector<Wire> nizkWireIds;
	std::vector<Wire> outputWireIds;

	size_t numWires {0};
	size_t numInputs {0};
	size_t numNizkInputs {0};
	size_t numOutputs{0};

	void evalOpcode( short opcode, std::vector<FieldT> &inValues, std::vector<Wire> &outWires, FieldT &constant );
	void parseAndEval(const char* arithFilepath, const char* inputsFilepath);
	void constructCircuit(const char*);  // Second Pass:
	void addOperationConstraints( const char *type, const InputWires& inWires, const OutputWires& outWires );
	void mapValuesToProtoboard();

	bool wireExists( Wire wireId );
	LinearCombinationT& wireGet( Wire wire_id );

	bool varExists( Wire wire_id );
	VariableT& varNew( Wire wire_id, const std::string &annotation="");
	VariableT& varGet( Wire wire_id, const std::string &annotation="");

	void addMulConstraint(const InputWires& inputs, const OutputWires& outputs);
	void addXorConstraint(const InputWires& inputs, const OutputWires& outputs);

	void addOrConstraint(const InputWires& inputs, const OutputWires& outputs);
	void addAssertionConstraint(const InputWires& inputs, const OutputWires& outputs);

	void addSplitConstraint(const InputWires& inputs, const OutputWires& outputs);
	void addPackConstraint(const InputWires& inputs, const OutputWires& outputs);
	void addNonzeroCheckConstraint(const InputWires& inputs, const OutputWires& outputs);

	void handleAddition(const InputWires& inputs, const OutputWires& outputs);
	void handleMulConst(const InputWires& inputs, const OutputWires& outputs, const char*);
	void handleMulNegConst(const InputWires& inputs, const OutputWires& outputs, const char*);

};

// namespace ethsnarks
}
