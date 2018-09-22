/*
MIT License

Copyright (c) 2015 Ahmed Kosba
Copyright (c) 2018 HarryR

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


namespace ethsnarks {

typedef unsigned int Wire;
typedef std::vector<Wire> InputWires;
typedef std::vector<Wire> OutputWires;

typedef std::vector<FieldT> FieldArrayT;


typedef std::vector<LinearCombinationT> LinearCombinationsT;


enum Opcode {
	ADD_OPCODE,
	MUL_OPCODE,
	XOR_OPCODE,
	OR_OPCODE,
	ASSERT_OPCODE,
	ZEROP_OPCODE,
	SPLIT_OPCODE,
	PACK_OPCODE,
	CONST_MUL_NEG_OPCODE,
	CONST_MUL_OPCODE
};


struct ZeroEqualityItem {
	Wire in_wire_id;
	ethsnarks::VariableT aux_var;
};


struct CircuitInstruction {
	Opcode opcode;
	FieldT constant;
	InputWires inputs;
	OutputWires outputs;
};


/*
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

	int getNumInputs() const {
		return numInputs;
	}

	int getNumOutputs() const {
		return numOutputs;
	}

	const InputWires& getInputWireIds() const {
		return inputWireIds;
	}

	const OutputWires& getOutputWireIds() const {
		return outputWireIds;
	}

	void parseInputs( const char *inputsFilepath );

	bool wireExists( Wire wireId );
	LinearCombinationT& wireGet( Wire wire_id, const std::string &annotation="" );
	FieldT wireValue( Wire wire_id );

	bool varExists( Wire wire_id );
	VariableT& varNew( Wire wire_id, const std::string &annotation="");
	VariableT& varGet( Wire wire_id, const std::string &annotation="");

protected:
	std::map<Wire,LinearCombinationT> wireLC;
	std::map<Wire,VariableT> variableMap;

	std::vector<ZeroEqualityItem> zerop_items;

	std::vector<FieldT> wireValues;

	std::vector<CircuitInstruction> instructions;

	std::vector<Wire> inputWireIds;
	std::vector<Wire> nizkWireIds;
	std::vector<Wire> outputWireIds;

	size_t numWires {0};
	size_t numInputs {0};
	size_t numNizkInputs {0};
	size_t numOutputs{0};

	void parseCircuit(const char* arithFilepath);
	void evalInstruction( const CircuitInstruction &inst );
	void makeAllConstraints( );
	void makeConstraints( const CircuitInstruction& inst );
	void addOperationConstraints( const char *type, const InputWires& inWires, const OutputWires& outWires );
	void mapValuesToProtoboard();


	void addMulConstraint(const InputWires& inputs, const OutputWires& outputs);
	void addXorConstraint(const InputWires& inputs, const OutputWires& outputs);

	void addOrConstraint(const InputWires& inputs, const OutputWires& outputs);
	void addAssertionConstraint(const InputWires& inputs, const OutputWires& outputs);

	void addSplitConstraint(const InputWires& inputs, const OutputWires& outputs);
	void addPackConstraint(const InputWires& inputs, const OutputWires& outputs);
	void addNonzeroCheckConstraint(const InputWires& inputs, const OutputWires& outputs);

	void handleAddition(const InputWires& inputs, const OutputWires& outputs);
	void handleMulConst(const InputWires& inputs, const OutputWires& outputs, const FieldT& constant);
	void handleMulNegConst(const InputWires& inputs, const OutputWires& outputs, const FieldT& constant);

};

// namespace ethsnarks
}
