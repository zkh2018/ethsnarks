/*
 * CircuitReader.hpp
 *
 *      Author: Ahmed Kosba
 */

#include "ethsnarks.hpp"

#include "libsnark/gadgetlib1/pb_variable.hpp"

typedef unsigned int Wire;

using ethsnarks::FieldT;
using ethsnarks::ProtoboardT;
using ethsnarks::VariableT;

typedef libsnark::pb_linear_combination<FieldT> LinearCombination;
typedef std::shared_ptr<LinearCombination> LinearCombinationPtr;
typedef std::map<Wire, unsigned int> WireMap;

#define ADD_OPCODE 1
#define MUL_OPCODE 2
#define SPLIT_OPCODE 3
#define NONZEROCHECK_OPCODE 4
#define PACK_OPCODE 5
#define MULCONST_OPCODE 6
#define XOR_OPCODE 7
#define OR_OPCODE 8
#define CONSTRAINT_OPCODE 9

class CircuitReader {
public:
	CircuitReader(char* arithFilepath, char* inputsFilepath, ProtoboardT& in_pb);

	int getNumInputs() { return numInputs;}
	int getNumOutputs() { return numOutputs;}
	std::vector<Wire> getInputWireIds() const { return inputWireIds; }
	std::vector<Wire> getOutputWireIds() const { return outputWireIds; }

private:
	ProtoboardT& pb;

	std::vector<VariableT> variables;
	std::vector<LinearCombinationPtr> wireLinearCombinations;
	std::vector<LinearCombinationPtr> zeroPwires;

	WireMap variableMap;
	WireMap zeropMap;

	std::vector<unsigned int> wireUseCounters;
	std::vector<FieldT> wireValues;

	std::vector<Wire> toClean;

	std::vector<Wire> inputWireIds;
	std::vector<Wire> nizkWireIds;
	std::vector<Wire> outputWireIds;

	unsigned int numWires;
	unsigned int numInputs, numNizkInputs, numOutputs;

	unsigned int currentVariableIdx, currentLinearCombinationIdx;

	void parseAndEval(char* arithFilepath, char* inputsFilepath);
	void constructCircuit(char*);  // Second Pass:
	void mapValuesToProtoboard();

	int find(unsigned int, LinearCombinationPtr&, bool intentionToEdit = false);
	void clean();

	void addMulConstraint(char*, char*);
	void addXorConstraint(char*, char*);

	void addOrConstraint(char*, char*);
	void addAssertionConstraint(char*, char*);

	void addSplitConstraint(char*, char*, unsigned short);
	void addPackConstraint(char*, char*, unsigned short);
	void addNonzeroCheckConstraint(char*, char*);

	void handleAddition(char*, char*);
	void handleMulConst(char*, char*, char*);
	void handleMulNegConst(char*, char*, char*);

};

