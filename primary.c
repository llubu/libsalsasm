/*
Copyright (c) 2012 Ryan Salsamendi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
#include "salsasm_types.h"


typedef bool (*DecodeOperandsFunc)(X86DecoderState* state);

typedef struct PrimaryOpCodeTableArithmeticOperands
{
	X86Operand operands[2];
	uint8_t dispBytes;
	uint8_t sibBytes;
} PrimaryOpCodeTableArithmeticOperands;

#define PRIMARY_ARITHMETIC_OPERANDS8(a, b, c, d) \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 1, 0, 0}, {X86_AL, {X86_NONE, X86_NONE}, X86_NONE, 1, 0, 0}}, d, 0}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 1, 0, 0}, {X86_CL, {X86_NONE, X86_NONE}, X86_NONE, 1, 0, 0}}, d, 0}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 1, 0, 0}, {X86_DL, {X86_NONE, X86_NONE}, X86_NONE, 1, 0, 0}}, d, 0}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 1, 0, 0}, {X86_BL, {X86_NONE, X86_NONE}, X86_NONE, 1, 0, 0}}, d, 0}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 1, 0, 0}, {X86_AH, {X86_NONE, X86_NONE}, X86_NONE, 1, 0, 0}}, d, 0}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 1, 0, 0}, {X86_CH, {X86_NONE, X86_NONE}, X86_NONE, 1, 0, 0}}, d, 0}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 1, 0, 0}, {X86_DH, {X86_NONE, X86_NONE}, X86_NONE, 1, 0, 0}}, d, 0}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 1, 0, 0}, {X86_BH, {X86_NONE, X86_NONE}, X86_NONE, 1, 0, 0}}, d, 0}

static const PrimaryOpCodeTableArithmeticOperands modRmOperands8[256] =
{
	// Mod 00
	PRIMARY_ARITHMETIC_OPERANDS8(MEM, BX, SI, 0),
	PRIMARY_ARITHMETIC_OPERANDS8(MEM, BX, DI, 0),
	PRIMARY_ARITHMETIC_OPERANDS8(MEM, BP, SI, 0),
	PRIMARY_ARITHMETIC_OPERANDS8(MEM, BP, DI, 0),
	PRIMARY_ARITHMETIC_OPERANDS8(MEM, SI, NONE, 0),
	PRIMARY_ARITHMETIC_OPERANDS8(MEM, DI, NONE, 0),
	PRIMARY_ARITHMETIC_OPERANDS8(MEM, NONE, NONE, 2),
	PRIMARY_ARITHMETIC_OPERANDS8(MEM, BX, NONE, 0),

	// Mod 01
	PRIMARY_ARITHMETIC_OPERANDS8(MEM, BX, SI, 1),
	PRIMARY_ARITHMETIC_OPERANDS8(MEM, BX, DI, 1),
	PRIMARY_ARITHMETIC_OPERANDS8(MEM, BP, SI, 1),
	PRIMARY_ARITHMETIC_OPERANDS8(MEM, BP, DI, 1),
	PRIMARY_ARITHMETIC_OPERANDS8(MEM, SI, NONE, 1),
	PRIMARY_ARITHMETIC_OPERANDS8(MEM, DI, NONE, 1),
	PRIMARY_ARITHMETIC_OPERANDS8(MEM, BP, NONE, 1),
	PRIMARY_ARITHMETIC_OPERANDS8(MEM, BX, NONE, 1),

	// Mod 10
	PRIMARY_ARITHMETIC_OPERANDS8(MEM, BX, SI, 2),
	PRIMARY_ARITHMETIC_OPERANDS8(MEM, BX, DI, 2),
	PRIMARY_ARITHMETIC_OPERANDS8(MEM, BP, SI, 2),
	PRIMARY_ARITHMETIC_OPERANDS8(MEM, BP, DI, 2),
	PRIMARY_ARITHMETIC_OPERANDS8(MEM, SI, NONE, 2),
	PRIMARY_ARITHMETIC_OPERANDS8(MEM, DI, NONE, 2),
	PRIMARY_ARITHMETIC_OPERANDS8(MEM, BP, NONE, 2),
	PRIMARY_ARITHMETIC_OPERANDS8(MEM, BX, NONE, 2),

	// Mod 11
	PRIMARY_ARITHMETIC_OPERANDS8(AL, NONE, NONE, 0),
	PRIMARY_ARITHMETIC_OPERANDS8(CL, NONE, NONE, 0),
	PRIMARY_ARITHMETIC_OPERANDS8(DL, NONE, NONE, 0),
	PRIMARY_ARITHMETIC_OPERANDS8(BL, NONE, NONE, 0),
	PRIMARY_ARITHMETIC_OPERANDS8(AH, NONE, NONE, 0),
	PRIMARY_ARITHMETIC_OPERANDS8(CH, NONE, NONE, 0),
	PRIMARY_ARITHMETIC_OPERANDS8(DH, NONE, NONE, 0),
	PRIMARY_ARITHMETIC_OPERANDS8(BH, NONE, NONE, 0),
};

#define PRIMARY_ARITHMETIC_OPERANDS16(a, b, c, d) \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 2, 0, 0}, {X86_AX, {X86_NONE, X86_NONE}, X86_NONE, 2, 0, 0}}, d, 0}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 2, 0, 0}, {X86_CX, {X86_NONE, X86_NONE}, X86_NONE, 2, 0, 0}}, d, 0}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 2, 0, 0}, {X86_DX, {X86_NONE, X86_NONE}, X86_NONE, 2, 0, 0}}, d, 0}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 2, 0, 0}, {X86_BX, {X86_NONE, X86_NONE}, X86_NONE, 2, 0, 0}}, d, 0}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 2, 0, 0}, {X86_SP, {X86_NONE, X86_NONE}, X86_NONE, 2, 0, 0}}, d, 0}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_SS, 2, 0, 0}, {X86_BP, {X86_NONE, X86_NONE}, X86_NONE, 2, 0, 0}}, d, 0}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 2, 0, 0}, {X86_SI, {X86_NONE, X86_NONE}, X86_NONE, 2, 0, 0}}, d, 0}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 2, 0, 0}, {X86_DI, {X86_NONE, X86_NONE}, X86_NONE, 2, 0, 0}}, d, 0}

static const PrimaryOpCodeTableArithmeticOperands modRmOperands16[256] =
{
	// Mod 00
	PRIMARY_ARITHMETIC_OPERANDS16(MEM, BX, SI, 0),
	PRIMARY_ARITHMETIC_OPERANDS16(MEM, BX, DI, 0),
	PRIMARY_ARITHMETIC_OPERANDS16(MEM, BP, SI, 0),
	PRIMARY_ARITHMETIC_OPERANDS16(MEM, BP, DI, 0),
	PRIMARY_ARITHMETIC_OPERANDS16(MEM, SI, NONE, 0),
	PRIMARY_ARITHMETIC_OPERANDS16(MEM, DI, NONE, 0),
	PRIMARY_ARITHMETIC_OPERANDS16(MEM, NONE, NONE, 2),
	PRIMARY_ARITHMETIC_OPERANDS16(MEM, BX, NONE, 0),

	// Mod 01
	PRIMARY_ARITHMETIC_OPERANDS16(MEM, BX, SI, 1),
	PRIMARY_ARITHMETIC_OPERANDS16(MEM, BX, DI, 1),
	PRIMARY_ARITHMETIC_OPERANDS16(MEM, BP, SI, 1),
	PRIMARY_ARITHMETIC_OPERANDS16(MEM, BP, DI, 1),
	PRIMARY_ARITHMETIC_OPERANDS16(MEM, SI, NONE, 1),
	PRIMARY_ARITHMETIC_OPERANDS16(MEM, DI, NONE, 1),
	PRIMARY_ARITHMETIC_OPERANDS16(MEM, BP, NONE, 1),
	PRIMARY_ARITHMETIC_OPERANDS16(MEM, BX, NONE, 1),

	// Mod 10
	PRIMARY_ARITHMETIC_OPERANDS16(MEM, BX, SI, 2),
	PRIMARY_ARITHMETIC_OPERANDS16(MEM, BX, DI, 2),
	PRIMARY_ARITHMETIC_OPERANDS16(MEM, BP, SI, 2),
	PRIMARY_ARITHMETIC_OPERANDS16(MEM, BP, DI, 2),
	PRIMARY_ARITHMETIC_OPERANDS16(MEM, SI, NONE, 2),
	PRIMARY_ARITHMETIC_OPERANDS16(MEM, DI, NONE, 2),
	PRIMARY_ARITHMETIC_OPERANDS16(MEM, BP, NONE, 2),
	PRIMARY_ARITHMETIC_OPERANDS16(MEM, BX, NONE, 2),

	// Mod 11
	PRIMARY_ARITHMETIC_OPERANDS16(AX, NONE, NONE, 0),
	PRIMARY_ARITHMETIC_OPERANDS16(CX, NONE, NONE, 0),
	PRIMARY_ARITHMETIC_OPERANDS16(DX, NONE, NONE, 0),
	PRIMARY_ARITHMETIC_OPERANDS16(BX, NONE, NONE, 0),
	PRIMARY_ARITHMETIC_OPERANDS16(SP, NONE, NONE, 0),
	PRIMARY_ARITHMETIC_OPERANDS16(BP, NONE, NONE, 0),
	PRIMARY_ARITHMETIC_OPERANDS16(SI, NONE, NONE, 0),
	PRIMARY_ARITHMETIC_OPERANDS16(DI, NONE, NONE, 0),
};

#define PRIMARY_ARITHMETIC_OPERANDS32(a, b, c, d, e) \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 2, 0, 0}, {X86_AX, {X86_NONE, X86_NONE}, X86_NONE, 2, 0, 0}}, d, e}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 2, 0, 0}, {X86_CX, {X86_NONE, X86_NONE}, X86_NONE, 2, 0, 0}}, d, e}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 2, 0, 0}, {X86_DX, {X86_NONE, X86_NONE}, X86_NONE, 2, 0, 0}}, d, e}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 2, 0, 0}, {X86_BX, {X86_NONE, X86_NONE}, X86_NONE, 2, 0, 0}}, d, e}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 2, 0, 0}, {X86_SP, {X86_NONE, X86_NONE}, X86_NONE, 2, 0, 0}}, d, e}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_SS, 2, 0, 0}, {X86_BP, {X86_NONE, X86_NONE}, X86_NONE, 2, 0, 0}}, d, e}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 2, 0, 0}, {X86_SI, {X86_NONE, X86_NONE}, X86_NONE, 2, 0, 0}}, d, e}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 2, 0, 0}, {X86_DI, {X86_NONE, X86_NONE}, X86_NONE, 2, 0, 0}}, d, e}

static const PrimaryOpCodeTableArithmeticOperands modRmOperands32[256] =
{
	// Mod 00
	PRIMARY_ARITHMETIC_OPERANDS32(MEM, EAX, NONE, 0, 0),
	PRIMARY_ARITHMETIC_OPERANDS32(MEM, ECX, NONE, 0, 0),
	PRIMARY_ARITHMETIC_OPERANDS32(MEM, EDX, NONE, 0, 0),
	PRIMARY_ARITHMETIC_OPERANDS32(MEM, EBX, NONE, 0, 0),
	PRIMARY_ARITHMETIC_OPERANDS32(NONE, NONE, NONE, 0, 1), // SIB
	PRIMARY_ARITHMETIC_OPERANDS32(MEM, NONE, NONE, 4, 0),
	PRIMARY_ARITHMETIC_OPERANDS32(MEM, ESI, NONE, 0, 0),
	PRIMARY_ARITHMETIC_OPERANDS32(MEM, EDI, NONE, 0, 0),

	// Mod 01
	PRIMARY_ARITHMETIC_OPERANDS32(MEM, EAX, NONE, 1, 0),
	PRIMARY_ARITHMETIC_OPERANDS32(MEM, ECX, NONE, 1, 0),
	PRIMARY_ARITHMETIC_OPERANDS32(MEM, EDX, NONE, 1, 0),
	PRIMARY_ARITHMETIC_OPERANDS32(MEM, EBX, NONE, 1, 0),
	PRIMARY_ARITHMETIC_OPERANDS32(NONE, NONE, NONE, 1, 1), // SIB
	PRIMARY_ARITHMETIC_OPERANDS32(MEM, NONE, NONE, 1, 0),
	PRIMARY_ARITHMETIC_OPERANDS32(MEM, ESI, NONE, 1, 0),
	PRIMARY_ARITHMETIC_OPERANDS32(MEM, EDI, NONE, 1, 0),

	// Mod 10
	PRIMARY_ARITHMETIC_OPERANDS32(MEM, EAX, NONE, 4, 0),
	PRIMARY_ARITHMETIC_OPERANDS32(MEM, ECX, NONE, 4, 0),
	PRIMARY_ARITHMETIC_OPERANDS32(MEM, EDX, NONE, 4, 0),
	PRIMARY_ARITHMETIC_OPERANDS32(MEM, EBX, NONE, 4, 0),
	PRIMARY_ARITHMETIC_OPERANDS32(NONE, NONE, NONE, 4, 1), // SIB
	PRIMARY_ARITHMETIC_OPERANDS32(MEM, NONE, NONE, 4, 0),
	PRIMARY_ARITHMETIC_OPERANDS32(MEM, ESI, NONE, 4, 0),
	PRIMARY_ARITHMETIC_OPERANDS32(MEM, EDI, NONE, 4, 0),

	// Mod 11
	PRIMARY_ARITHMETIC_OPERANDS32(EAX, NONE, NONE, 0, 0),
	PRIMARY_ARITHMETIC_OPERANDS32(ECX, NONE, NONE, 0, 0),
	PRIMARY_ARITHMETIC_OPERANDS32(EDX, NONE, NONE, 0, 0),
	PRIMARY_ARITHMETIC_OPERANDS32(EBX, NONE, NONE, 0, 0),
	PRIMARY_ARITHMETIC_OPERANDS32(ESP, NONE, NONE, 0, 0),
	PRIMARY_ARITHMETIC_OPERANDS32(EBP, NONE, NONE, 0, 0),
	PRIMARY_ARITHMETIC_OPERANDS32(ESI, NONE, NONE, 0, 0),
	PRIMARY_ARITHMETIC_OPERANDS32(EDI, NONE, NONE, 0, 0),
};

typedef enum OpCodeSize
{
	OP_8BIT = 0,
	OP_16BIT = 1,
	OP_32BIT = 2,
	OP_64BIT = 3
} OpCodeSize;

static const PrimaryOpCodeTableArithmeticOperands primaryArithmeticImmediateOperands[4] =
{
	// 8bit
	{{{X86_AL, X86_NONE, X86_NONE, X86_NONE, 1, 0, 0}, {X86_IMMEDIATE, X86_NONE, X86_NONE, X86_NONE, 1, 0, 0}}, 1, 0},

	// 16bit
	{{{X86_AX, X86_NONE, X86_NONE, X86_NONE, 2, 0, 0}, {X86_IMMEDIATE, X86_NONE, X86_NONE, X86_NONE, 2, 0, 0}}, 2, 0},

	// 32bit
	{{{X86_EAX, X86_NONE, X86_NONE, X86_NONE, 4, 0, 0}, {X86_IMMEDIATE, X86_NONE, X86_NONE, X86_NONE, 4, 0, 0}}, 4, 0},

	// 64bit
	{{{X86_RAX, X86_NONE, X86_NONE, X86_NONE, 8, 0, 0}, {X86_IMMEDIATE, X86_NONE, X86_NONE, X86_NONE, 8, 0, 0}}, 8, 0},
};

static const X86Operation primaryOpCodeTableArithmetic[] =
{
	X86_ADD, X86_ADC, X86_AND, X86_XOR,
	X86_OR, X86_SBB, X86_SUB, X86_CMP
};

static const PrimaryOpCodeTableArithmeticOperands* modRmOpSizeXref[3] =
{
	modRmOperands16, modRmOperands32, // modRmOperands64 // TODO
};

static const uint8_t operandOrder[2][2] =
{
	{0, 1}, {1, 0}
};

static bool DecodeModRm(X86DecoderState* state,
	const PrimaryOpCodeTableArithmeticOperands* operands, const uint8_t operandOrder[2])
{
	return false;
}

static bool DecodeImmediate(X86DecoderState* state,
	const PrimaryOpCodeTableArithmeticOperands* operands, const uint8_t operandOrder[2])
{
	state->instr->operands[0] = operands->operands[operandOrder[0]];
	state->instr->operands[1] = operands->operands[operandOrder[1]];
	return true;
}


typedef bool (*OperandDecoderFunc)(X86DecoderState* state,
	const PrimaryOpCodeTableArithmeticOperands* operands,
	const uint8_t operandOrder[2]);

static const OperandDecoderFunc opDecoders[2] =
{
	DecodeModRm, DecodeImmediate
};

// See Table A-1 Primary Opcode Map (One-byte Opcodes) AMD 24594_APM_v3.pdf
bool DecodePrimaryOpcodeMap(X86DecoderState* state)
{
	uint8_t op;
	uint8_t row;
	uint8_t col;

	const PrimaryOpCodeTableArithmeticOperands* opXref[2][2] =
	{
		// 8bit
		{&primaryArithmeticImmediateOperands[0], modRmOperands8},

		// Default operand size width
		{&primaryArithmeticImmediateOperands[state->operandSize - 1],
		modRmOpSizeXref[state->operandSize - 1]}
	};

	// Grab a byte from the machine
	if (!state->fetch(state->ctxt, 1, &op))
		return false;

	row  = ((op >> 4) & 0xf);
	col = (op & 0xf);

	// Simple Arithmetic Instructions
	if ((row < 3) && ((col & (~0x8)) < 6))
	{
		const uint8_t reverseOperands = ((col & 2) >> 1);
		const uint8_t operandForm = ((col & 4) >> 2); // IMM or MODRM
		const uint8_t operandSize = (col & 1); // 1byte or default operand size
		const PrimaryOpCodeTableArithmeticOperands* operands;

		state->instr->op = primaryOpCodeTableArithmetic[row];
		state->instr->operandCount = 2;

		operands = opXref[operandSize][operandForm];
		if (!opDecoders[operandForm](state, operands, operandOrder[reverseOperands]))
			return false;
	}
	else
	{
	}

	return false;
}