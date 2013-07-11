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


typedef struct PrimaryOpCodeTableOperands
{
	const X86Operand operands[2];
	const uint8_t dispBytes;
	const uint8_t sib;
} PrimaryOpCodeTableOperands;

#define PRIMARY_ARITHMETIC_OPERANDS8(a, b, c, d) \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 1, 0, 0}, {X86_AL, {X86_NONE, X86_NONE}, X86_NONE, 1, 0, 0}}, d, 0}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 1, 0, 0}, {X86_CL, {X86_NONE, X86_NONE}, X86_NONE, 1, 0, 0}}, d, 0}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 1, 0, 0}, {X86_DL, {X86_NONE, X86_NONE}, X86_NONE, 1, 0, 0}}, d, 0}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 1, 0, 0}, {X86_BL, {X86_NONE, X86_NONE}, X86_NONE, 1, 0, 0}}, d, 0}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 1, 0, 0}, {X86_AH, {X86_NONE, X86_NONE}, X86_NONE, 1, 0, 0}}, d, 0}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 1, 0, 0}, {X86_CH, {X86_NONE, X86_NONE}, X86_NONE, 1, 0, 0}}, d, 0}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 1, 0, 0}, {X86_DH, {X86_NONE, X86_NONE}, X86_NONE, 1, 0, 0}}, d, 0}, \
{{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 1, 0, 0}, {X86_BH, {X86_NONE, X86_NONE}, X86_NONE, 1, 0, 0}}, d, 0}

static const PrimaryOpCodeTableOperands modRmOperands8[256] =
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

static const PrimaryOpCodeTableOperands modRmOperands16[256] =
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

static const PrimaryOpCodeTableOperands modRmOperands32[256] =
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

#define PRIMARY_ARITHMETIC_SIB_OPERAND_ROW(scale, index) \
{X86_MEM, {X86_EAX, index}, X86_DS, 4, scale, 0}, \
{X86_MEM, {X86_ECX, index}, X86_DS, 4, scale, 0}, \
{X86_MEM, {X86_EDX, index}, X86_DS, 4, scale, 0}, \
{X86_MEM, {X86_EBX, index}, X86_DS, 4, scale, 0}, \
{X86_MEM, {X86_ESP, index}, X86_DS, 4, scale, 0}, \
{X86_MEM, {X86_NONE, index}, X86_DS, 4, scale, 0}, \
{X86_MEM, {X86_ESI, index}, X86_DS, 4, scale, 0}, \
{X86_MEM, {X86_EDI, index}, X86_DS, 4, scale, 0}

#define PRIMARY_ARITHMETIC_SIB_OPERAND_COL(scale) \
	PRIMARY_ARITHMETIC_SIB_OPERAND_ROW(scale, X86_EAX), \
	PRIMARY_ARITHMETIC_SIB_OPERAND_ROW(scale, X86_ECX), \
	PRIMARY_ARITHMETIC_SIB_OPERAND_ROW(scale, X86_EDX), \
	PRIMARY_ARITHMETIC_SIB_OPERAND_ROW(scale, X86_EBX), \
	PRIMARY_ARITHMETIC_SIB_OPERAND_ROW(scale, X86_NONE), \
	PRIMARY_ARITHMETIC_SIB_OPERAND_ROW(scale, X86_EBP), \
	PRIMARY_ARITHMETIC_SIB_OPERAND_ROW(scale, X86_ESI), \
	PRIMARY_ARITHMETIC_SIB_OPERAND_ROW(scale, X86_EDI) \

static const X86Operand sibTable[256] =
{
	PRIMARY_ARITHMETIC_SIB_OPERAND_COL(0),
	PRIMARY_ARITHMETIC_SIB_OPERAND_COL(1),
	PRIMARY_ARITHMETIC_SIB_OPERAND_COL(2),
	PRIMARY_ARITHMETIC_SIB_OPERAND_COL(3)
};


static const PrimaryOpCodeTableOperands primaryArithmeticOperands8 =
{
	{
		{X86_AL, X86_NONE, X86_NONE, X86_NONE, 1, 0, 0},
		{X86_IMMEDIATE, X86_NONE, X86_NONE, X86_NONE, 1, 0, 0}
	},

	1, 0
};

static const PrimaryOpCodeTableOperands primaryArithmeticOperands16 =
{
	{
		{X86_AX, X86_NONE, X86_NONE, X86_NONE, 2, 0, 0},
		{X86_IMMEDIATE, X86_NONE, X86_NONE, X86_NONE, 2, 0, 0}
	},

	2, 0
};

static const PrimaryOpCodeTableOperands primaryArithmeticOperands32 =
{
	{{X86_EAX, X86_NONE, X86_NONE, X86_NONE, 4, 0, 0}, {X86_IMMEDIATE, X86_NONE, X86_NONE, X86_NONE, 4, 0, 0}}, 4, 0
};

static const PrimaryOpCodeTableOperands primaryArithmeticOperands64 =
{
	{{X86_RAX, X86_NONE, X86_NONE, X86_NONE, 8, 0, 0}, {X86_IMMEDIATE, X86_NONE, X86_NONE, X86_NONE, 8, 0, 0}}, 8, 0
};

static const PrimaryOpCodeTableOperands* const primaryArithmeticImmediateOperands[4] =
{
	// 8bit
	&primaryArithmeticOperands8,

	// 16bit
	&primaryArithmeticOperands16,

	// 32bit
	&primaryArithmeticOperands32,

	// 64bit
	&primaryArithmeticOperands64,
};


static const PrimaryOpCodeTableOperands* const modRmOperands[4] =
{
	modRmOperands8, modRmOperands16, modRmOperands32, 0, // modRmOperands64
};

static const X86Operation primaryOpCodeTableArithmetic[] =
{
	X86_ADD, X86_ADC, X86_AND, X86_XOR,
	X86_OR, X86_SBB, X86_SUB, X86_CMP
};

static const PrimaryOpCodeTableOperands* modRmOpSizeXref[3] =
{
	modRmOperands8, modRmOperands16, modRmOperands32, // modRmOperands64 // TODO
};

static const uint8_t operandOrder[2][2] =
{
	{0, 1}, {1, 0}
};

static bool DecodeModRm(X86DecoderState* const state,
	const PrimaryOpCodeTableOperands* const operandTable, X86Operand* const operands)
{
	uint8_t modRm;
	const PrimaryOpCodeTableOperands* operandTableEntry;

	// Fetch the ModRM byte
	if (!state->fetch(state->ctxt, 1, (uint8_t*)&modRm))
	{
		state->instr->flags |= X86_FLAG_INSUFFICIENT_LENGTH;
		return false;
	}
	operandTableEntry = &operandTable[modRm];

	operands[1] = operandTableEntry->operands[1];
	if (operandTableEntry->sib)
	{
		uint8_t sib;
		if (!state->fetch(state->ctxt, 1, &sib))
		{
			state->instr->flags |= X86_FLAG_INSUFFICIENT_LENGTH;
			return false;
		}
		operands[0] = sibTable[sib];
	}
	else
	{
		operands[0] = operandTableEntry->operands[0];
	}

	if (operandTableEntry->dispBytes)
	{
		uint64_t displacement;
		int64_t sign;
		if (!state->fetch(state->ctxt, operandTableEntry->dispBytes, (uint8_t*)&displacement))
		{
			state->instr->flags |= X86_FLAG_INSUFFICIENT_LENGTH;
			return false;
		}

		// Now sign extend the displacement to 64bits.
		sign = (displacement << (operandTableEntry->dispBytes << 3) & 0x8000000000000000);
		operands[0].immediate = (int64_t)displacement | ((sign >> ((8 - operandTableEntry->dispBytes) << 3)));
	}

	return true;
}


static bool DecodeImmediate(X86DecoderState* const state,
	const PrimaryOpCodeTableOperands* const operandTable, X86Operand* const operands)
{
	uint64_t imm;
	int64_t sign;

	operands[0] = operandTable->operands[0];
	operands[1] = operandTable->operands[1];

	// Fetch the immediate value
	if (!state->fetch(state->ctxt, operandTable->dispBytes, (uint8_t*)&imm))
	{
		state->instr->flags |= X86_FLAG_INSUFFICIENT_LENGTH;
		return false;
	}

	// Now sign extend the immediate to 64bits.
	sign = (imm << (operandTable->dispBytes << 3) & 0x8000000000000000);
	operands[1].immediate = (int64_t)imm | ((sign >> ((8 - operandTable->dispBytes) << 3)));

	return true;
}


typedef bool (*OperandDecoderFunc)(X86DecoderState* const state,
	const PrimaryOpCodeTableOperands* const operandTable, X86Operand* const operands);

typedef bool (*PrimaryDecoder)(X86DecoderState* const state, uint8_t row, uint8_t col);

static bool DecodeInvalid(X86DecoderState* const state, uint8_t row, uint8_t col)
{
	(void)state;
	(void)row;
	(void)col;
	state->instr->op = X86_INVALID;
	return false;
}


static bool DecodePrimaryArithmetic(X86DecoderState* const state, uint8_t row, uint8_t col)
{
	static const OperandDecoderFunc opDecoders[2] = {DecodeModRm, DecodeImmediate};
	X86Operand operands[2];
	const uint8_t direction = ((col & 2) >> 1);
	const uint8_t operandForm = ((col & 4) >> 2); // IMM or MODRM
	const uint8_t operandSize = (col & 1); // 1byte or default operand size
	const PrimaryOpCodeTableOperands* operandTable;
	const PrimaryOpCodeTableOperands* const* const opXref[2] =
	{
		primaryArithmeticImmediateOperands, modRmOperands
	};

	state->instr->op = primaryOpCodeTableArithmetic[row];
	state->instr->operandCount = 2;

	operandTable = opXref[operandForm][operandSize];
	if (!opDecoders[operandForm](state, operandTable, operands))
		return false;

	state->instr->operands[direction] = operands[0];
	state->instr->operands[~direction] = operands[1];

	return true;
}


static bool DecodePushPopSegment(X86DecoderState* const state, uint8_t row, uint8_t col)
{
	static const X86Operation ops[2][2] = {{X86_PUSH, X86_POP}, {X86_PUSH, X86_INVALID}};
	static const X86Operand operands[2][2] =
	{
		{{X86_ES, {X86_NONE, X86_NONE}, X86_NONE, 2, 0, 0},
		{X86_SS, {X86_NONE, X86_NONE}, X86_NONE, 2, 0, 0}},
		{{X86_CS, {X86_NONE, X86_NONE}, X86_NONE, 2, 0, 0},
		{X86_DS, {X86_NONE, X86_NONE}, X86_NONE, 2, 0, 0}}
	};
	static const uint8_t operandSizes[3] = {2, 2, 8};

	// Docs say otherwise, but on real hardware 32bit mode does not modify
	// upper 2 bytes. 64bit mode zero extends to 8 bytes.
	state->instr->op = ops[(col >> 3) & 1][col & 1];
	state->instr->operandCount = 1;
	state->instr->operands[0] = operands[row & 1][col & 1];
	state->instr->operands[0].size = operandSizes[state->operandSize];

	return true;
}


static bool DecodeAscii(X86DecoderState* const state, uint8_t row, uint8_t col)
{
	static const X86Operation ops[2] = {X86_DAA, X86_AAA};
	state->instr->op = ops[row & 1];
	return true;
}


typedef struct RegAndSize
{
	X86OperandType reg;
	uint8_t size;
} RegAndSize;

static bool DecodeIncDec(X86DecoderState* const state, uint8_t row, uint8_t col)
{
	static const X86Operation ops[2] = {X86_INC, X86_DEC};
	static const RegAndSize operands[2][8] =
	{
		// 16bit mode
		{
			{X86_AX, 2}, {X86_CX, 2}, {X86_DX, 2}, {X86_BX, 2},
			{X86_SP, 2}, {X86_BP, 2}, {X86_SI, 2}, {X86_DI, 2}
		},

		// 32bit mode
		{
			{X86_EAX, 4}, {X86_ECX, 4}, {X86_EDX, 4}, {X86_EBX, 4},
			{X86_ESP, 4}, {X86_EBP, 4}, {X86_ESI, 4}, {X86_EDI, 4}
		}
	};
	const RegAndSize* reg = &operands[state->operandSize][row & 7];

	state->instr->op = ops[(col >> 3) & 1];
	state->instr->operandCount = 1;
	state->instr->operands[0].operandType = reg->reg;
	state->instr->operands[0].size = reg->size;

	return true;
}


static bool DecodePushPopGpr(X86DecoderState* const state, uint8_t row, uint8_t col)
{
	static const X86Operation ops[2] = {X86_PUSH, X86_POP};
	static const RegAndSize operands[2][8] =
	{
		// 16bit mode
		{
			{X86_AX, 2}, {X86_CX, 2}, {X86_DX, 2}, {X86_BX, 2},
			{X86_SP, 2}, {X86_BP, 2}, {X86_SI, 2}, {X86_DI, 2}
		},

		// 32bit mode
		{
			{X86_EAX, 4}, {X86_ECX, 4}, {X86_EDX, 4}, {X86_EBX, 4},
			{X86_ESP, 4}, {X86_EBP, 4}, {X86_ESI, 4}, {X86_EDI, 4}
		}
	};
	const RegAndSize* reg = &operands[state->operandSize][row & 7];

	state->instr->op = ops[(col >> 3) & 1];
	state->instr->operandCount = 1;
	state->instr->operands[0].operandType = reg->reg;
	state->instr->operands[0].size = reg->size;

	return true;
}


static bool DecodeJumpConditional(X86DecoderState* const state, uint8_t row, uint8_t col)
{
	static const X86Operation ops[16] =
	{
		X86_JO, X86_JNO, X86_JB, X86_JNB, X86_JZ, X86_JNZ, X86_JBE, X86_JNBE,
		X86_JS, X86_JNS, X86_JP, X86_JNP, X86_JL, X86_JNL, X86_JLE, X86_JNLE
	};
	uint8_t disp;

	state->instr->op = ops[col & 7];
	state->instr->operands[0].size = 1;

	if (!state->fetch(state->ctxt, 1, &disp))
	{
		state->instr->flags |= X86_FLAG_INSUFFICIENT_LENGTH;
		return false;
	}

	state->instr->operands[0].immediate = (int64_t)(int32_t)(int16_t)disp;

	return true;
}


static bool DecodePushPopAll(X86DecoderState* const state, uint8_t row, uint8_t col)
{
	static const X86Operation ops[3][2] = {{X86_PUSHA, X86_POPA}, {X86_PUSHA, X86_POPA}, {X86_PUSHAD, X86_POPAD}};

	state->instr->op = ops[state->mode][row & 1];
	state->instr->operandCount = 0;
	return true;
}


static bool DecodeBound(X86DecoderState* const state, uint8_t row, uint8_t col)
{
	static const X86Operation ops[3] = {X86_BOUND, X86_BOUND, X86_INVALID};
	X86Operand operands[2];
	static const uint8_t order[2] = {1, 0};
	const PrimaryOpCodeTableOperands* operandTable = modRmOpSizeXref[state->operandSize];

	state->instr->op = ops[state->mode];
	state->instr->operandCount = 2;

	if (state->instr->op == X86_INVALID)
		return false;

	if (!DecodeModRm(state, operandTable, operands))
		return false;

	// Operands are reversed. Yay Intel!
	state->instr->operands[0] = operands[1];
	state->instr->operands[1] = operands[0];

	if (state->instr->operands[1].operandType != X86_MEM)
		return false;

	return true;
}


static bool DecodeAarplMovSxd(X86DecoderState* const state, uint8_t row, uint8_t col)
{
	static const X86Operation ops[3] = {X86_ARPL, X86_ARPL, X86_MOVSXD};
	X86Operand operands[2];
	const X86DecoderMode opSize[3] = {X86_16BIT, X86_16BIT, state->operandSize};
	static const uint8_t order[3] = {0, 0, 1};

	state->instr->op = ops[state->mode];
	state->instr->operandCount = 2;

	if (!DecodeModRm(state, modRmOpSizeXref[opSize[state->mode]], operands))
		return false;

	state->instr->operands[0] = operands[order[state->mode]];
	state->instr->operands[1] = operands[~order[state->mode]];

	return true;
}


static bool DecodePushImmediate(X86DecoderState* state, uint8_t row, uint8_t col)
{
	uint64_t imm;
	int64_t sign;
	const uint8_t operandModes[3] = {state->operandSize, state->operandSize, X86_64BIT};
	static const uint8_t operandSizes[3] = {2, 4, 8};
	uint8_t operandBytes;

	state->instr->op = X86_PUSH;
	state->instr->operandCount = 1;
	state->instr->operands[0].operandType = X86_IMMEDIATE;

	operandBytes = operandSizes[operandModes[state->mode]];

	// Fetch the immediate value
	if (!state->fetch(state->ctxt, operandBytes, (uint8_t*)&imm))
	{
		state->instr->flags |= X86_FLAG_INSUFFICIENT_LENGTH;
		return false;
	}

	// Now sign extend the immediate to 64bits.
	sign = (imm << (operandBytes << 3) & 0x8000000000000000);
	state->instr->operands[0].immediate = (int64_t)imm | ((sign >> ((8 - operandBytes) << 3)));

	return true;
}


static bool DecodeGroup1(X86DecoderState* state, uint8_t row, uint8_t col)
{
	static const X86Operation group1Operations[] =
	{
		X86_ADD, X86_OR, X86_ADC, X86_SBB, X86_AND, X86_SUB, X86_XOR, X86_CMP
	};
	uint8_t modRm;
	uint8_t opBits;
	const uint8_t width = (col & 1);
	const PrimaryOpCodeTableOperands* operands;
	uint64_t imm;
	int64_t sign;
	uint8_t operandBytes;
	static const uint8_t operandSizes[2][3] =
	{
		{1, 1, 1},
		{2, 4, 8}
	};

	// Fetch the modrm byte
	if (!state->fetch(state->ctxt, 1, &modRm))
	{
		state->instr->flags |= X86_FLAG_INSUFFICIENT_LENGTH;
		return false;
	}

	opBits = ((modRm >> 3) & 7);
	state->instr->op = group1Operations[opBits];
	state->instr->operandCount = 2;

	operands = modRmOpSizeXref[state->operandSize];

	if (operands->sib)
	{
		uint8_t sib;
		if (!state->fetch(state->ctxt, 1, &sib))
		{
			state->instr->flags |= X86_FLAG_INSUFFICIENT_LENGTH;
			return false;
		}
		state->instr->operands[0] = sibTable[sib];
	}
	else
	{
		state->instr->operands[0] = operands[modRm].operands[0];
	}

	if (operands->dispBytes)
	{
		uint64_t displacement;
		int64_t sign;
		if (!state->fetch(state->ctxt, operands->dispBytes, (uint8_t*)&displacement))
		{
			state->instr->flags |= X86_FLAG_INSUFFICIENT_LENGTH;
			return false;
		}

		// Now sign extend the displacement to 64bits.
		sign = (displacement << (operands->dispBytes << 3) & 0x8000000000000000);
		state->instr->operands[0].immediate = (int64_t)displacement | ((sign >> ((8 - operands->dispBytes) << 3)));
	}

	operandBytes = operandSizes[width][state->operandSize];
	if (!state->fetch(state->ctxt, state->instr->operands[1].size, (uint8_t*)&imm))
	{
		state->instr->flags |= X86_FLAG_INSUFFICIENT_LENGTH;
		return false;
	}

	// Now sign extend the immediate to 64bits.
	sign = (imm << (operandBytes << 3) & 0x8000000000000000);
	state->instr->operands[1].immediate = (int64_t)imm | ((sign >> ((8 - operandBytes) << 3)));

	state->instr->operands[1].operandType = X86_IMMEDIATE;
	state->instr->operands[1].size = operandBytes;

	return true;
}


static bool DecodeTestXchgModRm(X86DecoderState* state, uint8_t row, uint8_t col)
{
	static const X86Operation ops[2] = {X86_TEST, X86_XCHG};
	X86Operand operands[2];
	static const uint8_t order[2] = {0, 1};
	const size_t operation = col & 1;

	state->instr->op = ops[operation];
	if (!DecodeModRm(state, modRmOpSizeXref[state->operandSize], operands))
		return false;

	state->instr->operands[0] = operands[0];
	state->instr->operands[1] = operands[1];

	return true;
}


static bool DecodeXchgRax(X86DecoderState* state, uint8_t row, uint8_t col)
{
	static const X86Operation ops[2] = {X86_XCHG, X86_NOP};
	static const X86OperandType sources[3][8] =
	{
		{X86_NONE, X86_CX, X86_DX, X86_BX, X86_SP, X86_BP, X86_SI, X86_DI},
		{X86_NONE, X86_ECX, X86_EDX, X86_EBX, X86_ESP, X86_EBP, X86_ESI, X86_EDI},
		{X86_NONE, X86_RCX, X86_RDX, X86_RBX, X86_RSP, X86_RBP, X86_RSI, X86_RDI}
	};
	static const uint8_t operandCount[8] = {0, 2, 2, 2, 2, 2, 2, 2};
	static const X86OperandType dests[3] = {X86_AX, X86_EAX, X86_RAX};
	static const uint8_t operandSizes[3] = {2, 4, 8};

	state->instr->op = ops[~col];
	state->instr->operandCount = operandCount[col];
	state->instr->operands[0].operandType = dests[state->operandSize];
	state->instr->operands[0].size = operandSizes[state->operandSize];
	state->instr->operands[0].operandType = sources[state->operandSize][col];
	state->instr->operands[1].size = operandSizes[state->operandSize];

	return true;
}


static bool DecodeMovRax(X86DecoderState* state, uint8_t row, uint8_t col)
{
	uint64_t offset;
	static const uint8_t operandSizes[2][3] =
	{
		{1, 1, 1}, // Column 0, 2
		{2, 4, 8} // Column 1, 3
	};
	static const X86OperandType rax[5] = {X86_NONE, X86_AL, X86_AX, X86_EAX, X86_RAX};
	const uint8_t opSize = operandSizes[col][state->operandSize];

	if (!state->fetch(state->ctxt, operandSizes[col & 1][state->operandSize],
		(uint8_t*)&offset))
	{
		state->instr->flags |= X86_FLAG_INSUFFICIENT_LENGTH;
		return false;
	}

	state->instr->op = X86_MOV;
	state->instr->operandCount = 2;
	state->instr->operands[operandOrder[col][0]].size = opSize;
	state->instr->operands[operandOrder[col][1]].size = opSize;

	state->instr->operands[operandOrder[col][0]].operandType = rax[opSize];
	state->instr->operands[operandOrder[col][1]].operandType = X86_MEM;
	state->instr->operands[operandOrder[col][1]].immediate = offset;

	return true;
}


static bool DecodeMovSCmpS(X86DecoderState* state, uint8_t row, uint8_t col)
{
	static const X86Operation operation[4][2] =
	{
		{X86_MOVSB, X86_CMPSB},
		{X86_MOVSW, X86_CMPSW},
		{X86_MOVSD, X86_CMPSD},
		{X86_MOVSQ, X86_CMPSQ}
	};
	static const uint8_t operandSizes[2][3] =
	{
		{1, 1, 1}, // Column 0, 2
		{2, 4, 8} // Column 1, 3
	};
	const size_t op = (col >> 2) & 1;
	const uint8_t opSize = operandSizes[col][state->operandSize];
	static const X86OperandType operands[3][2] =
	{
		{X86_SI, X86_DI},
		{X86_ESI, X86_EDI},
		{X86_RSI, X86_RDI}
	};
	static const X86OperandType segments[2] = {X86_DS, X86_ES};

	state->instr->op = operation[state->operandSize][op];
	state->instr->operandCount = 2;
	state->instr->operands[operandOrder[op][0]].size = opSize;
	state->instr->operands[operandOrder[op][1]].size = opSize;

	state->instr->operands[operandOrder[op][0]].segment = segments[0];
	state->instr->operands[operandOrder[op][0]].operandType = operands[opSize][0];
	state->instr->operands[operandOrder[op][1]].segment = segments[1];
	state->instr->operands[operandOrder[op][1]].operandType = operands[opSize][1];

	return true;
}


static bool DecodeMovImmByte(X86DecoderState* state, uint8_t row, uint8_t col)
{
	uint8_t imm;
	static const X86OperandType dests[8] =
	{
		X86_AL, X86_CL, X86_DL, X86_BL,
		X86_AH, X86_CH, X86_DH, X86_BH
	};

	if (!state->fetch(state->ctxt, 1, &imm))
	{
		state->instr->flags |= X86_FLAG_INSUFFICIENT_LENGTH;
		return false;
	}

	state->instr->operandCount = 2;
	state->instr->operands[0].size = 1;
	state->instr->operands[0].operandType = dests[col];
	state->instr->operands[1].size = 1;
	state->instr->operands[1].immediate = (int64_t)(int32_t)(int16_t)(int8_t)imm;

	return true;
}


static bool DecodeGroup2(X86DecoderState* state, uint8_t row, uint8_t col)
{
	uint8_t modRm;
	uint8_t reg;
	X86Operand operands[2];
	const PrimaryOpCodeTableOperands* operandTable;
	static const X86Operation op[8] =
	{
		X86_ROL, X86_ROR, X86_RCL, X86_RCR, X86_SHL, X86_SHR, X86_SHL, X86_SAR
	};

	// Grab the ModRM byte
	if (!state->fetch(state->ctxt, 1, &modRm))
	{
		state->instr->flags |= X86_FLAG_INSUFFICIENT_LENGTH;
		return false;
	}

	// The source operand is guaranteed to be a byte
	state->instr->operands[1].size = 1;

	// High nibble, 1 bit is clear
	if ((row & 0x10) == 0)
	{
		// Then grab the immediate
		uint8_t imm;
		if (!state->fetch(state->ctxt, 1, &imm))
		{
			state->instr->flags |= X86_FLAG_INSUFFICIENT_LENGTH;
			return false;
		}

		// The source is an immediate byte
		state->instr->operands[1].operandType = X86_IMMEDIATE;
		state->instr->operands[1].immediate = imm;
	}
	else if ((row & 0x2) == 0)
	{
		state->instr->operands[1].operandType = X86_IMMEDIATE;
		state->instr->operands[1].immediate = 1;
	}
	else
	{
		state->instr->operands[1].operandType = X86_CL;
	}

	// The destination is either a register or memory depending on the Mod bits

	// Reg field in ModRM actually selects operation for Group2
	// FIXME: SHR/SHL?
	reg = ((modRm >> 3) & 7);
	state->instr->op = op[reg];
	state->instr->operandCount = 2;

	operandTable = modRmOpSizeXref[state->operandSize];
	if (!DecodeModRm(state, operandTable, operands))
		return false;
	state->instr->operands[0] = operands[0];

	// Now the destination size
	if ((row & 1) == 0)
		state->instr->operands[0].size = 1;
	else
		state->instr->operands[0].size = state->operandSize;

	return true;
}


static bool DecodeLoadSegment(X86DecoderState* state, uint8_t row, uint8_t col)
{
	static const X86Operation op[2] = {X86_LDS, X86_LES};
	state->instr->op = op[col & 1];

	// FIXME: Operands!
	return false;
}


static bool DecodeGroup11(X86DecoderState* state, uint8_t row, uint8_t col)
{
	uint8_t opSize;
	uint64_t imm;
	const PrimaryOpCodeTableOperands* const operandTable =
		modRmOpSizeXref[state->operandSize];
	X86Operand operands[2];

	state->instr->op = X86_MOV;

	// Figure out the operand size
	if (row & 1)
		opSize = 1;
	else if (state->operandSize == 16)
		opSize = 2;
	else
		opSize = 4;

	// Fetch and initialize the destination immediate operand
	state->instr->operands[1].operandType = X86_IMMEDIATE;
	state->instr->operands[1].size = opSize;
	if (!state->fetch(state->ctxt, opSize, (uint8_t*)&imm))
	{
		state->instr->flags = X86_FLAG_INSUFFICIENT_LENGTH;
		return false;
	}

	// Figure out the destination
	if (!DecodeModRm(state, operandTable, operands))
		return false;
	state->instr->operands[0] = operands[0];

	return true;
}


static bool DecodeAsciiAdjust(X86DecoderState* state, uint8_t row, uint8_t col)
{
	static const X86Operation operation[4] = {X86_AAM, X86_AAD, X86_INVALID, X86_XLAT};
	static const X86OperandType operands[4] = {X86_IMMEDIATE, X86_IMMEDIATE, X86_NONE, X86_NONE};
	const uint8_t op = ((col >> 2) & 3);

	state->instr->op = operation[op];
	state->instr->operandCount = 1;
	state->instr->operands[0].size = 0;
	state->instr->operands[0].operandType = operands[op];

	if (op & 2)
	{
		uint8_t imm;
		if (!state->fetch(state->ctxt, 1, &imm))
		{
			state->instr->flags |= X86_FLAG_INSUFFICIENT_LENGTH;
			return false;
		}
		state->instr->operands[0].immediate = imm;
	}

	return true;
}


static const PrimaryDecoder primaryDecoders[][8] =
{
	// Row 0
	{
		DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePrimaryArithmetic,
		DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePushPopSegment, DecodePushPopSegment
	},

	// Row 1
	{
		DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePrimaryArithmetic,
		DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePushPopSegment, DecodePushPopSegment
	},

	// Row 2
	{
		DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePrimaryArithmetic,
		DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodeInvalid, DecodeAscii
	},

	// Row 3
	{
		DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePrimaryArithmetic,
		DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodeInvalid, DecodeAscii
	},

	// Row 4
	{
		DecodeIncDec, DecodeIncDec, DecodeIncDec, DecodeIncDec,
		DecodeIncDec, DecodeIncDec, DecodeIncDec, DecodeIncDec,
	},

	// Row 5
	{
		DecodePushPopGpr, DecodePushPopGpr, DecodePushPopGpr, DecodePushPopGpr,
		DecodePushPopGpr, DecodePushPopGpr, DecodePushPopGpr, DecodePushPopGpr
	},

	// Row 6
	{
		DecodePushPopAll, DecodePushPopAll, DecodeBound, DecodeAarplMovSxd,
		DecodePushImmediate, DecodeInvalid, DecodeInvalid, DecodeInvalid
	},

	// Row 7
	{
		DecodeJumpConditional, DecodeJumpConditional, DecodeJumpConditional, DecodeJumpConditional,
		DecodeJumpConditional, DecodeJumpConditional, DecodeJumpConditional, DecodeJumpConditional,
	},

	// Row 8
	{
		DecodeGroup1, DecodeGroup1, DecodeGroup1, DecodeGroup1,
		DecodeTestXchgModRm, DecodeTestXchgModRm, DecodeTestXchgModRm, DecodeTestXchgModRm
	},

	// Row 9
	{
		DecodeXchgRax, DecodeXchgRax, DecodeXchgRax, DecodeXchgRax,
		DecodeXchgRax, DecodeXchgRax, DecodeXchgRax, DecodeXchgRax
	},

	// Row 10
	{
		DecodeMovRax, DecodeMovRax, DecodeMovRax, DecodeMovRax,
		DecodeMovSCmpS, DecodeMovSCmpS, DecodeMovSCmpS, DecodeMovSCmpS
	},

	// Row 11
	{
		DecodeMovImmByte, DecodeMovImmByte, DecodeMovImmByte, DecodeMovImmByte,
		DecodeMovImmByte, DecodeMovImmByte, DecodeMovImmByte, DecodeMovImmByte
	}
};

// See Table A-1 Primary Opcode Map (One-byte Opcodes) AMD 24594_APM_v3.pdf
bool DecodePrimaryOpcodeMap(X86DecoderState* const state)
{
	uint8_t op;
	uint8_t row;
	uint8_t col;

	// Grab a byte from the machine
	if (!state->fetch(state->ctxt, 1, &op))
	{
		state->instr->flags |= X86_FLAG_INSUFFICIENT_LENGTH;
		return false;
	}

	row  = ((op >> 4) & 0xf);
	col = (op & 0xf);

	if (!primaryDecoders[row][col](state, row, col))
		return false;

	return true;
}
