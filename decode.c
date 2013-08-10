/*
	Copyright (c) 2013 Ryan Salsamendi

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
#include <memory.h>

#include "salsasm_types.h"
#include "decode.h"

typedef bool (*InstructionDecoder)(X86DecoderState* const state, uint8_t opcode);
static bool DecodeSecondaryOpCodeTable(X86DecoderState* state, uint8_t opcode);

typedef struct ModRmRmOperand
{
	const X86Operand operand;
	const uint8_t dispBytes;
	const uint8_t sib;
} ModRmRmOperand;

#define MODRM_MOD(a) (((a) >> 6) & 3)
#define MODRM_REG(a) (((a) >> 3) & 7)
#define MODRM_RM(a) ((a) & 7)

#define MODRM_RM_OPERANDS16(a, b, c, d) \
	{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 0, 0, 0}, d, 0}

static const ModRmRmOperand g_modRmRmOperands16[24] =
{
	// Mod 00
	MODRM_RM_OPERANDS16(MEM, BX, SI, 0),
	MODRM_RM_OPERANDS16(MEM, BX, DI, 0),
	MODRM_RM_OPERANDS16(MEM, BP, SI, 0),
	MODRM_RM_OPERANDS16(MEM, BP, DI, 0),
	MODRM_RM_OPERANDS16(MEM, SI, NONE, 0),
	MODRM_RM_OPERANDS16(MEM, DI, NONE, 0),
	MODRM_RM_OPERANDS16(MEM, NONE, NONE, 2),
	MODRM_RM_OPERANDS16(MEM, BX, NONE, 0),

	// Mod 01
	MODRM_RM_OPERANDS16(MEM, BX, SI, 1),
	MODRM_RM_OPERANDS16(MEM, BX, DI, 1),
	MODRM_RM_OPERANDS16(MEM, BP, SI, 1),
	MODRM_RM_OPERANDS16(MEM, BP, DI, 1),
	MODRM_RM_OPERANDS16(MEM, SI, NONE, 1),
	MODRM_RM_OPERANDS16(MEM, DI, NONE, 1),
	MODRM_RM_OPERANDS16(MEM, BP, NONE, 1),
	MODRM_RM_OPERANDS16(MEM, BX, NONE, 1),

	// Mod 10
	MODRM_RM_OPERANDS16(MEM, BX, SI, 2),
	MODRM_RM_OPERANDS16(MEM, BX, DI, 2),
	MODRM_RM_OPERANDS16(MEM, BP, SI, 2),
	MODRM_RM_OPERANDS16(MEM, BP, DI, 2),
	MODRM_RM_OPERANDS16(MEM, SI, NONE, 2),
	MODRM_RM_OPERANDS16(MEM, DI, NONE, 2),
	MODRM_RM_OPERANDS16(MEM, BP, NONE, 2),
	MODRM_RM_OPERANDS16(MEM, BX, NONE, 2),
};

#define MODRM_RM_OPERANDS32(a, b, c, d, e) \
	{{X86_ ## a, {X86_ ## b, X86_ ## c}, X86_DS, 0, 0, 0}, d, e}

static const ModRmRmOperand g_modRmRmOperands32[24] =
{
	// Mod 00
	MODRM_RM_OPERANDS32(MEM, EAX, NONE, 0, 0),
	MODRM_RM_OPERANDS32(MEM, ECX, NONE, 0, 0),
	MODRM_RM_OPERANDS32(MEM, EDX, NONE, 0, 0),
	MODRM_RM_OPERANDS32(MEM, EBX, NONE, 0, 0),
	MODRM_RM_OPERANDS32(NONE, NONE, NONE, 0, 1), // SIB
	MODRM_RM_OPERANDS32(MEM, NONE, NONE, 4, 0),
	MODRM_RM_OPERANDS32(MEM, ESI, NONE, 0, 0),
	MODRM_RM_OPERANDS32(MEM, EDI, NONE, 0, 0),

	// Mod 01
	MODRM_RM_OPERANDS32(MEM, EAX, NONE, 1, 0),
	MODRM_RM_OPERANDS32(MEM, ECX, NONE, 1, 0),
	MODRM_RM_OPERANDS32(MEM, EDX, NONE, 1, 0),
	MODRM_RM_OPERANDS32(MEM, EBX, NONE, 1, 0),
	MODRM_RM_OPERANDS32(NONE, NONE, NONE, 1, 1), // SIB
	MODRM_RM_OPERANDS32(MEM, NONE, NONE, 1, 0),
	MODRM_RM_OPERANDS32(MEM, ESI, NONE, 1, 0),
	MODRM_RM_OPERANDS32(MEM, EDI, NONE, 1, 0),

	// Mod 10
	MODRM_RM_OPERANDS32(MEM, EAX, NONE, 4, 0),
	MODRM_RM_OPERANDS32(MEM, ECX, NONE, 4, 0),
	MODRM_RM_OPERANDS32(MEM, EDX, NONE, 4, 0),
	MODRM_RM_OPERANDS32(MEM, EBX, NONE, 4, 0),
	MODRM_RM_OPERANDS32(NONE, NONE, NONE, 4, 1), // SIB
	MODRM_RM_OPERANDS32(MEM, NONE, NONE, 4, 0),
	MODRM_RM_OPERANDS32(MEM, ESI, NONE, 4, 0),
	MODRM_RM_OPERANDS32(MEM, EDI, NONE, 4, 0),
};

#define MODRM_SIB_OPERAND_ROW(scale, index) \
	{X86_MEM, {X86_EAX, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_ECX, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_EDX, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_EBX, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_ESP, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_NONE, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_ESI, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_EDI, index}, X86_DS, 4, scale, 0}

#define MODRM_SIB_OPERAND_COL(scale) \
	MODRM_SIB_OPERAND_ROW(scale, X86_EAX), \
	MODRM_SIB_OPERAND_ROW(scale, X86_ECX), \
	MODRM_SIB_OPERAND_ROW(scale, X86_EDX), \
	MODRM_SIB_OPERAND_ROW(scale, X86_EBX), \
	MODRM_SIB_OPERAND_ROW(scale, X86_NONE), \
	MODRM_SIB_OPERAND_ROW(scale, X86_EBP), \
	MODRM_SIB_OPERAND_ROW(scale, X86_ESI), \
	MODRM_SIB_OPERAND_ROW(scale, X86_EDI) \

static const X86Operand g_sibTable[256] =
{
	MODRM_SIB_OPERAND_COL(0),
	MODRM_SIB_OPERAND_COL(1),
	MODRM_SIB_OPERAND_COL(2),
	MODRM_SIB_OPERAND_COL(3)
};

static const ModRmRmOperand* const g_modRmRmOperands[4] =
{
	g_modRmRmOperands16, g_modRmRmOperands32, g_modRmRmOperands32
};

static const uint8_t g_operandOrder[2][2] = {{0, 1}, {1, 0}};
static const uint8_t g_decoderModeSizeXref[3] = {2, 4, 8};
static const uint8_t g_decoderModeSimdSizeXref[4] = {8, 16, 32, 64};

static const X86OperandType g_gpr8[16] =
{
	X86_AL, X86_CL, X86_DL, X86_BL, X86_AH, X86_CH, X86_DH, X86_BH,
	X86_R8B, X86_R9B, X86_R10B, X86_R11B, X86_R12B, X86_R13B, X86_R14B, X86_R15B
};

static const X86OperandType g_gpr16[16] =
{
	X86_AX, X86_CX, X86_DX, X86_BX, X86_SP, X86_BP, X86_SI, X86_DI,
	X86_R9W, X86_R10W, X86_R11W, X86_R12W, X86_R13W, X86_R14W, X86_R15W
};

static const X86OperandType g_gpr32[16] =
{
	X86_EAX, X86_ECX, X86_EDX, X86_EBX, X86_ESP, X86_EBP, X86_ESI, X86_EDI,
	X86_R9D, X86_R10D, X86_R11D, X86_R12D, X86_R13D, X86_R14D, X86_R15D
};

static const X86OperandType g_gpr64[16] =
{
	X86_RAX, X86_RCX, X86_RDX, X86_RBX, X86_RSP, X86_RBP, X86_RSI, X86_RDI,
	X86_R9, X86_R10, X86_R11, X86_R12, X86_R13, X86_R14, X86_R15
};

static const X86OperandType* const g_gprOperandTypes[4] = {g_gpr8, g_gpr16, g_gpr32, g_gpr64};

static const X86OperandType g_mmOperandTypes[8] =
{
	X86_MM0, X86_MM1, X86_MM2, X86_MM3, X86_MM4, X86_MM5, X86_MM6, X86_MM7,
};

static const X86OperandType g_xmmOperandTypes[16] =
{
	X86_XMM0, X86_XMM1, X86_XMM2, X86_XMM3, X86_XMM4, X86_XMM5, X86_XMM6, X86_XMM7,
	X86_XMM8, X86_XMM9, X86_XMM10, X86_XMM11, X86_XMM12, X86_XMM13, X86_XMM14, X86_XMM15
};

static const X86OperandType g_ymmOperandTypes[16] =
{
	X86_YMM0, X86_YMM1, X86_YMM2, X86_YMM3, X86_YMM4, X86_YMM5, X86_YMM6, X86_YMM7,
	X86_YMM8, X86_YMM9, X86_YMM10, X86_YMM11, X86_YMM12, X86_YMM13, X86_YMM14, X86_YMM15
};

static const X86OperandType g_zmmOperandTypes[16] =
{
	X86_ZMM0, X86_ZMM1, X86_ZMM2, X86_ZMM3, X86_ZMM4, X86_ZMM5, X86_ZMM6, X86_ZMM7,
	X86_ZMM8, X86_ZMM9, X86_ZMM10, X86_ZMM11, X86_ZMM12, X86_ZMM13, X86_ZMM14, X86_ZMM15
};

static const X86OperandType* const g_simdOperandTypes[4] =
{
	g_mmOperandTypes, g_xmmOperandTypes, g_ymmOperandTypes, g_zmmOperandTypes
};

static const X86OperandType g_fpSources[8] =
{
	X86_ST0, X86_ST1, X86_ST2, X86_ST3,
	X86_ST4, X86_ST5, X86_ST6, X86_ST7
};


static __inline bool Fetch(X86DecoderState* const state, size_t len, uint8_t* result)
{
	if (!state->fetch(state->ctxt, len, result))
	{
		state->instr->flags |= X86_FLAG_INSUFFICIENT_LENGTH;
		return false;
	}
	state->instr->length += len;
	return true;
}


static __inline bool IsModRmRmFieldReg(uint8_t modRm)
{
	if ((modRm & 0xc0) == 0xc0)
		return true;
	return false;
}


static __inline bool DecodeModRmRmFieldReg(X86DecoderState* const state, uint8_t operandSize,
		X86Operand* const operand, uint8_t modRm)
{
	const uint8_t rm = modRm & 7;
	operand->operandType = g_gprOperandTypes[operandSize >> 1][rm];
	operand->size = operandSize;
	return true;
}


static __inline bool DecodeModRmRmFieldMemory(X86DecoderState* const state, uint8_t operandSize,
		X86Operand* const operand, uint8_t modRm)
{
	const size_t operandTableIndex = (((modRm >> 3) &  0x18) | (modRm & 7));
	const ModRmRmOperand* operandTableEntry = &g_modRmRmOperands[state->mode][operandTableIndex];

	if (operandTableEntry->sib)
	{
		uint8_t sib;
		if (!Fetch(state, 1, &sib))
			return false;
		memcpy(operand, &g_sibTable[sib], sizeof(X86Operand));
	}
	else
	{
		memcpy(operand, &operandTableEntry->operand, sizeof(X86Operand));
	}
	operand->size = operandSize;

	if (operandTableEntry->dispBytes)
	{
		uint64_t displacement;

		displacement = 0;
		if (!Fetch(state, operandTableEntry->dispBytes, (uint8_t*)&displacement))
			return false;

		// Now sign extend the displacement to 64bits.
		operand->immediate = SIGN_EXTEND64(displacement, operandTableEntry->dispBytes);
	}

	return true;
}


static __inline bool DecodeModRmRmField(X86DecoderState* const state, uint8_t operandSize,
		X86Operand* const operand, uint8_t modRm)
{
	if (IsModRmRmFieldReg(modRm))
		return DecodeModRmRmFieldReg(state, operandSize, operand, modRm);

	return DecodeModRmRmFieldMemory(state, operandSize, operand, modRm);
}


static __inline void DecodeModRmRegField(X86DecoderState* const state, uint8_t operandSize,
	X86Operand* const operand, uint8_t modRm)
{
	const uint8_t reg = (modRm >> 3) & 7;
	operand->operandType = g_gprOperandTypes[operandSize >> 1][reg];
	operand->size = operandSize;
}


static __inline bool DecodeModRm(X86DecoderState* const state, uint8_t operandSize, X86Operand* const operands)
{
	uint8_t modRm;

	// Fetch the ModRM byte
	if (!Fetch(state, 1, (uint8_t*)&modRm))
		return false;

	if (!DecodeModRmRmField(state, operandSize, &operands[0], modRm))
		return false;

	DecodeModRmRegField(state, operandSize, &operands[1], modRm);

	return true;
}


static __inline bool DecodeImmediate(X86DecoderState* const state, X86Operand* const operand, uint8_t operandSize)
{
	uint64_t imm;

	// Fetch the immediate value
	imm = 0;
	if (!Fetch(state, operandSize, (uint8_t*)&imm))
		return false;

	// Now sign extend the immediate to 64bits.
	operand->immediate = SIGN_EXTEND64(imm, operandSize);
	operand->operandType = X86_IMMEDIATE;
	operand->size = operandSize;

	return true;
}


static bool DecodeInvalid(X86DecoderState* const state, uint8_t opcode)
{
	(void)state;
	(void)opcode;
	state->instr->op = X86_INVALID;
	return false;
}


static bool DecodePrimaryArithmetic(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation primaryOpCodeTableArithmetic[] =
	{
		X86_ADD, X86_ADC, X86_AND, X86_XOR,
		X86_OR, X86_SBB, X86_SUB, X86_CMP
	};
	const uint8_t operandSizes[2] = {1, g_decoderModeSizeXref[state->operandMode]};
	X86Operand operands[2] = {0};
	const uint8_t direction = ((opcode & 2) >> 1);
	const uint8_t operandSizeBit = (opcode & 1); // 1byte or default operand size
	const size_t operation = ((opcode & 0x8) >> 1) | ((opcode >> 4) & 7);
	const uint8_t operandSize = operandSizes[operandSizeBit];
	const uint8_t operand0 = direction;
	const uint8_t operand1 = ((~direction) & 1);

	state->instr->op = primaryOpCodeTableArithmetic[operation];
	state->instr->operandCount = 2;

	if (!DecodeModRm(state, operandSize, operands))
		return false;

	state->instr->operands[operand0] = operands[0];
	state->instr->operands[operand1] = operands[1];

	return true;
}


static bool DecodePrimaryArithmeticImm(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation primaryOpCodeTableArithmetic[] =
	{
		X86_ADD, X86_ADC, X86_AND, X86_XOR,
		X86_OR, X86_SBB, X86_SUB, X86_CMP
	};
	const uint8_t operandSizes[2] = {1, g_decoderModeSizeXref[state->operandMode]};
	const uint8_t operandSizeBit = (opcode & 1); // 1byte or default operand size
	const size_t operation = ((opcode & 0x8) >> 1) | ((opcode >> 4) & 7);
	const uint8_t operandSize = operandSizes[operandSizeBit];
	const X86OperandType dest = g_gprOperandTypes[operandSize >> 1][0];

	if (!DecodeImmediate(state, &state->instr->operands[1], operandSize))
		return false;

	state->instr->op = primaryOpCodeTableArithmetic[operation];
	state->instr->operandCount = 2;
	state->instr->operands[0].operandType = dest;
	state->instr->operands[0].size = operandSize;

	return true;
}


static bool DecodePushPopSegment(X86DecoderState* const state, uint8_t opcode)
{
	// NAB: The secondary op code map escape (0F) should never get here.
	static const X86Operation ops[2] = {X86_PUSH, X86_POP};
	static const X86OperandType operands[2][2] = {{X86_ES, X86_SS}, {X86_CS, X86_DS}};
	const size_t operandSelector = ((opcode & 0xf) >> 3);

	// Docs say otherwise, but on real hardware 32bit mode does not modify
	// upper 2 bytes. 64bit mode zero extends to 8 bytes.
	static const uint8_t operandSizes[3] = {2, 2, 8};

	state->instr->op = ops[opcode & 1];
	state->instr->operandCount = 1;
	state->instr->operands[0].operandType = operands[operandSelector][(opcode >> 4) & 1];
	state->instr->operands[0].size = operandSizes[state->operandMode];

	return true;
}


static bool DecodeAscii(X86DecoderState* const state, uint8_t opcode)
{
	const size_t opCol = (opcode >> 3) & 1;
	static const X86Operation ops[2][2] = {{X86_DAA, X86_AAA}, {X86_DAS, X86_AAS}};
	state->instr->op = ops[opCol][(opcode >> 4) & 1];
	return true;
}


static bool DecodeIncDec(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation ops[2] = {X86_INC, X86_DEC};
	const size_t operation = (opcode >> 3) & 1;
	const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];

	if (state->mode == X86_64BIT)
	{
		state->instr->flags |= X86_FLAG_INVALID_64BIT_MODE;
		return false;
	}

	state->instr->op = ops[operation];
	state->instr->operandCount = 1;
	state->instr->operands[0].operandType = g_gprOperandTypes[operandSize >> 1][opcode & 7];
	state->instr->operands[0].size = operandSize;

	return true;
}


static bool DecodePushPopGpr(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation ops[2] = {X86_PUSH, X86_POP};
	const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];

	// FIXME: REX prefix selects extended GPRs.
	state->instr->op = ops[(opcode >> 3) & 1];
	state->instr->operandCount = 1;
	state->instr->operands[0].operandType = g_gprOperandTypes[operandSize >> 1][opcode & 7];
	state->instr->operands[0].size = operandSize;

	return true;
}


static bool DecodeJumpConditional(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation ops[16] =
	{
		X86_JO, X86_JNO, X86_JB, X86_JNB, X86_JZ, X86_JNZ, X86_JBE, X86_JNBE,
		X86_JS, X86_JNS, X86_JP, X86_JNP, X86_JL, X86_JNL, X86_JLE, X86_JNLE
	};
	uint8_t disp;

	state->instr->op = ops[opcode & 0xf];
	state->instr->operands[0].size = 1;

	// Grab the displacement byte
	if (!Fetch(state, 1, &disp))
		return false;

	// Sign extend to 64 bit
	state->instr->operands[0].immediate = SIGN_EXTEND64(disp, 1);

	return true;
}


static bool DecodePushPopAll(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation ops[3][2] = {{X86_PUSHA, X86_POPA}, {X86_PUSHA, X86_POPA}, {X86_PUSHAD, X86_POPAD}};

	state->instr->op = ops[state->mode][opcode & 1];
	state->instr->operandCount = 0;
	return true;
}


static bool DecodeBound(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation ops[3] = {X86_BOUND, X86_BOUND, X86_INVALID};
	X86Operand operands[2] = {0};
	const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];

	state->instr->op = ops[state->mode];
	state->instr->operandCount = 2;

	if (state->instr->op == X86_INVALID)
		return false;

	if (!DecodeModRm(state, operandSize, operands))
		return false;

	// Operands are reversed. Yay Intel!
	state->instr->operands[0] = operands[1];
	state->instr->operands[1] = operands[0];

	if (state->instr->operands[1].operandType != X86_MEM)
		return false;

	return true;
}


static bool DecodeAarplMovSxd(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation ops[3] = {X86_ARPL, X86_ARPL, X86_MOVSXD};
	X86Operand operands[2] = {0};
	const uint8_t opSize[3] = {2, 2, g_decoderModeSizeXref[state->operandMode]};
	static const uint8_t order[3] = {0, 0, 1};
	const size_t operand0 = order[state->mode];
	const size_t operand1 = ((~order[state->mode]) & 1);

	state->instr->op = ops[state->mode];
	state->instr->operandCount = 2;

	if (!DecodeModRm(state, opSize[state->mode], operands))
		return false;

	state->instr->operands[0] = operands[operand0];
	state->instr->operands[1] = operands[operand1];

	return true;
}


static bool DecodePushImmediate(X86DecoderState* state, uint8_t opcode)
{
	uint64_t imm;
	static const uint8_t operandModes[3] = {2, 4, 4};
	const uint8_t operandSizes[2] = {operandModes[state->operandMode], 1};
	const uint8_t operandBytes = operandSizes[(opcode >> 1) & 1];

	// Fetch the immediate value
	imm = 0;
	if (!Fetch(state, operandBytes, (uint8_t*)&imm))
		return false;

	state->instr->op = X86_PUSH;
	state->instr->operandCount = 1;

	// Now sign extend the immediate to 64bits.
	state->instr->operands[0].operandType = X86_IMMEDIATE;
	state->instr->operands[0].immediate = SIGN_EXTEND64(imm, operandBytes);
	state->instr->operands[0].size = operandBytes;

	return true;
}


static bool DecodeGroup1(X86DecoderState* state, uint8_t opcode)
{
	static const X86Operation group1Operations[] =
	{
		X86_ADD, X86_OR, X86_ADC, X86_SBB, X86_AND, X86_SUB, X86_XOR, X86_CMP
	};
	uint8_t modRm;
	uint8_t reg;
	const uint8_t width = (opcode & 1);
	static const uint8_t operandSizes[2][3] =
	{
		{1, 1, 1},
		{2, 4, 8}
	};
	const uint8_t operandSize = operandSizes[width][state->operandMode];

	// Fetch the modrm byte
	if (!Fetch(state, 1, &modRm))
		return false;
	reg = ((modRm >> 3) & 7);

	if (!DecodeModRmRmField(state, operandSize, &state->instr->operands[0], modRm))
		return false;

	// Operation is encoded in the reg field
	state->instr->op = group1Operations[reg];
	state->instr->operandCount = 2;

	// Fetch and decode the source
	if (!DecodeImmediate(state, &state->instr->operands[1], operandSize))
		return false;

	return true;
}


static bool DecodeTestXchgModRm(X86DecoderState* state, uint8_t opcode)
{
	static const X86Operation ops[2] = {X86_TEST, X86_XCHG};
	X86Operand operands[2] = {0};
	const size_t operation = ((opcode >> 1) & 1);
	const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];

	if (!DecodeModRm(state, operandSize, operands))
		return false;

	state->instr->op = ops[operation];
	state->instr->operands[0] = operands[0];
	state->instr->operands[1] = operands[1];

	return true;
}


static bool DecodeNop(X86DecoderState* state, uint8_t opcode)
{
	(void)opcode;
	state->instr->op = X86_NOP;
	return true;
}


static bool DecodeXchgRax(X86DecoderState* state, uint8_t opcode)
{
	static const X86OperandType sources[3] = {X86_AX, X86_EAX, X86_RAX};
	const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];
	const uint8_t operandSel = opcode & 0xf;

	state->instr->op = X86_XCHG;
	state->instr->operandCount = 2;

	state->instr->operands[0].operandType = g_gprOperandTypes[operandSize >> 1][operandSel];
	state->instr->operands[0].size = operandSize;

	state->instr->operands[1].operandType = sources[state->operandMode];
	state->instr->operands[1].size = operandSize;

	return true;
}


static bool DecodeMovOffset(X86DecoderState* state, uint8_t opcode)
{
	uint64_t offset;
	const uint8_t operandSizes[2] = {1, g_decoderModeSizeXref[state->operandMode]};
	const uint8_t sizeBit = opcode & 1;
	const uint8_t orderBit = (opcode >> 1) & 1;
	static const X86OperandType rax[5] = {X86_AL, X86_AX, X86_EAX, X86_RAX};
	const uint8_t operandSize = operandSizes[sizeBit];
	const uint8_t offsetSize = g_decoderModeSizeXref[state->mode];
	const uint8_t operand0 = g_operandOrder[orderBit][0];
	const uint8_t operand1 = g_operandOrder[orderBit][1];

	offset = 0;
	if (!Fetch(state, offsetSize, (uint8_t*)&offset))
		return false;

	state->instr->op = X86_MOV;
	state->instr->operandCount = 2;
	state->instr->operands[operand0].size = operandSize;
	state->instr->operands[operand1].size = operandSize;

	state->instr->operands[operand0].operandType = rax[operandSize >> 1];
	state->instr->operands[operand1].operandType = X86_MEM;
	state->instr->operands[operand1].immediate = offset;

	return true;
}


static bool DecodeMovCmpString(X86DecoderState* state, uint8_t opcode)
{
	static const X86Operation operations[4][2] =
	{
		{X86_MOVSB, X86_CMPSB},
		{X86_MOVSW, X86_CMPSW},
		{X86_MOVSD, X86_CMPSD},
		{X86_MOVSQ, X86_CMPSQ}
	};
	const uint8_t operandSizes[2] = {1, g_decoderModeSizeXref[state->operandMode]};
	const size_t op = (opcode >> 1) & 1;
	const uint8_t opSize = operandSizes[opcode & 1];
	static const X86OperandType operands[3][2] =
	{
		{X86_SI, X86_DI},
		{X86_ESI, X86_EDI},
		{X86_RSI, X86_RDI}
	};
	static const X86OperandType segments[2] = {X86_DS, X86_ES};
	const X86Operation operation = operations[opSize >> 1][op];
	const uint8_t operand0 = g_operandOrder[op][0];
	const uint8_t operand1 = g_operandOrder[op][1];

	state->instr->op = operation;
	state->instr->operandCount = 2;
	state->instr->operands[operand0].size = opSize;
	state->instr->operands[operand1].size = opSize;

	state->instr->operands[operand0].segment = segments[0];
	state->instr->operands[operand0].operandType = operands[opSize][0];
	state->instr->operands[operand1].segment = segments[1];
	state->instr->operands[operand1].operandType = operands[opSize][1];

	return true;
}


static bool DecodeGroup2(X86DecoderState* state, uint8_t opcode)
{
	uint8_t modRm;
	uint8_t reg;
	X86Operand operands[2] = {0};
	const uint8_t operandSizes[2] = {1, g_decoderModeSizeXref[state->operandMode]};
	const uint8_t operandSizeBit = opcode & 1;
	static const X86Operation op[8] =
	{
		X86_ROL, X86_ROR, X86_RCL, X86_RCR, X86_SHL, X86_SHR, X86_SHL, X86_SAR
	};
	const uint8_t operandSize = operandSizes[operandSizeBit];

	// Grab the ModRM byte
	if (!Fetch(state, 1, &modRm))
		return false;

	// The source operand is guaranteed to be a byte
	state->instr->operands[1].size = 1;

	// High nibble, 1 bit is clear
	if ((opcode & 0x10) == 0)
	{
		// Then grab the immediate
		uint8_t imm;
		if (!Fetch(state, 1, &imm))
			return false;

		// The source is an immediate byte
		state->instr->operands[1].operandType = X86_IMMEDIATE;
		state->instr->operands[1].immediate = imm;
	}
	else if ((opcode & 2) == 0)
	{
		state->instr->operands[1].operandType = X86_IMMEDIATE;
		state->instr->operands[1].immediate = 1;
	}
	else
	{
		state->instr->operands[1].operandType = X86_CL;
	}

	// Reg field in ModRM actually selects operation for Group2
	reg = MODRM_REG(modRm);
	state->instr->op = op[reg];
	state->instr->operandCount = 2;

	// The destination is either a register or memory depending on the Mod bits
	if (!DecodeModRmRmField(state, operandSize, operands, modRm))
		return false;
	state->instr->operands[0] = operands[0];
	state->instr->operands[0].size = operandSize;

	return true;
}


static bool DecodeLoadSegment(X86DecoderState* state, uint8_t opcode)
{
	const uint8_t size = g_decoderModeSizeXref[state->mode];
	static const X86Operation operations[2] = {X86_LDS, X86_LES};
	static const X86OperandType dests[2] = {X86_DS, X86_ES};
	const uint8_t op = opcode & 1;
	const uint8_t operandSize = size + 2;
	uint8_t modRm;

	// First grab the ModRM byte
	if (!Fetch(state, 1, &modRm))
		return false;

	// A GPR source is invalid here.
	if (IsModRmRmFieldReg(modRm))
		return false;

	// Figure out the source
	if (!DecodeModRmRmFieldMemory(state, size, &state->instr->operands[1], modRm))
		return false;
	state->instr->operands[1].size = operandSize;

	// Now the destination
	state->instr->operands[0].size = operandSize;
	state->instr->operands[0].operandType = dests[op];

	state->instr->operandCount = 2;
	state->instr->op = operations[op];

	return true;
}


static bool DecodeGroup11(X86DecoderState* state, uint8_t opcode)
{
	const uint8_t sizeBit = ((opcode & 0x10) >> 4);
	static const uint8_t operandSizes[2][3] = {{1, 1, 1}, {2, 4, 8}};
	const uint8_t operandSize = operandSizes[sizeBit][state->operandMode];
	X86Operand operands[2] = {0};
	uint64_t imm;

	imm = 0;
	if (!Fetch(state, operandSize, (uint8_t*)&imm))
		return false;

	// Figure out the destination
	if (!DecodeModRm(state, operandSize, operands))
		return false;
	state->instr->operands[0] = operands[0];

	state->instr->op = X86_MOV;

	// Fetch and initialize the destination immediate operand
	state->instr->operands[1].operandType = X86_IMMEDIATE;
	state->instr->operands[1].size = operandSize;

	return true;
}


static bool DecodeAsciiAdjust(X86DecoderState* state, uint8_t opcode)
{
	static const X86Operation operation[4] = {X86_AAM, X86_AAD};
	static const X86OperandType operands[4] = {X86_IMMEDIATE, X86_IMMEDIATE};
	const uint8_t op = (opcode & 1);
	uint8_t imm;

	if (!Fetch(state, 1, &imm))
		return false;

	state->instr->operands[0].operandType = operands[op];
	state->instr->operands[0].immediate = imm;
	state->instr->operands[0].size = 1;

	state->instr->op = operation[op];
	state->instr->operandCount = 1;

	return true;
}


static bool DecodeXlat(X86DecoderState* state, uint8_t opcode)
{
	static const X86OperandType sources[3] = {X86_BX, X86_EBX, X86_RBX};
	const X86OperandType source = sources[state->mode];

	state->instr->op = X86_XLAT;
	state->instr->operandCount = 2;

	// Store in AL
	state->instr->operands[0].operandType = X86_AL;
	state->instr->operands[0].size = 1;

	// Value fetched from memory
	state->instr->operands[1].operandType = X86_MEM;
	state->instr->operands[1].size = 1;
	state->instr->operands[1].segment = X86_DS;
	state->instr->operands[1].components[0] = X86_AL;
	state->instr->operands[1].components[1] = source;

	return true;
}


static bool DecodeFPArithmetic(X86DecoderState* state, uint8_t opcode)
{
	static const X86Operation operations[8] =
	{
		X86_FADD, X86_FMUL, X86_FCOM, X86_FCOMP,
		X86_FSUB, X86_FSUBR, X86_FDIV, X86_FDIVR
	};
	uint8_t modRm;
	uint8_t reg;

	if (!Fetch(state, 1, &modRm))
		return false;

	if (!IsModRmRmFieldReg(modRm))
	{
		const uint8_t sizeBit = (opcode >> 2) & 1;
		static const uint8_t operandSizes[2] = {4, 8};

		// Memory!
		if (!DecodeModRmRmFieldMemory(state, 4, &state->instr->operands[1], modRm))
			return false;

		state->instr->operands[1].size = operandSizes[sizeBit];
		state->instr->operands[0].size = operandSizes[sizeBit];
	}
	else
	{
		const uint8_t rm = MODRM_RM(modRm);
		state->instr->operands[1].operandType = g_fpSources[rm];
		state->instr->operands[1].size = 4;
	}

	state->instr->operands[0].operandType = X86_ST0;
	state->instr->operands[0].size = 10;

	reg = MODRM_REG(modRm);
	state->instr->op = operations[reg];
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeFPLoadStore(X86DecoderState* state, uint8_t opcode)
{
	uint8_t modRm;
	uint8_t reg;

	if (!Fetch(state, 1, &modRm))
		return false;

	reg = MODRM_REG(modRm);
	if (!IsModRmRmFieldReg(modRm))
	{
		static const X86Operation operations[8] =
		{
			X86_FLD, X86_INVALID, X86_FST, X86_FSTP,
			X86_FLDENV, X86_FLDCW, X86_FNSTENV, X86_FNSTCW
		};
		const uint8_t operandSizes[8] =
		{
			4, 0, 4, 4,
			g_decoderModeSizeXref[state->mode] * 7, 2,
			g_decoderModeSizeXref[state->mode] * 7, 2
		};

		// Memory!
		if (!DecodeModRmRmFieldMemory(state, 4, &state->instr->operands[1], modRm))
			return false;

		state->instr->operands[1].size = operandSizes[reg];

		state->instr->op = operations[reg];
		state->instr->operandCount = 2;
	}
	else if (reg < 2)
	{
		static const X86Operation operations[2] = {X86_FLD, X86_FXCH};
		const uint8_t rm = MODRM_RM(modRm);

		state->instr->operands[1].operandType = g_fpSources[rm];
		state->instr->operands[1].size = 10;

		state->instr->op = operations[reg];
		state->instr->operandCount = 2;
	}
	else
	{
		const uint8_t rm = MODRM_RM(modRm);
		static const X86Operation operations[8][6] =
		{
			{X86_FNOP, X86_INVALID, X86_FCHS, X86_FLD1, X86_F2XM1, X86_FPREM}, // c0
			{X86_INVALID, X86_INVALID, X86_FABS, X86_FLDL2T, X86_FYL2X, X86_FYL2XP1}, // c1
			{X86_INVALID, X86_INVALID, X86_INVALID, X86_FLDL2E, X86_FPTAN, X86_FSQRT}, // c2
			{X86_INVALID, X86_INVALID, X86_INVALID, X86_FLDPI, X86_FPATAN, X86_FSINCOS}, // c3
			{X86_INVALID, X86_INVALID, X86_FTST, X86_FLDLG2, X86_FXTRACT, X86_FRNDINT}, // c4
			{X86_INVALID, X86_INVALID, X86_FXAM, X86_FLDLN2, X86_FPREM1, X86_FSCALE}, // c5
			{X86_INVALID, X86_INVALID, X86_INVALID, X86_FLDZ, X86_FDECSTP, X86_FSIN}, // c6
			{X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID, X86_FINCSTP, X86_FCOS} // c7
		};

		state->instr->op = operations[rm][reg - 2];

		// ffnop really has no args.
		if (state->instr->op == X86_FNOP)
			return true;

		state->instr->operandCount = 1;
	}

	state->instr->operands[0].operandType = X86_ST0;
	state->instr->operands[0].size = 10;

	return true;
}


static bool DecodeFPMovConditional(X86DecoderState* state, uint8_t opcode)
{
	uint8_t modRm;
	uint8_t reg;

	if (!Fetch(state, 1, &modRm))
		return false;

	reg = MODRM_REG(modRm);
	if (!IsModRmRmFieldReg(modRm))
	{
		static const X86Operation operations[8] =
		{
			X86_FIADD, X86_FIMUL, X86_FICOM, X86_FICOMP,
			X86_FISUB, X86_FISUBR, X86_FIDIV, X86_FIDIVR
		};

		// Memory!
		if (!DecodeModRmRmFieldMemory(state, 4, &state->instr->operands[1], modRm))
			return false;
		state->instr->operands[1].size = 4;

		state->instr->operandCount = 2;
		state->instr->op = operations[reg];
	}
	else if (modRm != 0xe9)
	{
		const uint8_t rm = MODRM_RM(modRm);
		static const X86Operation operations[4] =
		{
			X86_FCMOVB, X86_FCMOVE, X86_FCMOVBE, X86_FCMOVU
		};

		if (reg > 3)
			return false;

		state->instr->op = operations[reg];
		state->instr->operandCount = 2;

		state->instr->operands[1].operandType = g_fpSources[rm];
		state->instr->operands[1].size = 10;
	}
	else
	{
		state->instr->op = X86_FUCOMPP;
	}

	state->instr->operands[0].operandType = X86_ST0;
	state->instr->operands[0].size = 10;

	return true;
}


static bool DecodeFPMovNegConditional(X86DecoderState* state, uint8_t opcode)
{
	uint8_t modRm;
	uint8_t reg;

	if (!Fetch(state, 1, &modRm))
		return false;

	reg = MODRM_REG(modRm);
	if (!IsModRmRmFieldReg(modRm))
	{
		static const X86Operation operations[8] =
		{
			X86_FILD, X86_FISTTP, X86_FIST, X86_FISTP,
			X86_INVALID, X86_FLD, X86_INVALID, X86_FSTP
		};
		static const uint8_t operandSizes[8] =
		{
			4, 4, 4, 4,
			0, 10, 0, 10
		};

		// Memory!
		if (!DecodeModRmRmFieldMemory(state, 4, &state->instr->operands[1], modRm))
			return false;
		state->instr->operands[1].size = operandSizes[reg];

		state->instr->operands[0].operandType = X86_ST0;
		state->instr->operands[0].size = 10;

		state->instr->operandCount = 2;
		state->instr->op = operations[reg];
	}
	else if ((modRm != 0xe2) && (modRm != 0xe3))
	{
		const uint8_t rm = MODRM_RM(modRm);
		static const X86Operation operations[8] =
		{
			X86_FCMOVNB, X86_FCMOVNE, X86_FCMOVNBE, X86_FCMOVNU,
			X86_INVALID, X86_FUCOMI, X86_FCOMI, X86_INVALID
		};

		state->instr->operands[1].operandType = g_fpSources[rm];
		state->instr->operands[1].size = 10;

		state->instr->operands[0].operandType = X86_ST0;
		state->instr->operands[0].size = 10;

		state->instr->op = operations[reg];
		state->instr->operandCount = 2;

	}
	else
	{
		static const X86Operation operations[2] = {X86_FNCLEX, X86_FNINIT};
		const uint8_t opBit = modRm & 1;
		state->instr->op = operations[opBit];
	}

	return true;
}


static bool DecodeFPFreeStore(X86DecoderState* state, uint8_t opcode)
{
	uint8_t modRm;
	uint8_t reg;

	if (!Fetch(state, 1, &modRm))
		return false;

	reg = MODRM_REG(modRm);
	if (!IsModRmRmFieldReg(modRm))
	{
		static const X86Operation operations[8] =
		{
			X86_FLD, X86_FISTTP, X86_FST, X86_FSTP,
			X86_FRSTOR, X86_INVALID, X86_FNSAVE, X86_FNSTSW
		};
		static const uint8_t operandSizes[8] =
		{
			8, 8, 8, 8,
			0, 0, 0, 2 // FRSTOR and FNSAVE sizes depend on CPU state
		};
		X86Operand operand = {0};

		// Memory!
		if (!DecodeModRmRmFieldMemory(state, 4, &operand, modRm))
			return false;

		state->instr->op = operations[reg];
		if (reg < 4)
		{
			state->instr->operands[1] = operand;
			state->instr->operands[1].size = operandSizes[reg];
		}
		else
		{
			state->instr->operands[0] = operand;
			state->instr->operands[0].size = operandSizes[reg];
			state->instr->operandCount = 1;
			return true;
		}
	}
	else
	{
		const uint8_t rm = MODRM_RM(modRm);
		static const X86Operation operations[8] =
		{
			X86_FFREE, X86_INVALID, X86_FST, X86_FSTP,
			X86_FUCOM, X86_FUCOMP, X86_INVALID, X86_INVALID
		};

		state->instr->op = operations[reg];
		if (state->instr->op == X86_FUCOM)
		{
			state->instr->operands[1].operandType = g_fpSources[rm];
			state->instr->operands[1].size = 10;
		}
		else
		{
			state->instr->operands[0].operandType = g_fpSources[rm];
			state->instr->operands[0].size = 10;
			state->instr->operandCount = 1;
			return true;
		}
	}

	state->instr->operands[0].operandType = X86_ST0;
	state->instr->operands[0].size = 10;

	state->instr->operandCount = 2;

	return true;
}


static bool DecodeFPArithmeticPop(X86DecoderState* state, uint8_t opcode)
{
	uint8_t modRm;
	uint8_t reg;

	if (!Fetch(state, 1, &modRm))
		return false;

	reg = MODRM_REG(modRm);
	if (!IsModRmRmFieldReg(modRm))
	{
		static const X86Operation operations[8] =
		{
			X86_FIADD, X86_FIMUL, X86_FICOM, X86_FICOMP,
			X86_FISUB, X86_FISUBR, X86_FIDIV, X86_FIDIVR
		};

		// Memory!
		if (!DecodeModRmRmFieldMemory(state, 4, &state->instr->operands[1], modRm))
			return false;

		state->instr->operands[1].size = 2;
		state->instr->op = operations[reg];
	}
	else if (modRm != 0xd9)
	{
		static const X86Operation operations[8] =
		{
			X86_FADDP, X86_FMULP, X86_INVALID, X86_INVALID,
			X86_FSUBRP, X86_FSUBP, X86_FDIVRP, X86_FDIVP
		};
		const uint8_t rm = MODRM_RM(modRm);

		state->instr->operands[1].operandType = g_fpSources[rm];
		state->instr->operands[1].size = 10;

		state->instr->op = operations[reg];
	}
	else
	{
		state->instr->op = X86_FCOMPP;
		return true;
	}

	state->instr->operands[0].operandType = X86_ST0;
	state->instr->operands[0].size = 10;

	reg = MODRM_REG(modRm);
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeFPIntPop(X86DecoderState* state, uint8_t opcode)
{
	uint8_t modRm;
	uint8_t reg;

	if (!Fetch(state, 1, &modRm))
		return false;

	reg = MODRM_REG(modRm);
	if (!IsModRmRmFieldReg(modRm))
	{
		static const uint8_t operandSizes[8] =
		{
			2, 2, 2, 2,
			10, 8, 10, 8
		};
		static const X86Operation operations[8] =
		{
			X86_FILD, X86_FISTTP, X86_FIST, X86_FISTP,
			X86_FBLD, X86_FILD, X86_FBSTP, X86_FISTP
		};

		// Memory!
		if (!DecodeModRmRmFieldMemory(state, 4, &state->instr->operands[1], modRm))
			return false;

		state->instr->operands[1].size = operandSizes[reg];
		state->instr->operands[0].size = 10;
		state->instr->operands[0].operandType = X86_ST0;

		state->instr->operandCount = 2;
		state->instr->op = operations[reg];
	}
	else if ((modRm >= 0xe8) && (modRm < 0xf8))
	{
		static const X86Operation operations[2] = {X86_FUCOMIP, X86_FCOMIP};
		const uint8_t rm = MODRM_RM(modRm);
		const uint8_t opBit = (reg >> 1) & 1;

		state->instr->operands[1].operandType = g_fpSources[rm];
		state->instr->operands[1].size = 4;

		state->instr->operands[0].operandType = X86_ST0;
		state->instr->operands[0].size = 10;

		state->instr->op = operations[opBit];
		state->instr->operandCount = 2;
	}
	else if (modRm == 0xe0)
	{
		state->instr->op = X86_FNSTSW;
		state->instr->operandCount = 1;

		state->instr->operands[0].operandType = X86_AX;
		state->instr->operands[0].size = 2;
	}
	else
	{
		return false;
	}

	return true;
}


static bool DecodeLoop(X86DecoderState* state, uint8_t opcode)
{
	static const X86Operation op[3] = {X86_LOOPNE, X86_LOOPE, X86_LOOP};
	const size_t operation = opcode & 3;
	uint8_t imm;

	// All three have one immediate byte argument (jump target)
	if (!Fetch(state, 1, &imm))
		return false;

	state->instr->op = op[operation];
	state->instr->operandCount = 1;

	// Sign extend the immediate to 64 bits.
	state->instr->operands[0].immediate = SIGN_EXTEND64(imm, 1);
	state->instr->operands[0].operandType = X86_IMMEDIATE;
	state->instr->operands[0].size = 1;

	return true;
}


static bool DecodeJcxz(X86DecoderState* state, uint8_t opcode)
{
	static const X86Operation op[3] = {X86_JCXZ, X86_JECXZ, X86_JRCXZ};
	uint8_t imm;
	(void)opcode;

	// Fetch the immediate argument (jump target)
	if (!Fetch(state, 1, &imm))
		return false;

	state->instr->op = op[state->operandMode];
	state->instr->operandCount = 1;

	// Sign extend the immediate to 64 bits.
	state->instr->operands[0].immediate = SIGN_EXTEND64(imm, 1);
	state->instr->operands[0].operandType = X86_IMMEDIATE;
	state->instr->operands[0].size = 1;

	return true;
}


static bool DecodeInOutImm(X86DecoderState* state, uint8_t opcode)
{
	static const X86Operation operations[2] = {X86_IN, X86_OUT};
	const uint8_t operandSizeBit = opcode & 1;
	const size_t direction = ((opcode >> 1) & 1);
	const size_t op = direction;
	const uint8_t operandSizes[2] = {1, g_decoderModeSizeXref[state->operandMode]};
	const size_t operand0 = direction;
	const size_t operand1 = ((~direction) & 1);
	const uint8_t operandSize = operandSizes[operandSizeBit];
	uint8_t imm;

	if (!Fetch(state, 1, &imm))
		return false;

	state->instr->op = operations[op];
	state->instr->operandCount = 2;

	state->instr->operands[operand0].operandType = g_gprOperandTypes[operandSize >> 1][0];
	state->instr->operands[operand0].size = operandSizes[operandSizeBit];

	// Process the immediate operand
	state->instr->operands[operand1].operandType = X86_IMMEDIATE;
	state->instr->operands[operand1].immediate = imm;
	state->instr->operands[operand1].size = 1;

	return true;
}


static bool DecodeINT1(X86DecoderState* state, uint8_t opcode)
{
	(void)opcode;
	state->instr->op = X86_INT1;
	return true;
}


static bool DecodeHLT(X86DecoderState* state, uint8_t opcode)
{
	(void)opcode;
	state->instr->op = X86_HLT;
	return true;
}


static bool DecodeCMC(X86DecoderState* state, uint8_t opcode)
{
	(void)opcode;
	state->instr->op = X86_CMC;
	return true;
}


static bool DecodeGroup3(X86DecoderState* state, uint8_t opcode)
{
	static const X86Operation operations[8] =
	{
		X86_TEST, X86_TEST, X86_NOT, X86_NEG,
		X86_MUL, X86_IMUL, X86_DIV, X86_IDIV
	};
	const uint8_t operandSizeBit = opcode & 1;
	const uint8_t operandSizes[2] = {1, g_decoderModeSizeXref[state->operandMode]};
	X86Operand operand = {0};
	const uint8_t operandSize = operandSizes[operandSizeBit];
	uint8_t modRm;
	uint8_t reg;

	// Grab the ModRM byte
	if (!Fetch(state, 1, &modRm))
		return false;

	// Extra opcode bits are in the reg field of the ModRM byte
	reg = MODRM_REG(modRm);
	state->instr->op = operations[reg];

	if (state->instr->op == X86_TEST)
	{
		uint64_t imm;

		imm = 0;
		if (!Fetch(state, operandSize, (uint8_t*)&imm))
			return false;

		// Sign extend to 64 bits.
		state->instr->operands[1].operandType = X86_IMMEDIATE;
		state->instr->operands[1].immediate = SIGN_EXTEND64(imm, 1);
		state->instr->operands[1].size = operandSize;
		state->instr->operandCount = 2;
	}
	else
	{
		state->instr->operandCount = 1;
	}

	// Figure out the destination
	if (!DecodeModRmRmField(state, operandSize, &operand, modRm))
		return false;
	state->instr->operands[0] = operand;
	state->instr->operands[0].size = operandSize;

	return true;
}


static bool DecodeIMul(X86DecoderState* state, uint8_t opcode)
{
	const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];
	const uint8_t immSizes[2] = {operandSize, 1};
	const size_t immSizeBit = (opcode >> 1) & 1;
	const uint8_t immSize = immSizes[immSizeBit];
	X86Operand operands[2] = {0};
	uint64_t imm;

	// First decode the destination and first source
	if (!DecodeModRm(state, operandSize, operands))
	{
		state->instr->flags |= X86_FLAG_INSUFFICIENT_LENGTH;
		return false;
	}
	state->instr->operands[0] = operands[1];
	state->instr->operands[0].size = operandSize;
	state->instr->operands[1] = operands[0];
	state->instr->operands[1].size = operandSize;

	// Now grab the second source, an immediate
	imm = 0;
	if (!Fetch(state, immSize, (uint8_t*)&imm))
		return false;

	state->instr->operands[2].operandType = X86_IMMEDIATE;
	state->instr->operands[2].immediate = SIGN_EXTEND64(imm, immSize);
	state->instr->operands[2].size = immSize;

	state->instr->op = X86_IMUL;
	state->instr->operandCount = 3;

	return true;
}


static bool DecodeInOutString(X86DecoderState* state, uint8_t opcode)
{
	static const X86Operation operations[2][3] =
	{
		{X86_INSB, X86_INSW, X86_INSD},
		{X86_OUTSB, X86_OUTSW, X86_OUTSD}
	};
	static const X86OperandType memOperands[3][2] =
	{
		{X86_SI, X86_DI},
		{X86_ESI, X86_EDI},
		{X86_RSI, X86_RDI}
	};
	const uint8_t operandSizes[2][3] =
	{
		{1, 1, 1},
		{2, 4, 4}
	};
	const size_t opBit = (opcode >> 1) & 1;
	const size_t operandBit = opcode & 1;
	const size_t operand0 = opBit;
	const size_t operand1 = ((~opBit) & 1);

	state->instr->op = operations[opBit][operandBit];
	state->instr->operandCount = 2;

	state->instr->operands[operand0].operandType = X86_DX;
	state->instr->operands[operand0].size = 2;

	state->instr->operands[operand1].operandType = X86_MEM;
	state->instr->operands[operand1].size = operandSizes[operandBit][state->operandMode];
	state->instr->operands[operand1].components[0] = memOperands[state->mode][0];
	state->instr->operands[operand1].components[1] = memOperands[state->mode][1];

	return true;
}


static bool DecodeMovGpr(X86DecoderState* state, uint8_t opcode)
{
	const uint8_t operandSizes[2] = {1, g_decoderModeSizeXref[state->operandMode]};
	const uint8_t operandSizeBit = opcode & 1;
	X86Operand operands[2] = {0};
	const uint8_t operandSize = operandSizes[operandSizeBit];
	const uint8_t direction = ((opcode >> 1) & 1);
	const uint8_t operand0 = direction;
	const uint8_t operand1 = ((~direction) & 1);

	state->instr->op = X86_MOV;
	if (!DecodeModRm(state, operandSize, operands))
		return false;

	state->instr->operandCount = 2;
	state->instr->operands[0] = operands[operand0];
	state->instr->operands[1] = operands[operand1];

	return true;
}


static bool DecodeMovSeg(X86DecoderState* state, uint8_t opcode)
{
	const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];
	static const X86OperandType segments[8] = {X86_ES, X86_CS, X86_SS, X86_DS, X86_FS, X86_GS, X86_NONE, X86_NONE};
	X86Operand operands[2] = {0};
	const uint8_t direction = (opcode >> 1) & 1;
	uint8_t modRm;
	uint8_t segment;
	const uint8_t operand0 = direction;
	const uint8_t operand1 = ((~direction) & 1);

	state->instr->op = X86_MOV;
	state->instr->operandCount = 2;

	// Grab the ModRm byte
	if (!Fetch(state, 1, &modRm))
		return false;

	// Look for values of 6 or 7 in the reg field
	// (does not encode a valid segment register)
	segment = MODRM_REG(modRm);
	if ((segment & 6) == 6)
		return false;

	// Process the first operand
	if (!DecodeModRmRmField(state, operandSize, operands, modRm))
		return false;
	state->instr->operands[operand0] = operands[0];

	// Now process the second operand.
	state->instr->operands[operand1].size = 2;
	state->instr->operands[operand1].operandType = segments[segment];

	return true;
}


static bool DecodeLea(X86DecoderState* state, uint8_t opcode)
{
	const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];
	uint8_t modRm;
	(void)opcode;

	// Grab the ModRm byte
	if (!Fetch(state, 1, &modRm))
		return false;

	// Only memory references are valid in the rm field.
	if (IsModRmRmFieldReg(modRm))
		return false;

	// Figure out the operands
	if (!DecodeModRmRmFieldMemory(state, operandSize, &state->instr->operands[1], modRm))
		return false;
	DecodeModRmRegField(state, operandSize, &state->instr->operands[0], modRm);

	state->instr->operands[0].size = operandSize;
	state->instr->operands[1].size = operandSize;

	// Write out the rest
	state->instr->op = X86_LEA;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeGroup1a(X86DecoderState* state, uint8_t opcode)
{
	const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];
	X86Operand operands[2] = {0};
	uint8_t modRm;
	uint8_t reg;

	// Grab the ModRm byte
	if (!Fetch(state, 1, &modRm))
		return false;

	// Only reg 0 is valid, which is POP R/M
	reg = MODRM_REG(modRm);
	if (reg != 0)
	{
		// TODO: XOP
		return false;
	}

	// Figure out the destination
	state->instr->operandCount = 1;
	if (!DecodeModRmRmField(state, operandSize, operands, modRm))
		return false;
	state->instr->operands[0] = operands[0];

	return true;
}


static bool DecodeConvertSize(X86DecoderState* state, uint8_t opcode)
{
	static const X86Operation operations[2][3] =
	{
		{X86_CBW, X86_CWDE, X86_CDQE},
		{X86_CWD, X86_CDQ, X86_CQO}
	};
	const uint8_t op = opcode & 1;

	// Current operand size defines the mnemonic
	state->instr->op = operations[op][state->operandMode];

	return true;
}


static bool DecodeCallFar(X86DecoderState* state, uint8_t opcode)
{
	const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];
	union
	{
		uint8_t imm[6];
		struct
		{
			uint16_t segment;
			union
			{
				uint16_t w;
				uint32_t d;
			} offset;
		};
	} farPtr = {0};
	const size_t operandBytes = operandSize + 2;
	(void)opcode;

	if (state->operandMode == X86_64BIT)
	{
		// This form is invalid in 64bit mode
		return false;
	}

	if (!Fetch(state, operandBytes, farPtr.imm))
		return false;

	state->instr->op = X86_CALLF;
	state->instr->operandCount = 2;

	// Store the segment first
	state->instr->operands[0].operandType = X86_IMMEDIATE;
	state->instr->operands[0].size = 2;
	state->instr->operands[0].immediate = farPtr.segment;

	// Now the offset
	state->instr->operands[0].operandType = X86_IMMEDIATE;
	state->instr->operands[0].size = operandSize;

	if (operandSize == 2)
		state->instr->operands[0].immediate = SIGN_EXTEND64(farPtr.offset.w, 2);
	else
		state->instr->operands[0].immediate = SIGN_EXTEND64(farPtr.offset.d, 4);

	return true;
}


static bool DecodeFWait(X86DecoderState* state, uint8_t opcode)
{
	(void)opcode;
	state->instr->op = X86_FWAIT;
	return true;
}


static bool DecodePushPopFlags(X86DecoderState* state, uint8_t opcode)
{
	static const X86Operation ops[2][3] =
	{
		{X86_PUSHF, X86_PUSHFD, X86_PUSHFQ},
		{X86_POPF, X86_POPFD, X86_POPFQ},
	};
	const uint8_t operation = (opcode & 1);

	state->instr->op = ops[operation][state->operandMode];

	return true;
}


static bool DecodeAHFlags(X86DecoderState* state, uint8_t opcode)
{
	static const X86Operation ops[2] = {X86_SAHF, X86_LAHF};
	const uint8_t operation = opcode & 1;
	state->instr->op = ops[operation];
	return true;
}


static bool DecodeTestImm(X86DecoderState* state, uint8_t opcode)
{
	uint64_t imm;
	const size_t sizeBit = opcode & 1;
	const uint8_t operandSizes[2] = {1, g_decoderModeSizeXref[state->operandMode]};
	static const X86OperandType dests[4] = {X86_AL, X86_AX, X86_EAX, X86_RAX};
	const uint8_t operandSize = operandSizes[sizeBit];

	imm = 0;
	if (!Fetch(state, operandSize, (uint8_t*)&imm))
		return false;

	state->instr->op = X86_TEST;
	state->instr->operandCount = 2;

	state->instr->operands[1].operandType = X86_IMMEDIATE;
	state->instr->operands[1].size = operandSize;
	state->instr->operands[1].immediate = imm;

	state->instr->operands[0].operandType = dests[operandSize >> 1];
	state->instr->operands[0].size = operandSize;

	return true;
}


static bool DecodeString(X86DecoderState* state, uint8_t opcode)
{
	static const X86Operation operations[3][4] =
	{
		{X86_STOSB, X86_STOSW, X86_STOSD, X86_STOSQ},
		{X86_LODSB, X86_LODSW, X86_LODSD, X86_LODSQ},
		{X86_SCASB, X86_SCASW, X86_SCASD, X86_SCASQ}
	};
	static const X86OperandType sources[3][4] =
	{
		{X86_AL, X86_AX, X86_EAX, X86_RAX},
		{X86_MEM, X86_MEM, X86_MEM, X86_MEM},
		{X86_MEM, X86_MEM, X86_MEM, X86_MEM}
	};
	static const X86OperandType sourceComponents[3][3] =
	{
		{X86_NONE, X86_NONE, X86_NONE},
		{X86_SI, X86_ESI, X86_RSI},
		{X86_DI, X86_EDI, X86_RDI}
	};
	static const X86OperandType dests[3][4] =
	{
		{X86_MEM, X86_MEM, X86_MEM, X86_MEM},
		{X86_AL, X86_AX, X86_EAX, X86_RAX},
		{X86_AL, X86_AX, X86_EAX, X86_RAX}
	};
	static const X86OperandType destComponents[3][3] =
	{
		{X86_DI, X86_EDI, X86_RDI},
		{X86_NONE, X86_NONE, X86_NONE},
		{X86_NONE, X86_NONE, X86_NONE}
	};
	static const X86OperandType segments[3][2] =
	{
		{X86_ES, X86_NONE},
		{X86_DS, X86_NONE},
		{X86_NONE, X86_ES}
	};
	const uint8_t operandSizes[2] = {1, g_decoderModeSizeXref[state->mode]};
	const uint8_t sizeBit = (opcode & 1);
	const uint8_t operationBits = ((opcode & 0xf) - 0xa) >> 1;
	const uint8_t operandSize = operandSizes[sizeBit];
	const uint8_t operandSel = operandSize >> 1;

	state->instr->op = operations[operationBits][operandSel];
	state->instr->operandCount = 2;

	state->instr->operands[0].operandType = dests[operandSel][operationBits];
	state->instr->operands[0].segment = segments[operationBits][0];
	state->instr->operands[0].size = operandSize;
	state->instr->operands[0].components[0] = destComponents[state->mode][operationBits];

	state->instr->operands[1].operandType = sources[operandSel][operationBits];
	state->instr->operands[1].segment = segments[operationBits][1];
	state->instr->operands[1].size = operandSize;
	state->instr->operands[1].components[0] = sourceComponents[state->mode][operationBits];

	return true;
}


static bool DecodeMovImm(X86DecoderState* state, uint8_t opcode)
{
	uint64_t imm;
	const uint8_t operandSizes[2] = {1, g_decoderModeSizeXref[state->mode]};
	const uint8_t operandSizeBit = (opcode >> 3) & 1;
	const uint8_t operand = opcode & 7;
	const uint8_t operandBytes = operandSizes[operandSizeBit];
	static const X86OperandType dests[4][16] =
	{
		{
			X86_AL, X86_CL, X86_DL, X86_BL,
			X86_AH, X86_CH, X86_DH, X86_BH,
			X86_R8B, X86_R9B, X86_R10B, X86_R11B,
			X86_R12B, X86_R13B, X86_R14B, X86_R15B
		},
		{
			X86_AX, X86_CX, X86_DX, X86_BX,
			X86_SP, X86_BP, X86_SI, X86_DI,
			X86_R8B, X86_R9W, X86_R10W, X86_R11W,
			X86_R12W, X86_R13W, X86_R14W, X86_R15W
		},
		{
			X86_EAX, X86_ECX, X86_EDX, X86_EBX,
			X86_ESP, X86_EBP, X86_ESI, X86_EDI,
			X86_R8D, X86_R9D, X86_R10D, X86_R11D,
			X86_R12D, X86_R13D, X86_R14D, X86_R15D
		},
		{
			X86_RAX, X86_RCX, X86_RDX, X86_RBX,
			X86_RSP, X86_RBP, X86_RSI, X86_RDI,
			X86_R8, X86_R9, X86_R10, X86_R11,
			X86_R12, X86_R13, X86_R14, X86_R15
		}
	};

	imm = 0;
	if (!Fetch(state, operandBytes, (uint8_t*)&imm))
		return false;

	// TODO: REX

	state->instr->op = X86_MOV;
	state->instr->operandCount = 2;

	// Sign extend the immediate.
	state->instr->operands[1].immediate = SIGN_EXTEND64(imm, operandBytes);
	state->instr->operands[1].operandType = X86_IMMEDIATE;
	state->instr->operands[1].size = operandBytes;

	state->instr->operands[0].size = operandBytes;
	state->instr->operands[0].operandType = dests[operandBytes >> 1][operand];

	return true;
}


static bool DecodeEnter(X86DecoderState* state, uint8_t opcode)
{
	union
	{
		uint8_t imm[3];
		struct
		{
			uint16_t size;
			uint8_t level;
		};
	} args;

	if (!Fetch(state, 3, args.imm))
		return false;

	state->instr->op = X86_ENTER;

	state->instr->operands[0].operandType = X86_IMMEDIATE;
	state->instr->operands[0].immediate = SIGN_EXTEND64(args.size, 2);
	state->instr->operands[0].size = 2;

	state->instr->operands[1].operandType = X86_IMMEDIATE;
	state->instr->operands[1].immediate = SIGN_EXTEND64(args.level, 1);
	state->instr->operands[1].size = 1;

	return true;
}


static bool DecodeLeave(X86DecoderState* state, uint8_t opcode)
{
	(void)opcode;
	state->instr->op = X86_LEAVE;
	return true;
}


static bool DecodeReturn(X86DecoderState* state, uint8_t opcode)
{
	static const X86Operation operations[2] = {X86_RETN, X86_RETF};
	const uint8_t op = ((opcode >> 3) & 1);
	uint16_t imm;

	state->instr->op = operations[op];
	if (opcode & 1)
	{
		// This form has no operands
		return true;
	}

	// Only fetch if the form requires an immediate
	if (!Fetch(state, 2, (uint8_t*)&imm))
		return false;

	state->instr->operandCount = 1;
	state->instr->operands[0].operandType = X86_IMMEDIATE;
	state->instr->operands[0].immediate = SIGN_EXTEND64(imm, 2);
	state->instr->operands[0].size = 2;

	return true;
}


static bool DecodeInt3(X86DecoderState* state, uint8_t opcode)
{
	(void)opcode;
	state->instr->op = X86_INT3;
	return true;
}


static bool DecodeInt(X86DecoderState* state, uint8_t opcode)
{
	uint8_t imm;
	(void)opcode;

	if (!Fetch(state, 1, &imm))
		return false;

	state->instr->operandCount = 1;
	state->instr->operands[0].operandType = X86_IMMEDIATE;
	state->instr->operands[0].immediate = SIGN_EXTEND64(imm, 1);
	state->instr->operands[0].size = 1;

	state->instr->op = X86_INT;

	return true;
}


static bool DecodeInto(X86DecoderState* state, uint8_t opcode)
{
	(void)opcode;

	if (state->mode == X86_64BIT)
		return false;

	state->instr->op = X86_INTO;

	return true;
}


static bool DecodeIRet(X86DecoderState* state, uint8_t opcode)
{
	static const X86Operation operations[3] = {X86_IRET, X86_IRETD, X86_IRETQ};
	(void)opcode;
	state->instr->op = operations[state->mode];
	return true;
}


static bool DecodeCallJmpRelative(X86DecoderState* state, uint8_t opcode)
{
	static const uint8_t operandSizes[3] = {2, 4, 4};
	const uint8_t operandBytes = operandSizes[state->operandMode];
	static const X86Operation operations[2] = {X86_CALLN, X86_JMP};
	const uint8_t operation = opcode & 1;
	uint64_t imm;

	(void)opcode;

	imm = 0;
	if (!Fetch(state, operandBytes, (uint8_t*)&imm))
		return false;

	state->instr->op = operations[operation];
	state->instr->operandCount = 1;
	state->instr->operands[0].operandType = X86_IMMEDIATE;
	state->instr->operands[0].immediate = SIGN_EXTEND64(imm, operandBytes);
	state->instr->operands[0].size = operandBytes;

	return true;
}


static bool DecodeJmpRelative(X86DecoderState* state, uint8_t opcode)
{
	static const uint8_t operandSizes[3] = {2, 4, 4};
	const uint8_t operandBytes = operandSizes[state->operandMode];
	uint64_t imm;
	(void)opcode;


	imm = 0;
	if (!Fetch(state, operandBytes, (uint8_t*)&imm))
		return false;

	state->instr->op = X86_JMP;
	state->instr->operandCount = 1;
	state->instr->operands[0].operandType = X86_IMMEDIATE;
	state->instr->operands[0].immediate = SIGN_EXTEND64(imm, operandBytes);
	state->instr->operands[0].size = operandBytes;

	return true;
}


static bool DecodeJmpFar(X86DecoderState* state, uint8_t opcode)
{
	const uint8_t operandBytes = g_decoderModeSizeXref[state->operandMode] + 2;
	union
	{
		uint8_t bytes[6];
		struct
		{
			uint16_t selector;
			union
			{
				uint16_t w;
				uint32_t d;
			} offset;
		};
	} operands = {0};

	if (!Fetch(state, operandBytes, operands.bytes))
		return false;

	state->instr->op = X86_JMP;
	state->instr->operandCount = 2;

	state->instr->operands[0].operandType = X86_IMMEDIATE;
	state->instr->operands[0].immediate = operands.selector;

	state->instr->operands[1].operandType = X86_IMMEDIATE;
	if (state->operandMode == X86_16BIT)
		state->instr->operands[1].immediate = operands.offset.w;
	else
		state->instr->operands[1].immediate = operands.offset.d;

	return true;
}


static bool DecodeJmpRelativeByte(X86DecoderState* state, uint8_t opcode)
{
	uint8_t imm;
	(void)opcode;

	if (!Fetch(state, 1, &imm))
		return false;

	state->instr->op = X86_JMP;
	state->instr->operandCount = 1;

	state->instr->operands[0].operandType = X86_IMMEDIATE;
	state->instr->operands[0].immediate = imm;
	state->instr->operands[0].size = 1;

	return true;
}


static bool DecodeInOutDx(X86DecoderState* state, uint8_t opcode)
{
	const uint8_t operandSizes[2] = {1, g_decoderModeSizeXref[state->mode]};
	static const X86Operation operations[2] = {X86_IN, X86_OUT};
	const uint8_t operandSizeBit = (opcode & 1);
	const uint8_t operation = (opcode >> 1) & 1;
	const uint8_t operandSize = operandSizes[operandSizeBit];
	const uint8_t operand0 = operation;
	const uint8_t operand1  = ((~operation) & 1);

	state->instr->op = operations[operation];
	state->instr->operandCount = 2;

	state->instr->operands[operand0].operandType = g_gprOperandTypes[operandSize >> 1][0];
	state->instr->operands[operand0].size = operandSize;

	state->instr->operands[operand1].operandType = X86_DX;
	state->instr->operands[operand1].size = 2;

	return true;
}


static bool DecodeSetClearFlag(X86DecoderState* state, uint8_t opcode)
{
	static const X86Operation operations[6] = {X86_CLC, X86_STC, X86_CLI, X86_STI, X86_CLD, X86_STD};
	const uint8_t op = (opcode & 7);
	state->instr->op = operations[op];
	return true;
}


static bool DecodeGroup4(X86DecoderState* state, uint8_t opcode)
{
	static const X86Operation operations[2] = {X86_INC, X86_DEC};
	uint8_t modRm;
	uint8_t reg;

	if (!Fetch(state, 1, &modRm))
		return false;

	if (!DecodeModRmRmField(state, 1, &state->instr->operands[0], modRm))
		return false;

	reg = MODRM_REG(modRm);
	if (reg & 2)
		return false;

	state->instr->operandCount = 1;
	state->instr->op = operations[reg];

	return true;
}


static bool DecodeGroup5(X86DecoderState* state, uint8_t opcode)
{
	const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];
	static const X86Operation operations[8] =
	{
		X86_INC, X86_DEC, X86_CALLN, X86_CALLN,
		X86_JMP, X86_JMP, X86_PUSH, X86_INVALID
	};
	uint8_t modRm;
	uint8_t reg;

	if (!Fetch(state, 1, &modRm))
		return false;

	// GPR encoding for CALL/JMP Mp invalid
	reg = MODRM_REG(modRm);
	if ((reg == 3) || (reg == 5))
	{
		if (IsModRmRmFieldReg(modRm))
			return false;
	}

	if (!DecodeModRmRmField(state, operandSize, &state->instr->operands[0], modRm))
		return false;

	state->instr->operandCount = 1;
	state->instr->op = operations[reg];

	return true;
}


static bool DecodeSegmentPrefix(X86DecoderState* state, uint8_t opcode)
{
	static const X86InstructionFlags segments[2][2] =
	{
		{X86_FLAG_SEGMENT_OVERRIDE_ES, X86_FLAG_SEGMENT_OVERRIDE_CS},
		{X86_FLAG_SEGMENT_OVERRIDE_SS, X86_FLAG_SEGMENT_OVERRIDE_DS}
	};
	const uint8_t colBit = (opcode >> 3) & 1;
	const uint8_t rowBit = (opcode >> 4) - 2;

	state->lastBytePrefix = true;

	// Only the last segment override prefix matters.
	state->instr->flags &= ~(X86_FLAG_SEGMENT_OVERRIDE_CS | X86_FLAG_SEGMENT_OVERRIDE_SS
		| X86_FLAG_SEGMENT_OVERRIDE_DS | X86_FLAG_SEGMENT_OVERRIDE_ES | X86_FLAG_SEGMENT_OVERRIDE_FS
		| X86_FLAG_SEGMENT_OVERRIDE_GS);

	state->instr->flags |= segments[rowBit][colBit];

	return DecodePrimaryOpcodeTable(state);
}


static bool DecodeExtendedSegmentPrefix(X86DecoderState* state, uint8_t opcode)
{
	static const X86InstructionFlags segments[2] = {X86_FLAG_SEGMENT_OVERRIDE_FS, X86_FLAG_SEGMENT_OVERRIDE_GS};
	const uint8_t colBit = opcode - 4;
	state->lastBytePrefix = true;

	// Only the last segment override prefix matters.
	state->instr->flags &= ~(X86_FLAG_SEGMENT_OVERRIDE_CS | X86_FLAG_SEGMENT_OVERRIDE_SS
		| X86_FLAG_SEGMENT_OVERRIDE_DS | X86_FLAG_SEGMENT_OVERRIDE_ES | X86_FLAG_SEGMENT_OVERRIDE_FS
		| X86_FLAG_SEGMENT_OVERRIDE_GS);

	state->instr->flags |= segments[colBit];

	return DecodePrimaryOpcodeTable(state);
}


static bool DecodeOperandSizePrefix(X86DecoderState* state, uint8_t opcode)
{
	static const X86DecoderMode modes[3] = {X86_32BIT, X86_16BIT, X86_32BIT};
	(void)opcode;
	state->lastBytePrefix = true;
	state->operandMode = modes[state->operandMode];
	return DecodePrimaryOpcodeTable(state);
}


static bool DecodeAddrSizePrefix(X86DecoderState* state, uint8_t opcode)
{
	static const X86DecoderMode modes[3] = {X86_32BIT, X86_16BIT, X86_32BIT};
	(void)opcode;
	state->lastBytePrefix = true;
	state->mode = modes[state->operandMode];
	return DecodePrimaryOpcodeTable(state);
}


static bool DecodeLockPrefix(X86DecoderState* state, uint8_t opcode)
{
	(void)opcode;
	state->lastBytePrefix = true;
	state->instr->flags |= X86_FLAG_LOCK;
	return DecodePrimaryOpcodeTable(state);
}


static bool DecodeRepPrefix(X86DecoderState* state, uint8_t opcode)
{
	static const X86InstructionFlags reps[2] = {X86_FLAG_REPNE, X86_FLAG_REPE};
	const uint8_t colBit = opcode - 2;

	state->lastBytePrefix = true;

	// Clear existing rep flags, only the last one counts
	state->instr->flags &= ~(X86_FLAG_REP | X86_FLAG_REPE | X86_FLAG_REPNE);
	state->instr->flags |= reps[colBit];

	return DecodePrimaryOpcodeTable(state);
}

static const InstructionDecoder g_primaryDecoders[256] =
{
	// Row 0
	DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePrimaryArithmetic,
	DecodePrimaryArithmeticImm, DecodePrimaryArithmeticImm, DecodePushPopSegment, DecodePushPopSegment,
	DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePrimaryArithmetic,
	DecodePrimaryArithmeticImm, DecodePrimaryArithmeticImm, DecodePushPopSegment, DecodeSecondaryOpCodeTable,

	// Row 1
	DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePrimaryArithmetic,
	DecodePrimaryArithmeticImm, DecodePrimaryArithmeticImm, DecodePushPopSegment, DecodePushPopSegment,
	DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePrimaryArithmetic,
	DecodePrimaryArithmeticImm, DecodePrimaryArithmeticImm, DecodePushPopSegment, DecodePushPopSegment,

	// Row 2
	DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePrimaryArithmetic,
	DecodePrimaryArithmeticImm, DecodePrimaryArithmeticImm, DecodeSegmentPrefix, DecodeAscii,
	DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePrimaryArithmetic,
	DecodePrimaryArithmeticImm, DecodePrimaryArithmeticImm, DecodeSegmentPrefix, DecodeAscii,

	// Row 3
	DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePrimaryArithmetic,
	DecodePrimaryArithmeticImm, DecodePrimaryArithmeticImm, DecodeSegmentPrefix, DecodeAscii,
	DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePrimaryArithmetic, DecodePrimaryArithmetic,
	DecodePrimaryArithmeticImm, DecodePrimaryArithmeticImm, DecodeSegmentPrefix, DecodeAscii,

	// Row 4
	DecodeIncDec, DecodeIncDec, DecodeIncDec, DecodeIncDec,
	DecodeIncDec, DecodeIncDec, DecodeIncDec, DecodeIncDec,
	DecodeIncDec, DecodeIncDec, DecodeIncDec, DecodeIncDec,
	DecodeIncDec, DecodeIncDec, DecodeIncDec, DecodeIncDec,

	// Row 5
	DecodePushPopGpr, DecodePushPopGpr, DecodePushPopGpr, DecodePushPopGpr,
	DecodePushPopGpr, DecodePushPopGpr, DecodePushPopGpr, DecodePushPopGpr,
	DecodePushPopGpr, DecodePushPopGpr, DecodePushPopGpr, DecodePushPopGpr,
	DecodePushPopGpr, DecodePushPopGpr, DecodePushPopGpr, DecodePushPopGpr,

	// Row 6
	DecodePushPopAll, DecodePushPopAll, DecodeBound, DecodeAarplMovSxd,
	DecodeExtendedSegmentPrefix, DecodeExtendedSegmentPrefix, DecodeOperandSizePrefix, DecodeAddrSizePrefix,
	DecodePushImmediate, DecodeIMul, DecodePushImmediate, DecodeIMul,
	DecodeInOutString, DecodeInOutString, DecodeInOutString, DecodeInOutString,

	// Row 7
	DecodeJumpConditional, DecodeJumpConditional, DecodeJumpConditional, DecodeJumpConditional,
	DecodeJumpConditional, DecodeJumpConditional, DecodeJumpConditional, DecodeJumpConditional,
	DecodeJumpConditional, DecodeJumpConditional, DecodeJumpConditional, DecodeJumpConditional,
	DecodeJumpConditional, DecodeJumpConditional, DecodeJumpConditional, DecodeJumpConditional,

	// Row 8
	DecodeGroup1, DecodeGroup1, DecodeGroup1, DecodeGroup1,
	DecodeTestXchgModRm, DecodeTestXchgModRm, DecodeTestXchgModRm, DecodeTestXchgModRm,
	DecodeMovGpr, DecodeMovGpr, DecodeMovGpr, DecodeMovGpr,
	DecodeMovSeg, DecodeLea, DecodeMovSeg, DecodeGroup1a,

	// Row 9
	DecodeNop, DecodeXchgRax, DecodeXchgRax, DecodeXchgRax,
	DecodeXchgRax, DecodeXchgRax, DecodeXchgRax, DecodeXchgRax,
	DecodeConvertSize, DecodeConvertSize, DecodeCallFar, DecodeFWait,
	DecodePushPopFlags, DecodePushPopFlags, DecodeAHFlags, DecodeAHFlags,

	// Row 0xa
	DecodeMovOffset, DecodeMovOffset, DecodeMovOffset, DecodeMovOffset,
	DecodeMovCmpString, DecodeMovCmpString, DecodeMovCmpString, DecodeMovCmpString,
	DecodeTestImm, DecodeTestImm, DecodeString, DecodeString,
	DecodeString, DecodeString, DecodeString, DecodeString,

	// Row 0xb
	DecodeMovImm, DecodeMovImm, DecodeMovImm, DecodeMovImm,
	DecodeMovImm, DecodeMovImm, DecodeMovImm, DecodeMovImm,
	DecodeMovImm, DecodeMovImm, DecodeMovImm, DecodeMovImm,
	DecodeMovImm, DecodeMovImm, DecodeMovImm, DecodeMovImm,

	// Row 0xc
	DecodeGroup2, DecodeGroup2, DecodeReturn, DecodeReturn,
	DecodeLoadSegment, DecodeLoadSegment, DecodeGroup11, DecodeGroup11,
	DecodeEnter, DecodeLeave, DecodeReturn, DecodeReturn,
	DecodeInt3, DecodeInt, DecodeInto, DecodeIRet,

	// Row 0xd
	DecodeGroup2, DecodeGroup2, DecodeGroup2, DecodeGroup2,
	DecodeAsciiAdjust, DecodeAsciiAdjust, DecodeInvalid, DecodeXlat,
	DecodeFPArithmetic, DecodeFPLoadStore, DecodeFPMovConditional, DecodeFPMovNegConditional,
	DecodeFPArithmetic, DecodeFPFreeStore, DecodeFPArithmeticPop, DecodeFPIntPop,

	// Row 0xe
	DecodeLoop, DecodeLoop, DecodeLoop, DecodeJcxz,
	DecodeInOutImm, DecodeInOutImm, DecodeInOutImm, DecodeInOutImm,
	DecodeCallJmpRelative, DecodeCallJmpRelative, DecodeJmpFar, DecodeJmpRelativeByte,
	DecodeInOutDx, DecodeInOutDx, DecodeInOutDx, DecodeInOutDx,

	// Row 0xf
	DecodeLockPrefix, DecodeINT1, DecodeRepPrefix, DecodeRepPrefix,
	DecodeHLT, DecodeCMC, DecodeGroup3, DecodeGroup3,
	DecodeSetClearFlag, DecodeSetClearFlag, DecodeSetClearFlag, DecodeSetClearFlag,
	DecodeSetClearFlag, DecodeSetClearFlag, DecodeGroup4, DecodeGroup5
};


// See Table A-1 Primary Opcode Table (One-byte Opcodes) AMD 24594_APM_v3.pdf
bool DecodePrimaryOpcodeTable(X86DecoderState* const state)
{
	bool ret;
	uint8_t opcode;

	// Grab a byte from the machine
	if (!Fetch(state, 1, &opcode))
		return false;

	if (!g_primaryDecoders[opcode](state, opcode))
		return false;

	if (state->lastBytePrefix && state->prefixesDone);
		return false;

	state->prefixesDone = !state->lastBytePrefix;

	return ret;
}


static bool DecodeGroup6(X86DecoderState* state, uint8_t opcode)
{
	static const X86Operation operations[] =
	{
		X86_SLDT, X86_STR, X86_LLDT, X86_LTR,
		X86_VERR, X86_VERW, X86_INVALID, X86_INVALID
	};
	uint8_t modRm;
	uint8_t reg;

	if (!Fetch(state, 1, &modRm))
		return false;

	if (!DecodeModRmRmField(state, 2, &state->instr->operands[0], modRm))
		return false;

	reg = MODRM_REG(modRm);
	state->instr->op = operations[reg];

	return true;
}


static bool DecodeGroup7(X86DecoderState* state, uint8_t opcode)
{
	static const X86Operation operations[] =
	{
		X86_SGDT, X86_SIDT, X86_LGDT, X86_LIDT,
		X86_SMSW, X86_INVALID, X86_LMSW, X86_INVLPG
	};
	uint8_t modRm;
	uint8_t reg;

	if (!Fetch(state, 1, &modRm))
		return false;

	if (!DecodeModRmRmField(state, 2, &state->instr->operands[0], modRm))
		return false;

	reg = MODRM_REG(modRm);
	state->instr->op = operations[reg];

	return true;
}


static bool DecodeLoadSegmentInfo(X86DecoderState* state, uint8_t opcode)
{
	static const X86Operation operations[] = {X86_LAR, X86_LSL};
	const uint8_t op = opcode & 1;

	if (!DecodeModRm(state, g_decoderModeSizeXref[state->operandMode], state->instr->operands))
		return false;

	state->instr->op = operations[op];
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeSys(X86DecoderState* state, uint8_t opcode)
{
	static const X86Operation operations[] = {X86_INVALID, X86_SYSCALL, X86_CLTS, X86_SYSRET};
	const uint8_t op = (opcode & 3);
	state->instr->op = operations[op];
	return true;
}


static __inline bool DecodeModRmRmFieldSimdReg(X86DecoderState* const state, uint8_t operandSize,
		X86Operand* const operand, uint8_t modRm)
{
	const uint8_t rm = modRm & 7;
	operand->operandType = g_simdOperandTypes[operandSize >> 3][rm];
	operand->size = operandSize;
	return true;
}


static __inline void DecodeModRmRegFieldSimd(X86DecoderState* const state, uint8_t operandSize,
	X86Operand* const operand, uint8_t modRm)
{
	const uint8_t reg = (modRm >> 3) & 7;
	operand->operandType = g_simdOperandTypes[operandSize >> 3][reg];
	operand->size = operandSize;
}


static __inline bool DecodeModRmRmFieldSimd(X86DecoderState* const state, uint8_t operandSize,
		X86Operand* const operand, uint8_t modRm)
{
	if (IsModRmRmFieldReg(modRm))
		return DecodeModRmRmFieldSimdReg(state, operandSize, operand, modRm);

	return DecodeModRmRmFieldMemory(state, operandSize, operand, modRm);
}


static __inline bool DecodeModRmSimd(X86DecoderState* const state, uint8_t operandSize, X86Operand* const operands)
{
	uint8_t modRm;

	// Fetch the ModRM byte
	if (!Fetch(state, 1, (uint8_t*)&modRm))
		return false;

	if (!DecodeModRmRmFieldSimd(state, operandSize, &operands[0], modRm))
		return false;

	DecodeModRmRegFieldSimd(state, operandSize, &operands[1], modRm);

	return true;
}


static __inline bool DecodePackedSingle(X86DecoderState* state, uint8_t opcode)
{
	static const X86Operation operations[] = {X86_MOVUPS, X86_MOVLPS, X86_UNPCKLPS, X86_MOVHPS};
	const uint8_t operandSizes[] = {8, 16}; // FIXME
	const uint8_t direction = (opcode & 1);
	const uint8_t op = (opcode >> 1);
	const uint8_t operandSize = operandSizes[state->operandMode];
	X86Operand operands[2] = {0};
	const uint8_t operand0 = direction;
	const uint8_t operand1 = ((~direction) & 1);

	if (!DecodeModRmSimd(state, operandSize, operands))
		return false;

	state->instr->op = operations[op];
	state->instr->operandCount = 2;

	state->instr->operands[operand0] = operands[0];
	state->instr->operands[0].size = operandSize;

	state->instr->operands[operand1] = operands[1];
	state->instr->operands[1].size = operandSize;

	return true;
}


static __inline bool DecodeMovSpecialPurpose(X86DecoderState* state, uint8_t opcode)
{
	static const uint8_t operandSizes[] = {4, 4, 8};
	static const X86OperandType operands[2][8] =
	{
		{X86_CR0, X86_NONE, X86_CR2, X86_CR3, X86_CR4, X86_NONE, X86_NONE, X86_NONE},
		{X86_DR0, X86_DR1, X86_DR2, X86_DR3, X86_NONE, X86_NONE, X86_DR6, X86_DR7}
	};
	const uint8_t direction = ((opcode >> 2) & 1);
	const uint8_t operand0 = direction;
	const uint8_t operand1 = ((~direction) & 1);
	const uint8_t operandSel = (opcode & 1);
	// FIXME: The operand size theoretically should not be altered by addr mode prefix?
	const uint8_t operandSize = operandSizes[state->mode];
	uint8_t modRm;
	uint8_t reg;

	if (!Fetch(state, 1, &modRm))
		return false;

	if (!DecodeModRmRmField(state, operandSize, &state->instr->operands[operand1], modRm))
		return false;

	reg = MODRM_REG(modRm);

	state->instr->operands[0].size = operandSize;
	state->instr->operands[1].size = operandSize;

	state->instr->operands[operand0].operandType = operands[operandSel][reg];

	return true;
}


static const InstructionDecoder g_secondaryDecodersF2[256] =
{
	DecodeInvalid,
};

static const InstructionDecoder g_secondaryDecodersF3[256] =
{
	DecodeInvalid,
};

static const InstructionDecoder g_secondaryDecoders[256] =
{
	// Row 0
	DecodeGroup6, DecodeGroup6, DecodeLoadSegmentInfo, DecodeLoadSegmentInfo,
	DecodeSys, DecodeSys, DecodeSys, DecodeSys,

	// Row 1
	DecodePackedSingle, DecodePackedSingle, DecodePackedSingle, DecodePackedSingle,
	DecodePackedSingle, DecodePackedSingle, DecodePackedSingle, DecodePackedSingle,

	// Row 2
	DecodeMovSpecialPurpose, DecodeMovSpecialPurpose, DecodeMovSpecialPurpose, DecodeMovSpecialPurpose,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
};

static bool DecodeSecondaryOpCodeTable(X86DecoderState* state, uint8_t opcode)
{
	// Grab a byte from the machine
	if (!Fetch(state, 1, &opcode))
		return false;

	if (!g_secondaryDecoders[opcode](state, opcode))
		return false;

	return true;
}