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

#include "decode.h"

typedef bool (*InstructionDecoder)(X86DecoderState* const state, uint8_t opcode);
static bool DecodeSecondaryOpCodeTable(X86DecoderState* const state, uint8_t opcode);

static const InstructionDecoder g_primaryDecoders[256];
static const InstructionDecoder* g_secondaryDecoders[4];
static const InstructionDecoder g_0f38Decoders[256];
static const InstructionDecoder g_0f3aDecoders[256];

typedef struct ModRmRmOperand
{
	const X86Operand operand;
	const uint8_t dispBytes;
	const uint8_t sib;
} ModRmRmOperand;

#define MODRM_RM_OPERANDS(type, base, index, disp, sib) \
	{{X86_ ## type, {X86_ ## base, X86_ ## index}, X86_DS, 0, 0, 0}, disp, sib}

static const ModRmRmOperand g_modRmRmOperands16[24] =
{
	// Mod 00
	MODRM_RM_OPERANDS(MEM, BX, SI, 0, 0),
	MODRM_RM_OPERANDS(MEM, BX, DI, 0, 0),
	MODRM_RM_OPERANDS(MEM, BP, SI, 0, 0),
	MODRM_RM_OPERANDS(MEM, BP, DI, 0, 0),
	MODRM_RM_OPERANDS(MEM, SI, NONE, 0, 0),
	MODRM_RM_OPERANDS(MEM, DI, NONE, 0, 0),
	MODRM_RM_OPERANDS(MEM, NONE, NONE, 2, 0),
	MODRM_RM_OPERANDS(MEM, BX, NONE, 0, 0),

	// Mod 01
	MODRM_RM_OPERANDS(MEM, BX, SI, 1, 0),
	MODRM_RM_OPERANDS(MEM, BX, DI, 1, 0),
	MODRM_RM_OPERANDS(MEM, BP, SI, 1, 0),
	MODRM_RM_OPERANDS(MEM, BP, DI, 1, 0),
	MODRM_RM_OPERANDS(MEM, SI, NONE, 1, 0),
	MODRM_RM_OPERANDS(MEM, DI, NONE, 1, 0),
	MODRM_RM_OPERANDS(MEM, BP, NONE, 1, 0),
	MODRM_RM_OPERANDS(MEM, BX, NONE, 1, 0),

	// Mod 10
	MODRM_RM_OPERANDS(MEM, BX, SI, 2, 0),
	MODRM_RM_OPERANDS(MEM, BX, DI, 2, 0),
	MODRM_RM_OPERANDS(MEM, BP, SI, 2, 0),
	MODRM_RM_OPERANDS(MEM, BP, DI, 2, 0),
	MODRM_RM_OPERANDS(MEM, SI, NONE, 2, 0),
	MODRM_RM_OPERANDS(MEM, DI, NONE, 2, 0),
	MODRM_RM_OPERANDS(MEM, BP, NONE, 2, 0),
	MODRM_RM_OPERANDS(MEM, BX, NONE, 2, 0),
};

static const ModRmRmOperand g_modRmRmOperands32[24] =
{
	// Mod 00
	MODRM_RM_OPERANDS(MEM, EAX, NONE, 0, 0),
	MODRM_RM_OPERANDS(MEM, ECX, NONE, 0, 0),
	MODRM_RM_OPERANDS(MEM, EDX, NONE, 0, 0),
	MODRM_RM_OPERANDS(MEM, EBX, NONE, 0, 0),
	MODRM_RM_OPERANDS(NONE, NONE, NONE, 0, 1), // SIB
	MODRM_RM_OPERANDS(MEM, NONE, NONE, 4, 0),
	MODRM_RM_OPERANDS(MEM, ESI, NONE, 0, 0),
	MODRM_RM_OPERANDS(MEM, EDI, NONE, 0, 0),

	// Mod 01
	MODRM_RM_OPERANDS(MEM, EAX, NONE, 1, 0),
	MODRM_RM_OPERANDS(MEM, ECX, NONE, 1, 0),
	MODRM_RM_OPERANDS(MEM, EDX, NONE, 1, 0),
	MODRM_RM_OPERANDS(MEM, EBX, NONE, 1, 0),
	MODRM_RM_OPERANDS(NONE, NONE, NONE, 1, 1), // SIB
	MODRM_RM_OPERANDS(MEM, EBP, NONE, 1, 0),
	MODRM_RM_OPERANDS(MEM, ESI, NONE, 1, 0),
	MODRM_RM_OPERANDS(MEM, EDI, NONE, 1, 0),

	// Mod 10
	MODRM_RM_OPERANDS(MEM, EAX, NONE, 4, 0),
	MODRM_RM_OPERANDS(MEM, ECX, NONE, 4, 0),
	MODRM_RM_OPERANDS(MEM, EDX, NONE, 4, 0),
	MODRM_RM_OPERANDS(MEM, EBX, NONE, 4, 0),
	MODRM_RM_OPERANDS(NONE, NONE, NONE, 4, 1), // SIB
	MODRM_RM_OPERANDS(MEM, EBP, NONE, 4, 0),
	MODRM_RM_OPERANDS(MEM, ESI, NONE, 4, 0),
	MODRM_RM_OPERANDS(MEM, EDI, NONE, 4, 0),
};

static const ModRmRmOperand g_modRmRmOperands64[64] =
{
	// Mod 00
	MODRM_RM_OPERANDS(MEM, RAX, NONE, 0, 0),
	MODRM_RM_OPERANDS(MEM, RCX, NONE, 0, 0),
	MODRM_RM_OPERANDS(MEM, RDX, NONE, 0, 0),
	MODRM_RM_OPERANDS(MEM, RBX, NONE, 0, 0),
	MODRM_RM_OPERANDS(NONE, NONE, NONE, 0, 1), // SIB
	MODRM_RM_OPERANDS(MEM, NONE, NONE, 4, 0),
	MODRM_RM_OPERANDS(MEM, RSI, NONE, 0, 0),
	MODRM_RM_OPERANDS(MEM, RDI, NONE, 0, 0),

	// Mod 01
	MODRM_RM_OPERANDS(MEM, RAX, NONE, 1, 0),
	MODRM_RM_OPERANDS(MEM, RCX, NONE, 1, 0),
	MODRM_RM_OPERANDS(MEM, RDX, NONE, 1, 0),
	MODRM_RM_OPERANDS(MEM, RBX, NONE, 1, 0),
	MODRM_RM_OPERANDS(NONE, NONE, NONE, 1, 1), // SIB
	MODRM_RM_OPERANDS(MEM, RBP, NONE, 1, 0),
	MODRM_RM_OPERANDS(MEM, RSI, NONE, 1, 0),
	MODRM_RM_OPERANDS(MEM, RDI, NONE, 1, 0),

	// Mod 10
	MODRM_RM_OPERANDS(MEM, RAX, NONE, 4, 0),
	MODRM_RM_OPERANDS(MEM, RCX, NONE, 4, 0),
	MODRM_RM_OPERANDS(MEM, RDX, NONE, 4, 0),
	MODRM_RM_OPERANDS(MEM, RBX, NONE, 4, 0),
	MODRM_RM_OPERANDS(NONE, NONE, NONE, 4, 1), // SIB
	MODRM_RM_OPERANDS(MEM, RBP, NONE, 4, 0),
	MODRM_RM_OPERANDS(MEM, RSI, NONE, 4, 0),
	MODRM_RM_OPERANDS(MEM, RDI, NONE, 4, 0),

	// Mod 11 (Pad)
	MODRM_RM_OPERANDS(NONE, NONE, NONE, 0, 0),
	MODRM_RM_OPERANDS(NONE, NONE, NONE, 0, 0),
	MODRM_RM_OPERANDS(NONE, NONE, NONE, 0, 0),
	MODRM_RM_OPERANDS(NONE, NONE, NONE, 0, 0),
	MODRM_RM_OPERANDS(NONE, NONE, NONE, 0, 0),
	MODRM_RM_OPERANDS(NONE, NONE, NONE, 0, 0),
	MODRM_RM_OPERANDS(NONE, NONE, NONE, 0, 0),
	MODRM_RM_OPERANDS(NONE, NONE, NONE, 0, 0),

	// REX.B, Mod 00
	MODRM_RM_OPERANDS(MEM, R8, NONE, 0, 0),
	MODRM_RM_OPERANDS(MEM, R9, NONE, 0, 0),
	MODRM_RM_OPERANDS(MEM, R10, NONE, 0, 0),
	MODRM_RM_OPERANDS(MEM, R11, NONE, 0, 0),
	MODRM_RM_OPERANDS(NONE, NONE, NONE, 0, 1),
	MODRM_RM_OPERANDS(MEM, RIP, NONE, 0, 0),
	MODRM_RM_OPERANDS(MEM, R14, NONE, 0, 0),
	MODRM_RM_OPERANDS(MEM, R15, NONE, 0, 0),

	// REX.B, Mod 01
	MODRM_RM_OPERANDS(MEM, R8, NONE, 1, 0),
	MODRM_RM_OPERANDS(MEM, R9, NONE, 1, 0),
	MODRM_RM_OPERANDS(MEM, R10, NONE, 1, 0),
	MODRM_RM_OPERANDS(MEM, R11, NONE, 1, 0),
	MODRM_RM_OPERANDS(NONE, NONE, NONE, 1, 1),
	MODRM_RM_OPERANDS(MEM, R13, NONE, 1, 0),
	MODRM_RM_OPERANDS(MEM, R14, NONE, 1, 0),
	MODRM_RM_OPERANDS(MEM, R15, NONE, 1, 0),

	// REX.B, Mod 10
	MODRM_RM_OPERANDS(MEM, R8, NONE, 4, 0),
	MODRM_RM_OPERANDS(MEM, R9, NONE, 4, 0),
	MODRM_RM_OPERANDS(MEM, R10, NONE, 4, 0),
	MODRM_RM_OPERANDS(MEM, R11, NONE, 4, 0),
	MODRM_RM_OPERANDS(NONE, NONE, NONE, 4, 1),
	MODRM_RM_OPERANDS(MEM, R13, NONE, 4, 0),
	MODRM_RM_OPERANDS(MEM, R14, NONE, 4, 0),
	MODRM_RM_OPERANDS(MEM, R15, NONE, 4, 0)
};

#define MODRM_SIB_OPERAND_ROW32(scale, index, base5) \
	{X86_MEM, {X86_EAX, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_ECX, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_EDX, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_EBX, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_ESP, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {base5, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_ESI, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_EDI, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_R8D, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_R9D, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_R10D, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_R11D, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_R12D, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_R13D, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_R14D, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_R15D, index}, X86_DS, 4, scale, 0}

#define MODRM_SIB_OPERAND_COL32(scale, base5) \
	MODRM_SIB_OPERAND_ROW32(scale, X86_EAX, base5), \
	MODRM_SIB_OPERAND_ROW32(scale, X86_ECX, base5), \
	MODRM_SIB_OPERAND_ROW32(scale, X86_EDX, base5), \
	MODRM_SIB_OPERAND_ROW32(scale, X86_EBX, base5), \
	MODRM_SIB_OPERAND_ROW32(0, X86_NONE, base5), \
	MODRM_SIB_OPERAND_ROW32(scale, X86_EBP, base5), \
	MODRM_SIB_OPERAND_ROW32(scale, X86_ESI, base5), \
	MODRM_SIB_OPERAND_ROW32(scale, X86_EDI, base5), \
	MODRM_SIB_OPERAND_ROW32(scale, X86_R8D, base5), \
	MODRM_SIB_OPERAND_ROW32(scale, X86_R9D, base5), \
	MODRM_SIB_OPERAND_ROW32(scale, X86_R10D, base5), \
	MODRM_SIB_OPERAND_ROW32(scale, X86_R11D, base5), \
	MODRM_SIB_OPERAND_ROW32(scale, X86_R12D, base5), \
	MODRM_SIB_OPERAND_ROW32(scale, X86_R13D, base5), \
	MODRM_SIB_OPERAND_ROW32(scale, X86_R14D, base5), \
	MODRM_SIB_OPERAND_ROW32(scale, X86_R15D, base5)

static const X86Operand g_sibTable32[4096] =
{
	// Mod 0
	MODRM_SIB_OPERAND_COL32(1, X86_NONE),
	MODRM_SIB_OPERAND_COL32(2, X86_NONE),
	MODRM_SIB_OPERAND_COL32(4, X86_NONE),
	MODRM_SIB_OPERAND_COL32(8, X86_NONE),

	// Mod 1,
	MODRM_SIB_OPERAND_COL32(1, X86_EBP),
	MODRM_SIB_OPERAND_COL32(2, X86_EBP),
	MODRM_SIB_OPERAND_COL32(4, X86_EBP),
	MODRM_SIB_OPERAND_COL32(8, X86_EBP),

	// Mod 2
	MODRM_SIB_OPERAND_COL32(1, X86_EBP),
	MODRM_SIB_OPERAND_COL32(2, X86_EBP),
	MODRM_SIB_OPERAND_COL32(4, X86_EBP),
	MODRM_SIB_OPERAND_COL32(8, X86_EBP),

	// Mod 3 (Pad)
	MODRM_SIB_OPERAND_COL32(0, X86_NONE),
	MODRM_SIB_OPERAND_COL32(0, X86_NONE),
	MODRM_SIB_OPERAND_COL32(0, X86_NONE),
	MODRM_SIB_OPERAND_COL32(0, X86_NONE),
};

#define MODRM_SIB_OPERAND_ROW64(scale, index, base5) \
	{X86_MEM, {X86_RAX, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_RCX, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_RDX, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_RBX, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_RSP, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {base5, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_RSI, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_RDI, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_R8, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_R9, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_R10, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_R11, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_R12, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_R13, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_R14, index}, X86_DS, 4, scale, 0}, \
	{X86_MEM, {X86_R15, index}, X86_DS, 4, scale, 0}

#define MODRM_SIB_OPERAND_COL64(scale, base5) \
	MODRM_SIB_OPERAND_ROW64(scale, X86_RAX, base5), \
	MODRM_SIB_OPERAND_ROW64(scale, X86_RCX, base5), \
	MODRM_SIB_OPERAND_ROW64(scale, X86_RDX, base5), \
	MODRM_SIB_OPERAND_ROW64(scale, X86_RBX, base5), \
	MODRM_SIB_OPERAND_ROW64(0, X86_NONE, base5), \
	MODRM_SIB_OPERAND_ROW64(scale, X86_RBP, base5), \
	MODRM_SIB_OPERAND_ROW64(scale, X86_RSI, base5), \
	MODRM_SIB_OPERAND_ROW64(scale, X86_RDI, base5), \
	MODRM_SIB_OPERAND_ROW64(scale, X86_R8, base5), \
	MODRM_SIB_OPERAND_ROW64(scale, X86_R9, base5), \
	MODRM_SIB_OPERAND_ROW64(scale, X86_R10, base5), \
	MODRM_SIB_OPERAND_ROW64(scale, X86_R11, base5), \
	MODRM_SIB_OPERAND_ROW64(scale, X86_R12, base5), \
	MODRM_SIB_OPERAND_ROW64(scale, X86_R13, base5), \
	MODRM_SIB_OPERAND_ROW64(scale, X86_R14, base5), \
	MODRM_SIB_OPERAND_ROW64(scale, X86_R15, base5)


static const X86Operand g_sibTable64[4096] =
{
	// Mod 0
	MODRM_SIB_OPERAND_COL64(1, X86_NONE),
	MODRM_SIB_OPERAND_COL64(2, X86_NONE),
	MODRM_SIB_OPERAND_COL64(4, X86_NONE),
	MODRM_SIB_OPERAND_COL64(8, X86_NONE),

	// Mod 1,
	MODRM_SIB_OPERAND_COL64(1, X86_RBP),
	MODRM_SIB_OPERAND_COL64(2, X86_RBP),
	MODRM_SIB_OPERAND_COL64(4, X86_RBP),
	MODRM_SIB_OPERAND_COL64(8, X86_RBP),

	// Mod 2
	MODRM_SIB_OPERAND_COL64(1, X86_RBP),
	MODRM_SIB_OPERAND_COL64(2, X86_RBP),
	MODRM_SIB_OPERAND_COL64(4, X86_RBP),
	MODRM_SIB_OPERAND_COL64(8, X86_RBP),

	// Mod 3 (PAD)
	MODRM_SIB_OPERAND_COL64(0, X86_NONE),
	MODRM_SIB_OPERAND_COL64(0, X86_NONE),
	MODRM_SIB_OPERAND_COL64(0, X86_NONE),
	MODRM_SIB_OPERAND_COL64(0, X86_NONE),
};

static const X86Operand* const g_sibTables[2] = {g_sibTable32, g_sibTable64};

static const ModRmRmOperand* const g_modRmRmOperands[4] =
{
	g_modRmRmOperands16, g_modRmRmOperands32, g_modRmRmOperands64
};

static const uint8_t g_operandOrder[2][2] = {{0, 1}, {1, 0}};
static const uint8_t g_decoderModeSizeXref[3] = {2, 4, 8};
static const uint8_t g_decoderModeSimdSizeXref[4] = {8, 16, 32, 64};
static const uint8_t g_sseOperandSizes[3] = {16, 32, 64};
static const uint8_t g_simdOperandSizes[4] = {8, 16, 32, 64};

static const X86OperandType g_gpr8[16] =
{
	// FIXME: x64
	// X86_AL, X86_CL, X86_DL, X86_BL, X86_BPL, X86_SPL, X86_SIL, X86_DIL,
	X86_AL, X86_CL, X86_DL, X86_BL, X86_AH, X86_CH, X86_DH, X86_BH,
	X86_R8B, X86_R9B, X86_R10B, X86_R11B, X86_R12B, X86_R13B, X86_R14B, X86_R15B
};

static const X86OperandType g_gpr16[16] =
{
	X86_AX, X86_CX, X86_DX, X86_BX, X86_SP, X86_BP, X86_SI, X86_DI,
	X86_R8W, X86_R9W, X86_R10W, X86_R11W, X86_R12W, X86_R13W, X86_R14W, X86_R15W
};

static const X86OperandType g_gpr32[16] =
{
	X86_EAX, X86_ECX, X86_EDX, X86_EBX, X86_ESP, X86_EBP, X86_ESI, X86_EDI,
	X86_R8D, X86_R9D, X86_R10D, X86_R11D, X86_R12D, X86_R13D, X86_R14D, X86_R15D
};

static const X86OperandType g_gpr64[16] =
{
	X86_RAX, X86_RCX, X86_RDX, X86_RBX, X86_RSP, X86_RBP, X86_RSI, X86_RDI,
	X86_R8, X86_R9, X86_R10, X86_R11, X86_R12, X86_R13, X86_R14, X86_R15
};

static const X86OperandType* const g_gprOperandTypes[5] = {g_gpr8, g_gpr16, g_gpr32, 0, g_gpr64};

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

static __inline void InitImmediate(X86Operand* const operand, uint64_t val, uint8_t size)
{
	operand->operandType = X86_IMMEDIATE;
	operand->size = size;
	operand->immediate = SIGN_EXTEND64(val, size);
}


static __inline void InitImmediateUnsigned(X86Operand* const operand, uint64_t val, uint8_t size)
{
	operand->operandType = X86_IMMEDIATE;
	operand->size = size;
	operand->immediate = val;
}


static __inline bool Fetch(X86DecoderState* const state, size_t len, uint8_t* result)
{
	if ((state->instr->length == 15) || (!state->fetch(state->ctxt, len, result)))
	{
		state->instr->flags.insufficientLength = 1;
		return false;
	}
	memcpy(&state->instr->bytes[state->currentByte], result, len);
	state->currentByte += (uint8_t)len;
	state->instr->length += len;
	return true;
}


static __inline bool ProcessPrimaryOpcode(X86DecoderState* const state)
{
	uint8_t opcode;

	// Grab a byte from the machine
	if (!Fetch(state, 1, &opcode))
		return false;

	if (!g_primaryDecoders[opcode](state, opcode))
		return false;

	// Once REX prefixes start, no other prefixes can follow
	if (state->lastBytePrefix && (state->rex.byte != 0) && (!state->lastPrefixRex))
		return false;

	return true;
}


static __inline bool IsModRmRmFieldReg(ModRmByte modRm)
{
	if (modRm.mod == 3)
		return true;
	return false;
}


static __inline void DecodeOperandGpr(X86Operand* const operand, uint8_t reg, uint8_t operandSize)
{
	operand->operandType = g_gprOperandTypes[operandSize >> 1][reg];
	operand->size = operandSize;
}


static __inline void DecodeModRmRmFieldReg(int8_t operandSize, X86Operand* const operand, ModRmByte modRm, RexByte rex)
{
	const uint8_t reg = ((rex.b << 3) | modRm.rm);
	DecodeOperandGpr(operand, reg, operandSize);
}


static __inline bool DecodeModRmRmFieldMemory(X86DecoderState* const state, uint8_t operandSize,
		X86Operand* const operand, ModRmByte modRm)
{
	const size_t operandTableIndex = ((state->rex.b << 5) | ((modRm.mod << 3) | modRm.rm));
	const ModRmRmOperand* const operandTableEntry = &g_modRmRmOperands[state->addrMode][operandTableIndex];
	uint8_t dispBytes = operandTableEntry->dispBytes;

	if (operandTableEntry->sib)
	{
		static const uint8_t tables[] = {0, 0, 1};
		const uint8_t table = tables[state->addrMode];
		static const uint8_t modDispBytes[] = {4, 1, 4};
		SibByte sib;
		uint16_t operandSel;

		if (!Fetch(state, 1, &sib.byte))
			return false;

		// Compute lookup indices
		operandSel = (((modRm.mod << 10) | (sib.scale << 8)
			| (state->rex.x << 7) | (sib.index << 4))
			| ((state->rex.b << 3) | sib.base));

		memcpy(operand, &g_sibTables[table][operandSel], sizeof(X86Operand));

		// The ModRm.Mod=0 && SIB.Base=5 has a 4 byte displacement.
		if (sib.base == 5)
			dispBytes = modDispBytes[modRm.mod];
	}
	else
	{
		memcpy(operand, &operandTableEntry->operand, sizeof(X86Operand));

		if (state->mode == X86_64BIT)
		{
			// RIP Relative address mode
		}
	}
	operand->size = operandSize;

	if (dispBytes)
	{
		uint64_t displacement;

		displacement = 0;
		if (!Fetch(state, dispBytes, (uint8_t*)&displacement))
			return false;

		// Now sign extend the displacement to 64bits.
		operand->immediate = SIGN_EXTEND64(displacement, operandTableEntry->dispBytes);
	}

	return true;
}


static __inline bool DecodeModRmRmField(X86DecoderState* const state, uint8_t operandSize,
		X86Operand* const operand, ModRmByte modRm)
{
	if (IsModRmRmFieldReg(modRm))
	{
		DecodeModRmRmFieldReg(operandSize, operand, modRm, state->rex);
		return true;
	}
	return DecodeModRmRmFieldMemory(state, operandSize, operand, modRm);
}


static __inline void DecodeModRmRegField(int8_t operandSize,
	X86Operand* const operand, ModRmByte modRm, RexByte rex)
{
	const uint8_t reg = ((rex.r << 3) | modRm.reg);
	DecodeOperandGpr(operand, reg, operandSize);
}


static __inline bool DecodeModRm(X86DecoderState* const state, uint8_t operandSize, X86Operand* const operands)
{
	ModRmByte modRm;

	// Fetch the ModRM byte
	if (!Fetch(state, 1, (uint8_t*)&modRm.byte))
		return false;
	if (!DecodeModRmRmField(state, operandSize, &operands[0], modRm))
		return false;
	DecodeModRmRegField(operandSize, &operands[1], modRm, state->rex);

	return true;
}


static __inline bool DecodeModRmRev(X86DecoderState* const state, uint8_t operandSize, X86Operand* const operands)
{
	ModRmByte modRm;

	// Fetch the ModRM byte
	if (!Fetch(state, 1, (uint8_t*)&modRm.byte))
		return false;
	if (!DecodeModRmRmField(state, operandSize, &operands[1], modRm))
		return false;
	DecodeModRmRegField(operandSize, &operands[0], modRm, state->rex);

	return true;
}


static __inline bool DecodeModRmDirection(X86DecoderState* const state, uint8_t operandSize, X86Operand* const operands, uint8_t direction)
{
	const uint8_t operand0 = direction;
	const uint8_t operand1 = ((~direction) & 1);
	ModRmByte modRm;

	// Fetch the ModRM byte
	if (!Fetch(state, 1, (uint8_t*)&modRm.byte))
		return false;
	if (!DecodeModRmRmField(state, operandSize, &operands[operand0], modRm))
		return false;
	DecodeModRmRegField(operandSize, &operands[operand1], modRm, state->rex);

	return true;
}


static __inline bool DecodeImmediate(X86DecoderState* const state, X86Operand* const operand, uint8_t operandSize)
{
	uint64_t imm;

	// Fetch the immediate value
	imm = 0;
	if (!Fetch(state, operandSize, (uint8_t*)&imm))
		return false;
	InitImmediate(operand, imm, operandSize);

	return true;
}


static __inline void DecodeOneOperandOpcodeGpr(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];
	const uint8_t reg = ((state->rex.w << 3) | (opcode & 7));
	DecodeOperandGpr(&state->instr->operands[0], reg, operandSize);
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
	const uint8_t direction = ((opcode & 2) >> 1);
	const uint8_t operandSizeBit = (opcode & 1); // 1byte or default operand size
	const size_t operation = ((opcode & 0x8) >> 1) | ((opcode >> 4) & 7);
	const uint8_t operandSize = operandSizes[operandSizeBit];

	state->instr->op = primaryOpCodeTableArithmetic[operation];
	state->instr->operandCount = 2;

	if (!DecodeModRmDirection(state, operandSize, state->instr->operands, direction))
		return false;

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

	if (!DecodeImmediate(state, &state->instr->operands[1], operandSize))
		return false;
	DecodeOperandGpr(&state->instr->operands[0], 0, operandSize);

	state->instr->op = primaryOpCodeTableArithmetic[operation];
	state->instr->operandCount = 2;

	return true;
}


static bool DecodePushPopSegment(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[2] = {X86_PUSH, X86_POP};
	static const X86OperandType operands[2][2] = {{X86_ES, X86_SS}, {X86_CS, X86_DS}};
	const size_t operandSelector = ((opcode & 0xf) >> 3);
	static const uint8_t operandSizes[3] = {2, 2};

	if (state->mode == X86_64BIT)
		return false;

	state->instr->op = operations[opcode & 1];
	state->instr->operandCount = 1;

	state->instr->operands[0].operandType = operands[operandSelector][(opcode >> 4) & 1];
	state->instr->operands[0].size = operandSizes[state->operandMode];

	return true;
}


static bool DecodeAscii(X86DecoderState* const state, uint8_t opcode)
{
	const size_t opCol = (opcode >> 3) & 1;
	static const X86Operation ops[2][2] = {{X86_DAA, X86_AAA}, {X86_DAS, X86_AAS}};
	if (state->mode == X86_64BIT)
		return false;
	state->instr->op = ops[opCol][(opcode >> 4) & 1];
	return true;
}


static __inline void EvaluateRexPrefix(X86DecoderState* const state, uint8_t opcode)
{
	// Intel 2a 2.2.1.2 "More on REX Prefix Fields" says 66
	// prefix is ignored if REX.W is set.
	static const X86DecoderMode modes[] =
	{
		X86_32BIT, X86_16BIT,
		X86_64BIT, X86_64BIT
	};
	const uint8_t mode = ((opcode >> 2) & 2) // REX.W
		| state->instr->flags.operandSizeOverride;

	state->rex.byte = opcode;
	state->lastBytePrefix = true;
	state->lastPrefixRex = true;

	// NOTE: This should only ever be called in 64bit mode.
	state->operandMode = modes[mode];
}


static bool DecodeInc(X86DecoderState* const state, uint8_t opcode)
{
	if (state->mode == X86_64BIT)
	{
		EvaluateRexPrefix(state, opcode);
		return ProcessPrimaryOpcode(state);
	}
	DecodeOneOperandOpcodeGpr(state, opcode);
	state->instr->op = X86_INC;
	state->instr->operandCount = 1;
	return true;
}


static bool DecodeDec(X86DecoderState* const state, uint8_t opcode)
{
	if (state->mode == X86_64BIT)
	{
		EvaluateRexPrefix(state, opcode);
		return ProcessPrimaryOpcode(state);
	}
	DecodeOneOperandOpcodeGpr(state, opcode);
	state->instr->op = X86_DEC;
	state->instr->operandCount = 1;
	return true;
}


static bool DecodePushPopGpr(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[2] = {X86_PUSH, X86_POP};
	const uint8_t operandSizes[] =
	{
		g_decoderModeSizeXref[state->operandMode],
		g_decoderModeSizeXref[state->operandMode],
		8
	};
	const uint8_t reg = ((state->rex.w << 3) | (opcode & 7));
	const uint8_t operandSize = operandSizes[state->mode];

	// Operand size is ignored in 64bit mode and can only encode 64bit GPRs.
	DecodeOperandGpr(&state->instr->operands[0], reg, operandSize);

	state->instr->op = operations[(opcode >> 3) & 1];
	state->instr->operandCount = 1;

	return true;
}


static bool DecodeJmpConditional(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation ops[16] =
	{
		X86_JO, X86_JNO, X86_JB, X86_JNB, X86_JZ, X86_JNZ, X86_JBE, X86_JNBE,
		X86_JS, X86_JNS, X86_JP, X86_JNP, X86_JL, X86_JNL, X86_JLE, X86_JNLE
	};
	static const uint8_t operandSizes[2][3] =
	{
		{1, 1, 1},
		{2, 4, 4}
	};
	const uint8_t operandSizeBit = ((opcode >> 7) & 1);
	const uint8_t operandSize = operandSizes[operandSizeBit][state->operandMode];

	// Grab the offset
	if (!DecodeImmediate(state, &state->instr->operands[0], operandSize))
		return false;

	state->instr->op = ops[opcode & 0xf];
	state->instr->operandCount = 1;

	return true;
}


static bool DecodePushPopAll(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation ops[3][2] =
	{
		{X86_PUSHA, X86_POPA},
		{X86_PUSHAD, X86_POPAD}
	};

	if (state->addrMode == X86_64BIT)
		return false;

	state->instr->op = ops[state->operandMode][opcode & 1];
	state->instr->operandCount = 0;

	return true;
}


static bool DecodeBound(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation ops[3] = {X86_BOUND, X86_BOUND, X86_INVALID};
	const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];
	ModRmByte modRm;

	(void)opcode;

	if (ops[state->addrMode] == X86_INVALID)
		return false;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (IsModRmRmFieldReg(modRm))
		return false;
	if (!DecodeModRmRmFieldMemory(state, operandSize, &state->instr->operands[1], modRm))
		return false;
	DecodeModRmRegField(operandSize, &state->instr->operands[0], modRm, state->rex);

	state->instr->op = ops[state->addrMode];
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeAarplMovSxd(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation ops[3] = {X86_ARPL, X86_ARPL, X86_MOVSXD};
	const uint8_t opSize[3] = {2, 2, g_decoderModeSizeXref[state->operandMode]};
	static const uint8_t order[3] = {0, 0, 1};

	(void)opcode;

	if (!DecodeModRmDirection(state, opSize[state->addrMode], state->instr->operands, order[state->addrMode]))
		return false;

	state->instr->op = ops[state->addrMode];
	state->instr->operandCount = 2;

	return true;
}


static bool DecodePushImm(X86DecoderState* const state, uint8_t opcode)
{
	static const uint8_t operandModes[3] = {2, 4, 4};
	const uint8_t operandSizes[2] = {operandModes[state->operandMode], 1};
	const uint8_t operandBytes = operandSizes[(opcode >> 1) & 1];

	// Fetch the immediate value
	if (!DecodeImmediate(state, &state->instr->operands[0], operandBytes))
		return false;

	state->instr->op = X86_PUSH;
	state->instr->operandCount = 1;

	return true;
}


static bool DecodeGroup1(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation group1Operations[] =
	{
		X86_ADD, X86_OR, X86_ADC, X86_SBB,
		X86_AND, X86_SUB, X86_XOR, X86_CMP
	};
	static const uint8_t operandSizes[2][3] =
	{
		{1, 1, 1},
		{2, 4, 8}
	};
	static const uint8_t immSizes[] = {2, 4, 4};
	const uint8_t immOperandSizes[] = {1, immSizes[state->operandMode], 1, 1};
	const uint8_t width = (opcode & 1);
	const uint8_t immOperandSizeBits = (opcode & 3);
	const uint8_t dstSize = operandSizes[width][state->operandMode];
	const uint8_t immSize = immOperandSizes[immOperandSizeBits];
	ModRmByte modRm;

	if ((state->mode == X86_64BIT) && (opcode == 0x82))
	{
		// This form is invalid in 64bit mode
		return false;
	}

	// Fetch the modrm byte
	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!DecodeModRmRmField(state, dstSize, &state->instr->operands[0], modRm))
		return false;

	// Operation is encoded in the reg field
	state->instr->op = group1Operations[modRm.reg];
	state->instr->operandCount = 2;

	// Fetch and decode the source
	if (!DecodeImmediate(state, &state->instr->operands[1], immSize))
		return false;

	return true;
}


static bool DecodeTestXchgModRm(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation ops[2] = {X86_TEST, X86_XCHG};
	const uint8_t operandSizes[] = {1, g_decoderModeSizeXref[state->operandMode]};
	const uint8_t operandSizeSel = (opcode & 1);
	const size_t operation = ((opcode >> 1) & 1);
	const uint8_t operandSize = operandSizes[operandSizeSel];

	if (!DecodeModRm(state, operandSize, state->instr->operands))
		return false;

	state->instr->op = ops[operation];
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeNop(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	state->instr->op = X86_NOP;
	return true;
}


static bool DecodeNopModRm(X86DecoderState* const state, uint8_t opcode)
{
	X86Operand operands[2];
	(void)opcode;
	memset(operands, 0, sizeof(operands));
	if (!DecodeModRm(state, g_decoderModeSizeXref[state->operandMode], operands))
		return false;
	state->instr->op = X86_NOP;
	return true;
}


static bool DecodeXchgRax(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];
	const uint8_t reg = (opcode & 0xf);

	DecodeOperandGpr(&state->instr->operands[0], reg, operandSize);
	DecodeOperandGpr(&state->instr->operands[1], 0, operandSize);

	state->instr->op = X86_XCHG;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeMovOffset(X86DecoderState* const state, uint8_t opcode)
{
	uint64_t offset;
	const uint8_t operandSizes[2] = {1, g_decoderModeSizeXref[state->operandMode]};
	const uint8_t sizeBit = opcode & 1;
	const uint8_t orderBit = (opcode >> 1) & 1;
	const uint8_t operandSize = operandSizes[sizeBit];
	const uint8_t offsetSize = g_decoderModeSizeXref[state->addrMode];
	const uint8_t operand0 = g_operandOrder[orderBit][0];
	const uint8_t operand1 = g_operandOrder[orderBit][1];

	offset = 0;
	if (!Fetch(state, offsetSize, (uint8_t*)&offset))
		return false;
	DecodeOperandGpr(&state->instr->operands[operand0], 0, operandSize);

	state->instr->operands[operand1].operandType = X86_MEM;
	state->instr->operands[operand1].size = operandSize;
	state->instr->operands[operand1].immediate = offset;

	state->instr->op = X86_MOV;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeMovCmpString(X86DecoderState* const state, uint8_t opcode)
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


static bool DecodeGroup2(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSizes[2] = {1, g_decoderModeSizeXref[state->operandMode]};
	const uint8_t operandSizeBit = opcode & 1;
	static const X86Operation op[8] =
	{
		X86_ROL, X86_ROR, X86_RCL, X86_RCR,
		X86_SHL, X86_SHR, X86_SHL, X86_SAR
	};
	const uint8_t operandSize = operandSizes[operandSizeBit];
	ModRmByte modRm;

	// Grab the ModRM byte
	if (!Fetch(state, 1, &modRm.byte))
		return false;

	// The destination is either a register or memory depending on the Mod bits
	if (!DecodeModRmRmField(state, operandSize, &state->instr->operands[0], modRm))
		return false;

	// The source operand is guaranteed to be a byte
	state->instr->operands[1].size = 1;

	// High nibble, 1 bit is clear
	if ((opcode & 0x10) == 0)
	{
		// Then grab the immediate
		if (!DecodeImmediate(state, &state->instr->operands[1], 1))
			return false;
	}
	else if ((opcode & 2) == 0)
	{
		// The source is an immediate == 1
		InitImmediateUnsigned(&state->instr->operands[1], 1, 1);
	}
	else
	{
		// The source is in cl
		state->instr->operands[1].operandType = X86_CL;
	}

	// Reg field in ModRM actually selects operation for Group2
	state->instr->op = op[modRm.reg];
	state->instr->operandCount = 2;

	return true;
}


static __inline bool DecodeLoadSegment(X86DecoderState* const state, X86Operation op)
{
	static const uint8_t destSizes[] = {2, 4, 4};
	static const uint8_t srcSizes[] = {4, 6, 10};
	ModRmByte modRm;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (IsModRmRmFieldReg(modRm))
		return false;
	if (!DecodeModRmRmFieldMemory(state, srcSizes[state->operandMode], &state->instr->operands[1], modRm))
		return false;
	DecodeModRmRegField(destSizes[state->operandMode], &state->instr->operands[0], modRm, state->rex);

	state->instr->op = op;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeLes(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (state->mode == X86_64BIT)
	{
		// FIXME: VEX escape
		return false;
	}
	if (!DecodeLoadSegment(state, X86_LES))
		return false;
	return true;
}


static bool DecodeLds(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (state->mode == X86_64BIT)
	{
		// FIXME: VEX escape
		return false;
	}
	if (!DecodeLoadSegment(state, X86_LDS))
		return false;
	return true;
}


static bool DecodeGroup11(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t sizeBit = (opcode & 1);
	static const uint8_t dstSizes[2][3] =
	{
		{1, 1, 1},
		{2, 4, 8}
	};
	static const uint8_t immSizes[2][3] =
	{
		{1, 1, 1},
		{2, 4, 4}
	};
	const uint8_t dstSize = dstSizes[sizeBit][state->operandMode];
	const uint8_t immSize = immSizes[sizeBit][state->operandMode];
	ModRmByte modRm;

	if (!Fetch(state, 1, &modRm.byte))
		return false;

	if (modRm.reg == 0)
	{
		if (!DecodeModRmRmField(state, dstSize, &state->instr->operands[0], modRm))
			return false;
		if (!DecodeImmediate(state, &state->instr->operands[1], immSize))
			return false;

		state->instr->op = X86_MOV;
		state->instr->operandCount = 2;
	}
	else if ((modRm.reg == 7) && (IsModRmRmFieldReg(modRm)))
	{
		static const X86Operation operations[] = {X86_XABORT, X86_XBEGIN};

		if (!DecodeImmediate(state, &state->instr->operands[0], immSize))
			return false;

		state->instr->op = operations[sizeBit];
		state->instr->operandCount = 1;
	}
	else
	{
		return false;
	}

	return true;
}


static bool DecodeAsciiAdjust(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operation[4] = {X86_AAM, X86_AAD};
	const uint8_t op = (opcode & 1);

	if (state->mode == X86_64BIT)
		return false;

	if (!DecodeImmediate(state, &state->instr->operands[0], 1))
		return false;

	state->instr->op = operation[op];
	state->instr->operandCount = 1;

	return true;
}


static bool DecodeSalc(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	state->instr->op = X86_SALC;
	return true;
}


static bool DecodeXlat(X86DecoderState* const state, uint8_t opcode)
{
	static const X86OperandType sources[3] = {X86_BX, X86_EBX, X86_RBX};
	const X86OperandType source = sources[state->addrMode];

	(void)opcode;

	// Store in AL
	state->instr->operands[0].operandType = X86_AL;
	state->instr->operands[0].size = 1;

	// Value fetched from memory
	state->instr->operands[1].operandType = X86_MEM;
	state->instr->operands[1].size = 1;
	state->instr->operands[1].segment = X86_DS;
	state->instr->operands[1].components[0] = X86_AL;
	state->instr->operands[1].components[1] = source;

	state->instr->op = X86_XLAT;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeFPArithmetic(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[8] =
	{
		X86_FADD, X86_FMUL, X86_FCOM, X86_FCOMP,
		X86_FSUB, X86_FSUBR, X86_FDIV, X86_FDIVR
	};
	ModRmByte modRm;

	if (!Fetch(state, 1, &modRm.byte))
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
		state->instr->operands[1].operandType = g_fpSources[modRm.rm];
		state->instr->operands[1].size = 4;
	}

	state->instr->operands[0].operandType = X86_ST0;
	state->instr->operands[0].size = 10;

	state->instr->op = operations[modRm.reg];
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeFPLoadStore(X86DecoderState* const state, uint8_t opcode)
{
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;

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
			g_decoderModeSizeXref[state->addrMode] * 7, 2,
			g_decoderModeSizeXref[state->addrMode] * 7, 2
		};

		state->instr->op = operations[modRm.reg];
		if (state->instr->op == X86_INVALID)
			return false;

		state->instr->operandCount = 2;

		// Memory!
		if (!DecodeModRmRmFieldMemory(state, 4, &state->instr->operands[1], modRm))
			return false;
		state->instr->operands[1].size = operandSizes[modRm.reg];
	}
	else if (modRm.reg < 2)
	{
		static const X86Operation operations[2] = {X86_FLD, X86_FXCH};

		state->instr->operands[1].operandType = g_fpSources[modRm.rm];
		state->instr->operands[1].size = 10;

		state->instr->op = operations[modRm.reg];
		state->instr->operandCount = 2;
	}
	else
	{
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

		state->instr->op = operations[modRm.rm][modRm.reg - 2];
		if (state->instr->op == X86_INVALID)
			return false;

		// ffnop really has no args.
		if (state->instr->op == X86_FNOP)
			return true;

		state->instr->operandCount = 1;
	}

	state->instr->operands[0].operandType = X86_ST0;
	state->instr->operands[0].size = 10;

	return true;
}


static bool DecodeFPMovConditional(X86DecoderState* const state, uint8_t opcode)
{
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;

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
		state->instr->op = operations[modRm.reg];
	}
	else if (modRm.byte != 0xe9)
	{
		static const X86Operation operations[4] =
		{
			X86_FCMOVB, X86_FCMOVE, X86_FCMOVBE, X86_FCMOVU
		};

		if (modRm.reg > 3)
			return false;

		state->instr->op = operations[modRm.reg];
		state->instr->operandCount = 2;

		state->instr->operands[1].operandType = g_fpSources[modRm.rm];
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


static bool DecodeFPMovNegConditional(X86DecoderState* const state, uint8_t opcode)
{
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;

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
		state->instr->operands[1].size = operandSizes[modRm.reg];

		state->instr->operands[0].operandType = X86_ST0;
		state->instr->operands[0].size = 10;

		state->instr->operandCount = 2;
		state->instr->op = operations[modRm.reg];
	}
	else if ((modRm.byte != 0xe2) && (modRm.byte != 0xe3))
	{
		static const X86Operation operations[8] =
		{
			X86_FCMOVNB, X86_FCMOVNE, X86_FCMOVNBE, X86_FCMOVNU,
			X86_INVALID, X86_FUCOMI, X86_FCOMI, X86_INVALID
		};

		state->instr->operands[1].operandType = g_fpSources[modRm.rm];
		state->instr->operands[1].size = 10;

		state->instr->operands[0].operandType = X86_ST0;
		state->instr->operands[0].size = 10;

		state->instr->op = operations[modRm.reg];
		state->instr->operandCount = 2;
	}
	else
	{
		static const X86Operation operations[2] = {X86_FNCLEX, X86_FNINIT};
		const uint8_t opBit = (modRm.byte & 1);
		state->instr->op = operations[opBit];
	}

	return true;
}


static bool DecodeFPArithmeticDivRev(X86DecoderState* const state, uint8_t opcode)
{
	ModRmByte modRm;

	if (!Fetch(state, 1, &modRm.byte))
		return false;

	if (!IsModRmRmFieldReg(modRm))
	{
		const uint8_t sizeBit = (opcode >> 2) & 1;
		static const uint8_t operandSizes[2] = {4, 8};
		static const X86Operation operations[8] =
		{
			X86_FADD, X86_FMUL, X86_FCOM, X86_FCOMP,
			X86_FSUB, X86_FSUBR, X86_FDIV, X86_FDIVR
		};

		// Memory!
		if (!DecodeModRmRmFieldMemory(state, 4, &state->instr->operands[0], modRm))
			return false;

		state->instr->operands[1].size = operandSizes[sizeBit];
		state->instr->operands[0].size = operandSizes[sizeBit];

		state->instr->op = operations[modRm.reg];
	}
	else
	{
		static const X86Operation operations[8] =
		{
			X86_FADD, X86_FMUL, X86_FCOM2, X86_FCOMP3,
			X86_FSUB, X86_FSUBR, X86_FDIVR, X86_FDIV
		};

		state->instr->operands[0].operandType = g_fpSources[modRm.rm];
		state->instr->operands[0].size = 4;

		state->instr->op = operations[modRm.reg];
	}

	state->instr->operands[1].operandType = X86_ST0;
	state->instr->operands[1].size = 10;

	state->instr->operandCount = 2;

	return true;
}


static bool DecodeFPFreeStore(X86DecoderState* const state, uint8_t opcode)
{
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;

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

		state->instr->op = operations[modRm.reg];
		if (modRm.reg < 4)
		{
			state->instr->operands[1] = operand;
			state->instr->operands[1].size = operandSizes[modRm.reg];
		}
		else
		{
			state->instr->operands[0] = operand;
			state->instr->operands[0].size = operandSizes[modRm.reg];
			state->instr->operandCount = 1;
			return true;
		}
	}
	else
	{
		static const X86Operation operations[8] =
		{
			X86_FFREE, X86_FXCH4, X86_FST, X86_FSTP,
			X86_FUCOM, X86_FUCOMP, X86_INVALID, X86_INVALID
		};

		state->instr->op = operations[modRm.reg];
		if (state->instr->op == X86_FUCOM)
		{
			state->instr->operands[1].operandType = g_fpSources[modRm.rm];
			state->instr->operands[1].size = 10;
		}
		else
		{
			state->instr->operands[0].operandType = g_fpSources[modRm.rm];
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


static bool DecodeFPArithmeticPop(X86DecoderState* const state, uint8_t opcode)
{
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;

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
		state->instr->op = operations[modRm.reg];
	}
	else if (modRm.byte != 0xd9)
	{
		static const X86Operation operations[8] =
		{
			X86_FADDP, X86_FMULP, X86_INVALID, X86_INVALID,
			X86_FSUBRP, X86_FSUBP, X86_FDIVRP, X86_FDIVP
		};

		state->instr->operands[1].operandType = g_fpSources[modRm.rm];
		state->instr->operands[1].size = 10;

		state->instr->op = operations[modRm.reg];
	}
	else
	{
		state->instr->op = X86_FCOMPP;
		return true;
	}

	state->instr->operands[0].operandType = X86_ST0;
	state->instr->operands[0].size = 10;

	state->instr->operandCount = 2;

	return true;
}


static bool DecodeFPIntPop(X86DecoderState* const state, uint8_t opcode)
{
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;

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

		state->instr->operands[1].size = operandSizes[modRm.reg];
		state->instr->operands[0].size = 10;
		state->instr->operands[0].operandType = X86_ST0;

		state->instr->operandCount = 2;
		state->instr->op = operations[modRm.reg];
	}
	else if ((modRm.byte >= 0xe8) && (modRm.byte < 0xf8))
	{
		static const X86Operation operations[2] = {X86_FUCOMIP, X86_FCOMIP};
		const uint8_t opBit = (modRm.reg >> 1) & 1;

		state->instr->operands[1].operandType = g_fpSources[modRm.rm];
		state->instr->operands[1].size = 4;

		state->instr->operands[0].operandType = X86_ST0;
		state->instr->operands[0].size = 10;

		state->instr->op = operations[opBit];
		state->instr->operandCount = 2;
	}
	else if (modRm.byte == 0xe0)
	{
		state->instr->op = X86_FNSTSW;
		state->instr->operandCount = 1;

		state->instr->operands[0].operandType = X86_AX;
		state->instr->operands[0].size = 2;
	}
	else
	{
		// Undocumented opcodes and aliases
		const uint8_t row = (modRm.byte & 0xf0);
		if (row == 0xc0)
		{
			static const X86Operation operations[] = {X86_FFREEP, X86_FXCH7};
			const uint8_t op = ((modRm.byte & 0x08) >> 3);
			state->instr->op = operations[op];
		}
		else if (row == 0xd0)
		{
			static const X86Operation operations[] = {X86_FSTP8, X86_FSTP9};
			const uint8_t op = ((modRm.byte & 0x08) >> 3);
			state->instr->op = operations[op];
		}
		else // 0xf8-0xdf
		{
			return false;
		}

		state->instr->operandCount = 1;
		state->instr->operands[0].operandType = g_fpSources[modRm.rm];
		state->instr->operands[0].size = 10;
	}

	return true;
}


static bool DecodeLoop(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation op[3] = {X86_LOOPNE, X86_LOOPE, X86_LOOP};
	const size_t operation = opcode & 3;

	// All three have one immediate byte argument (jump target)
	if (!DecodeImmediate(state, &state->instr->operands[0], 1))
		return false;

	state->instr->op = op[operation];
	state->instr->operandCount = 1;

	return true;
}


static bool DecodeJcxz(X86DecoderState* const state, uint8_t opcode)
{
	// 64bit mode is always 64bit and ignores operand size overrides
	static const X86Operation op[3] = {X86_JCXZ, X86_JECXZ, X86_JRCXZ};
	const uint8_t modes[3] = {state->operandMode, state->operandMode, X86_64BIT};
	const uint8_t mode = modes[state->mode];
	(void)opcode;

	// Fetch the immediate argument (jump target)
	if (!DecodeImmediate(state, &state->instr->operands[0], 1))
		return false;

	state->instr->op = op[mode];
	state->instr->operandCount = 1;

	return true;
}


static bool DecodeInOutImm(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[2] = {X86_IN, X86_OUT};
	const uint8_t operandSizeBit = opcode & 1;
	const size_t direction = ((opcode >> 1) & 1);
	const size_t op = direction;
	const uint8_t operandSizes[2] = {1, g_decoderModeSizeXref[state->operandMode]};
	const size_t operand0 = direction;
	const size_t operand1 = ((~direction) & 1);
	const uint8_t operandSize = operandSizes[operandSizeBit];

	// Process the immediate operand
	if (!DecodeImmediate(state, &state->instr->operands[operand1], 1))
		return false;
	DecodeOperandGpr(&state->instr->operands[operand0], 0, operandSize);

	state->instr->op = operations[op];
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeInt1(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	state->instr->op = X86_INT1;
	return true;
}


static bool DecodeHLT(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	state->instr->op = X86_HLT;
	return true;
}


static bool DecodeCMC(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	state->instr->op = X86_CMC;
	return true;
}


static bool DecodeGroup3(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[8] =
	{
		X86_TEST, X86_TEST, X86_NOT, X86_NEG,
		X86_MUL, X86_IMUL, X86_DIV, X86_IDIV
	};
	const uint8_t operandSizeBit = (opcode & 1);
	const uint8_t operandSizes[2] = {1, g_decoderModeSizeXref[state->operandMode]};
	const uint8_t operandSize = operandSizes[operandSizeBit];
	ModRmByte modRm;

	// Grab the ModRM byte
	if (!Fetch(state, 1, &modRm.byte))
		return false;

	// Figure out the destination
	if (!DecodeModRmRmField(state, operandSize, &state->instr->operands[0], modRm))
		return false;

	// Extra opcode bits are in the reg field of the ModRM byte
	state->instr->op = operations[modRm.reg];

	if (state->instr->op == X86_TEST)
	{
		if (!DecodeImmediate(state, &state->instr->operands[1], operandSize))
			return false;
		state->instr->operandCount = 2;
	}
	else
	{
		state->instr->operandCount = 1;
	}

	return true;
}


static bool DecodeImulImm(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];
	const uint8_t immSizes[2] = {operandSize, 1};
	const size_t immSizeBit = (opcode >> 1) & 1;
	const uint8_t immSize = immSizes[immSizeBit];

	// First decode the destination and first source
	if (!DecodeModRmRev(state, operandSize, state->instr->operands))
		return false;

	// Now grab the second source, an immediate
	if (!DecodeImmediate(state, &state->instr->operands[2], immSize))
		return false;

	state->instr->op = X86_IMUL;
	state->instr->operandCount = 3;

	return true;
}


static bool DecodeCmpxchg(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSizes[] = {1, g_decoderModeSizeXref[state->operandMode]};
	const uint8_t operandSizeBit = (opcode & 1);
	const uint8_t operandSize = operandSizes[operandSizeBit];

	if (!DecodeModRm(state, operandSize, state->instr->operands))
		return false;

	state->instr->op = X86_CMPXCHG;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeLss(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeLoadSegment(state, X86_LSS))
		return false;
	return true;
}


static bool DecodeInOutString(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation sizeOps[2][3] =
	{
		{X86_INSW, X86_INSD, X86_INSD},
		{X86_OUTSW, X86_OUTSD, X86_OUTSD}
	};
	static const X86OperandType memOperands[3][2] =
	{
		{X86_SI, X86_DI},
		{X86_ESI, X86_EDI},
		{X86_RSI, X86_RDI}
	};
	const X86Operation operations[2][2] =
	{
		{X86_INSB, sizeOps[0][state->operandMode]},
		{X86_OUTSB, sizeOps[1][state->operandMode]}
	};
	const uint8_t operandSizes[2][3] =
	{
		{1, 1, 1},
		{2, 4, 4}
	};
	const uint8_t opBit = ((opcode >> 1) & 1);
	const uint8_t operandBit = (opcode & 1);
	const uint8_t operand0 = opBit;
	const uint8_t operand1 = ((~opBit) & 1);
	const uint8_t operandSize = operandSizes[operandBit][state->operandMode];

	state->instr->op = operations[opBit][operandBit];
	state->instr->operandCount = 2;

	state->instr->operands[operand0].operandType = X86_DX;
	state->instr->operands[operand0].size = 2;

	state->instr->operands[operand1].operandType = X86_MEM;
	state->instr->operands[operand1].size = operandSize;
	state->instr->operands[operand1].components[0] = memOperands[state->addrMode][0];
	state->instr->operands[operand1].components[1] = memOperands[state->addrMode][1];

	return true;
}


static bool DecodeMovGpr(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSizes[2] = {1, g_decoderModeSizeXref[state->operandMode]};
	const uint8_t operandSizeBit = opcode & 1;
	const uint8_t operandSize = operandSizes[operandSizeBit];
	const uint8_t direction = ((opcode >> 1) & 1);

	if (!DecodeModRmDirection(state, operandSize, state->instr->operands, direction))
		return false;

	state->instr->op = X86_MOV;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeMovSeg(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];
	static const X86OperandType segments[8] =
	{
		X86_ES, X86_CS, X86_SS, X86_DS,
		X86_FS, X86_GS, X86_NONE, X86_NONE
	};
	const uint8_t direction = (opcode >> 1) & 1;
	ModRmByte modRm;
	const uint8_t operand0 = direction;
	const uint8_t operand1 = ((~direction) & 1);

	// Grab the ModRm byte
	if (!Fetch(state, 1, &modRm.byte))
		return false;

	// Look for values of 6 or 7 in the reg field
	// (does not encode a valid segment register)
	if ((modRm.reg & 6) == 6)
		return false;

	// Process the first operand
	if (!DecodeModRmRmField(state, operandSize, &state->instr->operands[operand0], modRm))
		return false;

	// Can't load CS using the MOV instruction, only JMP/CALL
	if ((direction == 0) && (state->instr->operands[0].operandType == X86_CS))
		return false;

	// Now process the second operand.
	state->instr->operands[operand1].size = 2;
	state->instr->operands[operand1].operandType = segments[modRm.reg];

	state->instr->op = X86_MOV;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeLea(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];
	ModRmByte modRm;

	(void)opcode;

	// Grab the ModRm byte
	if (!Fetch(state, 1, &modRm.byte))
		return false;

	// Only memory references are valid in the rm field.
	if (IsModRmRmFieldReg(modRm))
		return false;

	// Figure out the operands
	if (!DecodeModRmRmFieldMemory(state, operandSize, &state->instr->operands[1], modRm))
		return false;
	DecodeModRmRegField(operandSize, &state->instr->operands[0], modRm, state->rex);

	// Write out the rest
	state->instr->op = X86_LEA;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeGroup1a(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];
	ModRmByte modRm;

	(void)opcode;

	// Grab the ModRm byte
	if (!Fetch(state, 1, &modRm.byte))
		return false;

	// Only reg 0 is valid, which is POP R/M
	if (modRm.reg != 0)
	{
		// TODO: XOP
		return false;
	}

	// Figure out the destination
	if (!DecodeModRmRmField(state, operandSize, &state->instr->operands[0], modRm))
		return false;

	state->instr->op = X86_POP;
	state->instr->operandCount = 1;

	return true;
}


static bool DecodeConvertSize(X86DecoderState* const state, uint8_t opcode)
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


static __inline bool DecodeFarOperand(X86DecoderState* const state)
{
	const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];
	union
	{
		uint8_t imm[6];
		struct
		{
			uint16_t segment;
			uint32_t offset;
		};
	} args;
	const size_t operandBytes = operandSize + 2;

	// Grab the segment and offset
	if (!Fetch(state, operandBytes, args.imm))
		return false;
	InitImmediateUnsigned(&state->instr->operands[0], args.segment, 2);
	InitImmediate(&state->instr->operands[1], args.offset, operandSize);

	return true;
}


static bool DecodeCallFar(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;

	if (state->mode == X86_64BIT)
	{
		// This form is invalid in 64bit mode
		return false;
	}

	DecodeFarOperand(state);

	state->instr->op = X86_CALLF;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeFWait(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	state->instr->op = X86_FWAIT;
	return true;
}


static bool DecodePushPopFlags(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation ops[2][2][3] =
	{
		{
			// Normal case
			{X86_PUSHF, X86_PUSHFD, X86_PUSHFQ},
			{X86_POPF, X86_POPFD, X86_POPFQ},
		},
		{
			// Overrides
			{X86_PUSHFD, X86_PUSHF, X86_PUSHF},
			{X86_POPFD, X86_POPF, X86_POPF},
		}
	};
	const uint8_t operation = (opcode & 1);
	const uint8_t override = state->instr->flags.operandSizeOverride;

	// PUSHF/POPF do not obey normal operand size override semantics.
	state->instr->op = ops[override][operation][state->mode];

	return true;
}


static bool DecodeAHFlags(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation ops[2] = {X86_SAHF, X86_LAHF};
	const uint8_t operation = opcode & 1;
	state->instr->op = ops[operation];
	return true;
}


static bool DecodeTestImm(X86DecoderState* const state, uint8_t opcode)
{
	const size_t sizeBit = opcode & 1;
	const uint8_t operandSizes[2] = {1, g_decoderModeSizeXref[state->operandMode]};
	const uint8_t operandSize = operandSizes[sizeBit];

	if (!DecodeImmediate(state, &state->instr->operands[1], operandSize))
		return false;
	DecodeOperandGpr(&state->instr->operands[0], 0, operandSize);

	state->instr->op = X86_TEST;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeString(X86DecoderState* const state, uint8_t opcode)
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
	const uint8_t operandSizes[2] = {1, g_decoderModeSizeXref[state->operandMode]};
	const uint8_t sizeBit = (opcode & 1);
	const uint8_t operationBits = ((opcode & 0xf) - 0xa) >> 1;
	const uint8_t operandSize = operandSizes[sizeBit];
	const uint8_t operandSel = operandSize >> 1;

	state->instr->op = operations[operationBits][operandSel];
	state->instr->operandCount = 2;

	state->instr->operands[0].operandType = dests[operandSel][operationBits];
	state->instr->operands[0].segment = segments[operationBits][0];
	state->instr->operands[0].size = operandSize;
	state->instr->operands[0].components[0] = destComponents[state->addrMode][operationBits];

	state->instr->operands[1].operandType = sources[operandSel][operationBits];
	state->instr->operands[1].segment = segments[operationBits][1];
	state->instr->operands[1].size = operandSize;
	state->instr->operands[1].components[0] = sourceComponents[state->addrMode][operationBits];

	return true;
}


static bool DecodeMovImm(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSizes[2] = {1, g_decoderModeSizeXref[state->operandMode]};
	const uint8_t operandSizeBit = (opcode >> 3) & 1;
	const uint8_t reg = (opcode & 7);
	const uint8_t operandSize = operandSizes[operandSizeBit];

	if (!DecodeImmediate(state, &state->instr->operands[1], operandSize))
		return false;
	DecodeOperandGpr(&state->instr->operands[0], reg, operandSize);

	state->instr->op = X86_MOV;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeEnter(X86DecoderState* const state, uint8_t opcode)
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

	(void)opcode;

	if (!Fetch(state, 3, args.imm))
		return false;
	InitImmediate(&state->instr->operands[0], args.size, 2);
	InitImmediate(&state->instr->operands[1], args.level, 1);

	state->instr->op = X86_ENTER;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeLeave(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	state->instr->op = X86_LEAVE;
	return true;
}


static bool DecodeReturn(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[2] = {X86_RETN, X86_RETF};
	const uint8_t op = ((opcode >> 3) & 1);

	state->instr->op = operations[op];
	if (opcode & 1)
	{
		// This form has no operands
		return true;
	}

	// Only fetch if the form requires an immediate
	if (!DecodeImmediate(state, &state->instr->operands[0], 2))
		return false;

	state->instr->operandCount = 1;

	return true;
}


static bool DecodeInt3(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	state->instr->op = X86_INT3;
	return true;
}


static bool DecodeInt(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;

	if (!DecodeImmediate(state, &state->instr->operands[0], 1))
		return false;

	state->instr->op = X86_INT;
	state->instr->operandCount = 1;

	return true;
}


static bool DecodeInto(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (state->addrMode == X86_64BIT)
		return false;
	state->instr->op = X86_INTO;
	return true;
}


static bool DecodeIRet(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[3] = {X86_IRET, X86_IRETD, X86_IRETQ};
	(void)opcode;
	state->instr->op = operations[state->operandMode];
	return true;
}


static bool DecodeCallJmpRelative(X86DecoderState* const state, uint8_t opcode)
{
	static const uint8_t operandSizes[3] = {2, 4, 4};
	const uint8_t operandBytes = operandSizes[state->operandMode];
	static const X86Operation operations[2] = {X86_CALLN, X86_JMPN};
	const uint8_t operation = opcode & 1;

	(void)opcode;

	if (!DecodeImmediate(state, &state->instr->operands[0], operandBytes))
		return false;

	state->instr->op = operations[operation];
	state->instr->operandCount = 1;

	return true;
}


static bool DecodeJmpFar(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (state->mode == X86_64BIT)
	{
		// This form is invalid in 64bit mode
		return false;
	}
	DecodeFarOperand(state);
	state->instr->op = X86_JMPF;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeJmpRelativeByte(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;

	if (!DecodeImmediate(state, &state->instr->operands[0], 1))
		return false;

	state->instr->op = X86_JMPN;
	state->instr->operandCount = 1;

	return true;
}


static bool DecodeInOutDx(X86DecoderState* const state, uint8_t opcode)
{
	static const uint8_t gprSizes[] = {2, 4, 4};
	const uint8_t operandSizes[2] = {1, gprSizes[state->operandMode]};
	static const X86Operation operations[2] = {X86_IN, X86_OUT};
	const uint8_t operandSizeBit = (opcode & 1);
	const uint8_t operation = (opcode >> 1) & 1;
	const uint8_t operandSize = operandSizes[operandSizeBit];
	const uint8_t operand0 = operation;
	const uint8_t operand1  = ((~operation) & 1);

	DecodeOperandGpr(&state->instr->operands[operand0], 0, operandSize);

	state->instr->operands[operand1].operandType = X86_DX;
	state->instr->operands[operand1].size = 2;

	state->instr->op = operations[operation];
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeSetClearFlag(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[6] = {X86_CLC, X86_STC, X86_CLI, X86_STI, X86_CLD, X86_STD};
	const uint8_t op = (opcode & 7);
	state->instr->op = operations[op];
	return true;
}


static bool DecodeGroup4(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[2] = {X86_INC, X86_DEC};
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (modRm.reg > 1)
		return false;
	if (!DecodeModRmRmField(state, 1, &state->instr->operands[0], modRm))
		return false;

	state->instr->operandCount = 1;
	state->instr->op = operations[modRm.reg];

	return true;
}


static bool DecodeGroup5(X86DecoderState* const state, uint8_t opcode)
{
	uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];
	static const X86Operation operations[8] =
	{
		X86_INC, X86_DEC, X86_CALLN, X86_CALLF,
		X86_JMPN, X86_JMPF, X86_PUSH, X86_INVALID
	};
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;

	// GPR encoding for CALL/JMP Mp invalid
	if ((modRm.reg == 3) || (modRm.reg == 5))
	{
		if (IsModRmRmFieldReg(modRm))
			return false;
	}
	else if ((modRm.reg == 2) || (modRm.reg == 4) || (modRm.reg == 6))
	{
		// f64 -- Operand size is forced to 64 bit no matter what.
		const uint8_t operandSizes[] = {operandSize, operandSize, 8};
		operandSize = operandSizes[state->mode];
	}

	if (!DecodeModRmRmField(state, operandSize, &state->instr->operands[0], modRm))
		return false;

	state->instr->operandCount = 1;
	state->instr->op = operations[modRm.reg];

	return true;
}


static bool DecodeSegmentPrefix(X86DecoderState* const state, uint8_t opcode)
{
	// ES, CS, SS, DS
	const uint8_t segment = (((opcode >> 3) & 2) | ((opcode >> 3) & 1));

	state->lastBytePrefix = true;

	// Only the last segment override prefix matters.
	if (state->mode != X86_64BIT)
	{
		state->instr->flags.segments = 0;
		switch (segment)
		{
		case 0:
			state->instr->flags.segmentOverrideES = 1;
			break;
		case 1:
			state->instr->flags.segmentOverrideCS = 1;
			break;
		case 2:
			state->instr->flags.segmentOverrideSS = 1;
			break;
		case 3:
			state->instr->flags.segmentOverrideDS = 1;
			break;
		}
	}

	return ProcessPrimaryOpcode(state);
}


static bool DecodeExtendedSegmentPrefix(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t colBit = (opcode & 1);
	state->lastBytePrefix = true;

	// Only the last segment override prefix matters.
	state->instr->flags.segments = 0;
	if (!colBit)
		state->instr->flags.segmentOverrideFS = 1;
	else
		state->instr->flags.segmentOverrideGS = 1;

	return ProcessPrimaryOpcode(state);
}


static bool DecodeOperandSizePrefix(X86DecoderState* const state, uint8_t opcode)
{
	static const X86DecoderMode modes[3] = {X86_32BIT, X86_16BIT, X86_16BIT};
	(void)opcode;
	state->lastBytePrefix = true;
	state->operandMode = modes[state->mode];
	state->instr->flags.operandSizeOverride = 1;
	state->secondaryTable = SECONDARY_TABLE_66;
	return ProcessPrimaryOpcode(state);
}


static bool DecodeAddrSizePrefix(X86DecoderState* const state, uint8_t opcode)
{
	static const X86DecoderMode modes[3] = {X86_32BIT, X86_16BIT, X86_32BIT};
	(void)opcode;
	state->lastBytePrefix = true;
	state->addrMode = modes[state->mode];
	state->instr->flags.addrSizeOverride = 1;
	return ProcessPrimaryOpcode(state);
}


static bool DecodeLockPrefix(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	state->lastBytePrefix = true;
	state->instr->flags.lock = 1;
	return ProcessPrimaryOpcode(state);
}


static bool DecodeRepPrefix(X86DecoderState* const state, uint8_t opcode)
{
	static const SecondaryOpCodeTable decoderTables[] = {SECONDARY_TABLE_F2, SECONDARY_TABLE_F3};
	const uint8_t colBit = (opcode & 1);

	state->lastBytePrefix = true;

	// Clear existing rep flags, only the last one counts
	if (colBit)
	{
		state->instr->flags.repne = 0;
		state->instr->flags.repe = 1;
	}
	else
	{
		state->instr->flags.repe = 0;
		state->instr->flags.repne = 1;
	}

	state->secondaryTable = decoderTables[colBit];

	return ProcessPrimaryOpcode(state);
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
	DecodeInc, DecodeInc, DecodeInc, DecodeInc,
	DecodeInc, DecodeInc, DecodeInc, DecodeInc,
	DecodeDec, DecodeDec, DecodeDec, DecodeDec,
	DecodeDec, DecodeDec, DecodeDec, DecodeDec,

	// Row 5
	DecodePushPopGpr, DecodePushPopGpr, DecodePushPopGpr, DecodePushPopGpr,
	DecodePushPopGpr, DecodePushPopGpr, DecodePushPopGpr, DecodePushPopGpr,
	DecodePushPopGpr, DecodePushPopGpr, DecodePushPopGpr, DecodePushPopGpr,
	DecodePushPopGpr, DecodePushPopGpr, DecodePushPopGpr, DecodePushPopGpr,

	// Row 6
	DecodePushPopAll, DecodePushPopAll, DecodeBound, DecodeAarplMovSxd,
	DecodeExtendedSegmentPrefix, DecodeExtendedSegmentPrefix, DecodeOperandSizePrefix, DecodeAddrSizePrefix,
	DecodePushImm, DecodeImulImm, DecodePushImm, DecodeImulImm,
	DecodeInOutString, DecodeInOutString, DecodeInOutString, DecodeInOutString,

	// Row 7
	DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional,
	DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional,
	DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional,
	DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional,

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
	DecodeLes, DecodeLds, DecodeGroup11, DecodeGroup11,
	DecodeEnter, DecodeLeave, DecodeReturn, DecodeReturn,
	DecodeInt3, DecodeInt, DecodeInto, DecodeIRet,

	// Row 0xd
	DecodeGroup2, DecodeGroup2, DecodeGroup2, DecodeGroup2,
	DecodeAsciiAdjust, DecodeAsciiAdjust, DecodeSalc, DecodeXlat,
	DecodeFPArithmetic, DecodeFPLoadStore, DecodeFPMovConditional, DecodeFPMovNegConditional,
	DecodeFPArithmeticDivRev, DecodeFPFreeStore, DecodeFPArithmeticPop, DecodeFPIntPop,

	// Row 0xe
	DecodeLoop, DecodeLoop, DecodeLoop, DecodeJcxz,
	DecodeInOutImm, DecodeInOutImm, DecodeInOutImm, DecodeInOutImm,
	DecodeCallJmpRelative, DecodeCallJmpRelative, DecodeJmpFar, DecodeJmpRelativeByte,
	DecodeInOutDx, DecodeInOutDx, DecodeInOutDx, DecodeInOutDx,

	// Row 0xf
	DecodeLockPrefix, DecodeInt1, DecodeRepPrefix, DecodeRepPrefix,
	DecodeHLT, DecodeCMC, DecodeGroup3, DecodeGroup3,
	DecodeSetClearFlag, DecodeSetClearFlag, DecodeSetClearFlag, DecodeSetClearFlag,
	DecodeSetClearFlag, DecodeSetClearFlag, DecodeGroup4, DecodeGroup5
};


// See Table A-1 Primary Opcode Table (One-byte Opcodes) AMD 24594_APM_v3.pdf
bool DecodePrimaryOpcodeTable(X86DecoderState* const state)
{
	state->secondaryTable = SECONDARY_TABLE_NORMAL;
	return ProcessPrimaryOpcode(state);
}


static __inline void DecodeModRmRmFieldSimdReg(uint8_t operandSize, X86Operand* const operand,
	ModRmByte modRm, RexByte rex)
{
	const uint8_t reg = ((rex.b << 3) | modRm.rm);
	operand->operandType = g_simdOperandTypes[operandSize >> 4][reg];
	operand->size = operandSize;
}


static __inline void DecodeModRmRegFieldSimd(uint8_t operandSize, X86Operand* const operand,
	ModRmByte modRm, RexByte rex)
{
	operand->operandType = g_simdOperandTypes[operandSize >> 4][modRm.reg];
	operand->size = operandSize;
}


static __inline bool DecodeModRmRmFieldSimd(X86DecoderState* const state, uint8_t operandSize,
		X86Operand* const operand, ModRmByte modRm)
{
	if (IsModRmRmFieldReg(modRm))
	{
		DecodeModRmRmFieldSimdReg(operandSize, operand, modRm, state->rex);
		return true;
	}

	return DecodeModRmRmFieldMemory(state, operandSize, operand, modRm);
}


static __inline bool DecodeModRmSimd(X86DecoderState* const state,
	uint8_t operandSize, X86Operand* const operands)
{
	ModRmByte modRm;

	// Fetch the ModRM byte
	if (!Fetch(state, 1, (uint8_t*)&modRm.byte))
		return false;
	if (!DecodeModRmRmFieldSimd(state, operandSize, &operands[0], modRm))
		return false;
	DecodeModRmRegFieldSimd(operandSize, &operands[1], modRm, state->rex);

	return true;
}


static __inline bool DecodeModRmSimdRev(X86DecoderState* const state,
	uint8_t operandSize, X86Operand* const operands)
{
	ModRmByte modRm;

	// Fetch the ModRM byte
	if (!Fetch(state, 1, (uint8_t*)&modRm.byte))
		return false;
	if (!DecodeModRmRmFieldSimd(state, operandSize, &operands[1], modRm))
		return false;
	DecodeModRmRegFieldSimd(operandSize, &operands[0], modRm, state->rex);

	return true;
}


static __inline bool DecodeModRmSimdDirection(X86DecoderState* const state,
	uint8_t operandSize, X86Operand* const operands, uint8_t direction)
{
	const uint8_t operand0 = ((~direction) & 1);
	const uint8_t operand1 = direction;
	ModRmByte modRm;

	// Fetch the ModRM byte
	if (!Fetch(state, 1, (uint8_t*)&modRm.byte))
		return false;
	if (!DecodeModRmRmFieldSimd(state, operandSize, &operands[operand0], modRm))
		return false;
	DecodeModRmRegFieldSimd(operandSize, &operands[operand1], modRm, state->rex);

	return true;
}


static bool DecodeGroup6(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[] =
	{
		X86_SLDT, X86_STR, X86_LLDT, X86_LTR,
		X86_VERR, X86_VERW,
	};
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;

	if (modRm.reg > 5)
		return false;

	if (IsModRmRmFieldReg(modRm))
	{
		const uint8_t currentOperandSize = g_decoderModeSizeXref[state->operandMode];
		const uint8_t operandSizes[] = {currentOperandSize, currentOperandSize, 2, 2, 2, 2, 0};
		const uint8_t operandSize = operandSizes[modRm.reg];

		DecodeModRmRmFieldReg(operandSize, &state->instr->operands[0], modRm, state->rex);
	}
	else
	{
		if (!DecodeModRmRmField(state, 2, &state->instr->operands[0], modRm))
			return false;
	}

	state->instr->op = operations[modRm.reg];
	state->instr->operandCount = 1;

	return true;
}


static bool DecodeGroup7(X86DecoderState* const state, uint8_t opcode)
{
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;

	if (!IsModRmRmFieldReg(modRm))
	{
		static const uint8_t descriptorSizes[] = {6, 6, 10};
		static const X86Operation operations[] =
		{
			X86_SGDT, X86_SIDT, X86_LGDT, X86_LIDT,
			X86_SMSW, X86_INVALID, X86_LMSW, X86_INVLPG
		};
		const uint8_t operandSizes[] =
		{
			descriptorSizes[state->addrMode], descriptorSizes[state->addrMode],
			descriptorSizes[state->addrMode], descriptorSizes[state->addrMode],
			2, 0,
			2, 1
		};

		if (!DecodeModRmRmFieldMemory(state, operandSizes[modRm.reg],
			&state->instr->operands[0], modRm))
		{
			return false;
		}

		state->instr->op = operations[modRm.reg];
		state->instr->operandCount = 1;
	}
	else
	{
		static const X86Operation operations[64] =
		{
			X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
			X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,

			X86_MONITOR, X86_MWAIT, X86_INVALID, X86_INVALID,
			X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,

			X86_XGETBV, X86_XSETBV, X86_INVALID, X86_INVALID,
			X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,

			X86_VMRUN, X86_VMMCALL, X86_VMLOAD, X86_VMSAVE,
			X86_STGI, X86_CLGI, X86_SKINIT, X86_INVLPGA,

			X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
			X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,

			X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
			X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,

			X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
			X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,

			X86_SWAPGS, X86_RDTSCP, X86_INVALID, X86_INVALID,
			X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID
		};
		uint8_t regRm;
		uint8_t operandSize;

		switch (modRm.reg)
		{
		case 0:
		case 5:
			return false;
		case 1:
		case 2:
		case 3:
		case 7:
			regRm = (modRm.byte & 0x3f);
			state->instr->op = operations[regRm];
			break;
		case 4:
			operandSize = g_decoderModeSizeXref[state->operandMode];
			DecodeModRmRmFieldReg(operandSize, &state->instr->operands[0], modRm, state->rex);
			state->instr->op = X86_SMSW;
			state->instr->operandCount = 1;
			break;
		case 6:
			DecodeModRmRmFieldReg(2, &state->instr->operands[0], modRm, state->rex);
			state->instr->op = X86_LMSW;
			state->instr->operandCount = 1;
			break;
		}
	}

	return true;
}


static bool DecodeLoadSegmentInfo(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[] = {X86_LAR, X86_LSL};
	const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];
	const uint8_t op = opcode & 1;
	ModRmByte modRm;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!DecodeModRmRmField(state, 2, &state->instr->operands[1], modRm))
		return false;
	DecodeModRmRegField(operandSize, &state->instr->operands[0], modRm, state->rex);

	state->instr->op = operations[op];
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeSys(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[] = {X86_INVALID, X86_SYSCALL, X86_CLTS, X86_SYSRET};
	const uint8_t op = (opcode & 3);
	if (((state->mode != X86_64BIT) && (opcode & 1) != 0))
	{
		// SYSCALL and SYSRET are only valid in 64bit mode.
		return false;
	}
	state->instr->op = operations[op];
	return true;
}


static bool DecodeInvd(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[] = {X86_INVD, X86_WBINVD};
	const uint8_t op = (opcode & 1);
	state->instr->op = operations[op];
	return true;
}


static bool DecodeUd2(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	state->instr->op = X86_UD2;
	return true;
}


static bool DecodeGroupP(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[] =
	{
		// NOTE: This table is actually part of 3dnow, and Intel has no analog
		X86_PREFETCH, X86_PREFETCHW, X86_PREFETCH, X86_PREFETCHW,
		X86_PREFETCH, X86_PREFETCH, X86_PREFETCH, X86_PREFETCH // Reserved.
	};
	const uint8_t op = (opcode & 3);

	if (!DecodeModRm(state, 1, &state->instr->operands[0]))
		return false;

	state->instr->op = operations[op];
	state->instr->operandCount = 1;

	return true;
}


static bool DecodeFemms(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	state->instr->op = X86_FEMMS;
	return true;
}


static bool Decode3dnow(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[] =
	{
		// Row 0
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_PI2FW, X86_PI2FD, X86_INVALID, X86_INVALID,

		// Row 1
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_PF2IW, X86_PF2ID, X86_INVALID, X86_INVALID,

		// Row 2
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,

		// Row 3
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,

		// Row 4
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,

		// Row 5
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,

		// Row 6
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,

		// Row 7
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,

		// Row 8
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_PFNACC, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_PFPNACC, X86_INVALID,

		// Row 9
		X86_PFCMPGE, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_PFMIN, X86_INVALID, X86_PFRCP, X86_PFRSQRT,
		X86_INVALID, X86_INVALID, X86_PFSUB, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_PFADD, X86_INVALID,

		// Row 0xa
		X86_PFCMPGT, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_PFMAX, X86_INVALID, X86_PFRCPIT1, X86_PFRSQIT1,
		X86_INVALID, X86_INVALID, X86_PFSUBR, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_PFACC, X86_INVALID,

		// Row 0xb
		X86_PFCMPEQ, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_PFMUL, X86_INVALID, X86_PFRCPIT2, X86_PMULHRW,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_PSWAPD,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_PAVGUSB,

		// Row 0xc
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,

		// Row 0xd
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,

		// Row 0xe
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,

		// Row 0xf
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
	};
	uint8_t imm;

	(void)opcode;

	// 0f 0f [ModRM] [SIB] [displacement] imm8 opcode

	if (!DecodeModRmSimdRev(state, 8, state->instr->operands))
		return false;

	if (!Fetch(state, 1, &imm))
		return false;

	state->instr->op = operations[imm];
	if (state->instr->op == X86_INVALID)
		return false;
	state->instr->operandCount = 2;

	return true;
}


static __inline bool DecodeSimdDirectionOperands(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t direction = ((opcode) & 1);
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX

	return DecodeModRmSimdDirection(state, operandSize, state->instr->operands, direction);
}


static bool DecodeMovups(X86DecoderState* const state, uint8_t opcode)
{
	if (!DecodeSimdDirectionOperands(state, opcode))
		return false;
	state->instr->op = X86_MOVUPS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMovss(X86DecoderState* const state, uint8_t opcode)
{
	if (!DecodeSimdDirectionOperands(state, opcode))
		return false;
	state->instr->flags.repne = 0;
	state->instr->op = X86_MOVSS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMovupd(X86DecoderState* const state, uint8_t opcode)
{
	if (!DecodeSimdDirectionOperands(state, opcode))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_MOVUPD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMovsd(X86DecoderState* const state, uint8_t opcode)
{
	if (!DecodeSimdDirectionOperands(state, opcode))
		return false;
	state->instr->flags.repe = 0;
	state->instr->op = X86_MOVSD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMovlpd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t direction = (opcode & 1);
	const uint8_t operand0 = direction;
	const uint8_t operand1 = ((~direction) & 1);
	ModRmByte modRm;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (IsModRmRmFieldReg(modRm))
		return false;
	if (!DecodeModRmRmFieldMemory(state, 8, &state->instr->operands[operand1], modRm))
		return false;
	DecodeModRmRegFieldSimd(16, &state->instr->operands[operand0], modRm, state->rex);
	state->instr->operands[operand0].size = 8;

	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_MOVLPD;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeMovhpd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t direction = (opcode & 1);
	const uint8_t operand0 = direction;
	const uint8_t operand1 = ((~direction) & 1);
	ModRmByte modRm;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (IsModRmRmFieldReg(modRm))
		return false;
	if (!DecodeModRmRmFieldMemory(state, 8, &state->instr->operands[operand1], modRm))
		return false;
	DecodeModRmRegFieldSimd(16, &state->instr->operands[operand0], modRm, state->rex);
	state->instr->operands[operand0].size = 8;

	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_MOVHPD;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeUnpcklpd(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeModRmSimdRev(state, 16, state->instr->operands))
		return false;
	state->instr->operands[0].size = 8;
	state->instr->operands[1].size = 8;

	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_UNPCKLPD;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeUnpckhpd(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeModRmSimdRev(state, 16, state->instr->operands))
		return false;
	state->instr->operands[0].size = 8;
	state->instr->operands[1].size = 8;

	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_UNPCKHPD;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeUnalignedPackedSingle(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t direction = (opcode & 1);
	const uint8_t op = ((opcode & 7) >> 1) - 1;
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	const uint8_t operand0 = direction;
	const uint8_t operand1 = ((~direction) & 1);
	ModRmByte modRm;

	if (!Fetch(state, 1, &modRm.byte))
		return false;

	if (!IsModRmRmFieldReg(modRm))
	{
		static const X86Operation operations[] =
		{
			X86_MOVLPS, X86_UNPCKLPS, X86_MOVHPS
		};
		if (!DecodeModRmRmFieldMemory(state, operandSize,
			&state->instr->operands[operand1], modRm))
		{
			return false;
		}
		state->instr->op = operations[op];
	}
	else
	{
		static const X86Operation operations[] =
		{
			X86_MOVHLPS, X86_UNPCKLPS, X86_MOVLHPS
		};
		DecodeModRmRmFieldSimdReg(operandSize, &state->instr->operands[operand1],
			modRm, state->rex);
		state->instr->op = operations[op];
	}

	DecodeModRmRegFieldSimd(operandSize, &state->instr->operands[operand0],
		modRm, state->rex);

	state->instr->operandCount = 2;

	return true;
}


static bool DecodeUnpackSingle(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[] = {X86_UNPCKLPS, X86_UNPCKHPS};
	const uint8_t op = (opcode & 1);
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX

	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;

	state->instr->op = operations[op];
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeFlagSetByte(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[] =
	{
		X86_SETO, X86_SETNO, X86_SETB, X86_SETNB,
		X86_SETZ, X86_SETNZ, X86_SETBE, X86_SETNBE,
		X86_SETS, X86_SETNS, X86_SETP, X86_SETNP,
		X86_SETL, X86_SETNL, X86_SETLE, X86_SETNLE
	};
	const uint8_t op = (opcode & 0xf);
	ModRmByte modRm;

	if (!Fetch(state, 1, &modRm.byte))
		return false;

	if (!DecodeModRmRmField(state, 1, &state->instr->operands[0], modRm))
		return false;

	state->instr->operandCount = 1;
	state->instr->op = operations[op];

	return true;
}


static bool DecodePushPopFsGs(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[2] = {X86_PUSH, X86_POP};
	static const X86OperandType operands[2] = {X86_FS, X86_GS};
	const uint8_t op = (opcode & 1);
	const uint8_t operandBit = ((opcode >> 3) & 1);

	state->instr->operands[0].operandType = operands[operandBit];
	state->instr->operands[0].size = 2;

	state->instr->op = operations[op];
	state->instr->operandCount = 1;

	return true;
}


static bool DecodeCpuid(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	state->instr->op = X86_CPUID;
	return true;
}


static bool DecodeRsm(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	state->instr->op = X86_RSM;
	return true;
}


static bool DecodeBt(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[] = {X86_BT, X86_BTS, X86_BTR, X86_BTC};
	const uint8_t op = ((opcode >> 3) & 3);
	const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];

	if (!DecodeModRm(state, operandSize, state->instr->operands))
		return false;

	state->instr->op = operations[op];
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeShiftd(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[] = {X86_SHLD, X86_SHRD};
	const uint8_t op = ((opcode >> 3) & 1);

	if (!DecodeModRm(state, g_decoderModeSizeXref[state->operandMode], state->instr->operands))
		return false;

	if (opcode & 1)
	{
		state->instr->operands[2].operandType = X86_CL;
		state->instr->operands[2].size = 1;
	}
	else
	{
		if (!DecodeImmediate(state, &state->instr->operands[2], 1))
			return false;
	}

	state->instr->op = operations[op];
	state->instr->operandCount = 3;

	return true;
}


static bool DecodeGroup15(X86DecoderState* const state, uint8_t opcode)
{
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;

	if (!IsModRmRmFieldReg(modRm))
	{
		static const X86Operation operations[] =
		{
			X86_FXSAVE, X86_FXRSTOR, X86_LDMXCSR, X86_STMXCSR,
			X86_XSAVE, X86_XRSTOR, X86_XSAVEOPT, X86_CLFLUSH
		};
		const uint8_t operandSizes[] =
		{
			0, 0, 4, 4,
			0, 0, 0, 1
		};

		if (!DecodeModRmRmField(state, 1, &state->instr->operands[0], modRm))
			return false;
		state->instr->operands[0].size = operandSizes[modRm.reg];

		state->instr->op = operations[modRm.reg];
		state->instr->operandCount = 1;
	}
	else
	{
		static const X86Operation operations[] =
		{
			X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
			X86_INVALID, X86_LFENCE, X86_MFENCE, X86_SFENCE
		};
		state->instr->op = operations[modRm.reg];
	}

	return true;
}


static bool DecodeImul(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];
	(void)opcode;
	if (!DecodeModRmRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->op = X86_IMUL;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeLfs(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeLoadSegment(state, X86_LFS))
		return false;
	return true;
}


static bool DecodeLgs(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeLoadSegment(state, X86_LGS))
		return false;
	return true;
}


static bool DecodeMovExtend(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[] = {X86_MOVZX, X86_MOVSX};
	const uint8_t srcSizes[] = {1, 2};
	const uint8_t operandSizeBit = (opcode & 1);
	const uint8_t op = ((opcode >> 3) & 1);
	const uint8_t srcSize = srcSizes[operandSizeBit];
	const uint8_t dstSize = g_decoderModeSizeXref[state->operandMode];
	ModRmByte modRm;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!DecodeModRmRmField(state, srcSize, &state->instr->operands[1], modRm))
		return false;
	DecodeModRmRegField(dstSize, &state->instr->operands[0], modRm, state->rex);

	state->instr->op = operations[op];
	state->instr->operandCount = 2;

	return true;
}


static bool DecodePopcnt(X86DecoderState* const state, uint8_t opcode)
{
	uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];
	(void)opcode;
	if (!DecodeModRmRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.repne = 0;
	state->instr->op = X86_POPCNT;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeTzcnt(X86DecoderState* const state, uint8_t opcode)
{
	uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];
	(void)opcode;
	if (!DecodeModRmRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.repe = 0;
	state->instr->op = X86_TZCNT;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeLzcnt(X86DecoderState* const state, uint8_t opcode)
{
	uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];
	(void)opcode;
	if (!DecodeModRmRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.repe = 0;
	state->instr->op = X86_LZCNT;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeXadd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSizes[] = {1, g_decoderModeSizeXref[state->operandMode]};
	const uint8_t operandSizeBit = (opcode & 1);
	const uint8_t operandSize = operandSizes[operandSizeBit];

	if (!DecodeModRm(state, operandSize, state->instr->operands))
		return false;

	state->instr->op = X86_XADD;
	state->instr->operandCount = 2;

	return true;
}


static __inline bool DecodeCmpPacked(X86DecoderState* const state, X86Operation op)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX

	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;

	state->instr->op = op;
	state->instr->operandCount = 3;

	return true;
}


static bool DecodeCmpps(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	return DecodeCmpPacked(state, X86_CMPPS);
}


static bool DecodeCmpss(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	state->instr->flags.repne = 0;
	return DecodeCmpPacked(state, X86_CMPSS);
}


static bool DecodeCmppd(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	state->instr->flags.operandSizeOverride = 0;
	return DecodeCmpPacked(state, X86_CMPPD);
}


static bool DecodeCmpsd(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	state->instr->flags.repne = 0;
	return DecodeCmpPacked(state, X86_CMPSD);
}


static bool DecodeMovnti(X86DecoderState* const state, uint8_t opcode)
{
	static const uint8_t operandSizes[] = {4, 4, 8};
	const uint8_t operandSize = operandSizes[state->operandMode];
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (IsModRmRmFieldReg(modRm))
		return false;
	if (!DecodeModRmRmFieldMemory(state, operandSize, &state->instr->operands[0], modRm))
		return false;
	DecodeModRmRegField(operandSize, &state->instr->operands[1], modRm, state->rex);

	state->instr->op = X86_MOVNTI;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodePinsrw(X86DecoderState* const state, uint8_t opcode)
{
	static const uint8_t srcSizes[4][3] =
	{
		{2, 2, 2},
		{2, 2, 2},
		{2, 2, 2},
		{4, 4, 8}
	};
	static const uint8_t dstSizes[] = {8, 16};
	ModRmByte modRm;
	uint8_t srcSize;
	uint8_t dstSize;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;

	// AMD docs call operand[1] Ew, but Intel docs say Ry/Mw
	// ie only a word from memory but operand size reg.
	// ntsd and ud86 follow the intel behavior
	srcSize = srcSizes[modRm.mod][state->operandMode];
	dstSize = dstSizes[state->secondaryTable >> 1];

	if (!DecodeModRmRmField(state, srcSize, &state->instr->operands[1], modRm))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;
	DecodeModRmRegFieldSimd(dstSize, &state->instr->operands[0], modRm, state->rex);

	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_PINSRW;
	state->instr->operandCount = 3;

	return true;
}


static bool DecodePextrw(X86DecoderState* const state, uint8_t opcode)
{
	static const uint8_t srcSizes[] = {8, 16};
	const uint8_t srcSize = srcSizes[state->secondaryTable >> 1];
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!IsModRmRmFieldReg(modRm))
		return false;
	if (!DecodeModRmRmFieldSimd(state, srcSize, &state->instr->operands[1], modRm))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;
	DecodeModRmRegField(4, &state->instr->operands[0], modRm, state->rex);

	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_PEXTRW;
	state->instr->operandCount = 3;

	return true;
}


static __inline bool DecodeShufOperands(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!DecodeModRmRmFieldSimd(state, operandSize, &state->instr->operands[1], modRm))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;
	DecodeModRmRegFieldSimd(operandSize, &state->instr->operands[0], modRm, state->rex);

	return true;
}


static bool DecodeShufps(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeShufOperands(state, opcode))
		return false;
	state->instr->op = X86_SHUFPS;
	state->instr->operandCount = 3;
	return true;
}


static bool DecodeShufpd(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeShufOperands(state, opcode))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_SHUFPD;
	state->instr->operandCount = 3;
	return true;
}


static bool DecodeGroup9(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[] = {X86_CMPXCHG8B, X86_CMPXCHG16B};
	static const uint8_t operandSizes[] = {8, 16};
	const uint8_t op = 0; // FIXME: REX.W
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (IsModRmRmFieldReg(modRm))
		return false;
	if (modRm.reg != 1)
		return false;
	if (!DecodeModRmRmFieldMemory(state, operandSizes[op], &state->instr->operands[0], modRm))
		return false;

	state->instr->op = operations[op];
	state->instr->operandCount = 1;

	return true;
}


static bool DecodeBswap(X86DecoderState* const state, uint8_t opcode)
{
	uint8_t reg = (opcode & 0x7);

	(void)opcode;

	DecodeOperandGpr(&state->instr->operands[0], reg, 4);

	state->instr->op = X86_BSWAP;
	state->instr->operandCount = 1;

	return true;
}


static bool DecodeAddSubPacked(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	static const X86Operation operations[] = {X86_ADDSUBPD, X86_ADDSUBPS};
	const uint8_t op = (state->secondaryTable & 1);

	(void)opcode;

	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;

	state->instr->op = operations[op];
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeLddqu(X86DecoderState* const state, uint8_t opcode)
{
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (IsModRmRmFieldReg(modRm))
		return false;
	if (!DecodeModRmRmFieldMemory(state, 16, &state->instr->operands[1], modRm))
		return false;
	DecodeModRmRegFieldSimd(16, &state->instr->operands[0], modRm, state->rex);

	state->instr->flags.repe = 0;
	state->instr->op = X86_LDDQU;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeMovq2dq(X86DecoderState* const state, uint8_t opcode)
{
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!IsModRmRmFieldReg(modRm))
		return false;
	DecodeModRmRegFieldSimd(16, &state->instr->operands[0], modRm, state->rex);
	DecodeModRmRmFieldSimdReg(8, &state->instr->operands[1], modRm, state->rex);

	state->instr->op = X86_MOVQ2DQ;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeMovdq2q(X86DecoderState* const state, uint8_t opcode)
{
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!IsModRmRmFieldReg(modRm))
		return false;
	DecodeModRmRegFieldSimd(8, &state->instr->operands[0], modRm, state->rex);
	DecodeModRmRmFieldSimdReg(16, &state->instr->operands[1], modRm, state->rex);

	// Decode as 16 byte operand to get SSE reg, then fix up the size here
	state->instr->operands[1].size = 8;

	state->instr->op = X86_MOVDQ2Q;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeCvtdq2pd(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeModRmSimdRev(state, 16, state->instr->operands))
		return false;
	state->instr->op = X86_CVTDQ2PD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeCvttpd2dq(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeModRmSimdRev(state, 16, state->instr->operands))
		return false;
	state->instr->op = X86_CVTTPD2DQ;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeCvtpd2dq(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeModRmSimdRev(state, 16, state->instr->operands))
		return false;
	state->instr->op = X86_CVTPD2DQ;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMovmskb(X86DecoderState* const state, uint8_t opcode)
{
	static const uint8_t operandSizes[] = {8, 16};
	const uint8_t operandSize = operandSizes[state->secondaryTable >> 1];
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!IsModRmRmFieldReg(modRm))
		return false;

	DecodeModRmRmFieldSimdReg(operandSize, &state->instr->operands[1], modRm, state->rex);
	DecodeModRmRegField(4, &state->instr->operands[0], modRm, state->rex);

	state->instr->op = X86_PMOVMSKB;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeMovntq(X86DecoderState* const state, uint8_t opcode)
{
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (IsModRmRmFieldReg(modRm))
		return false;
	if (!DecodeModRmRmFieldMemory(state, 8, &state->instr->operands[0], modRm))
		return false;
	DecodeModRmRegFieldSimd(8, &state->instr->operands[1], modRm, state->rex);

	state->instr->op = X86_MOVNTQ;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeMovntdq(X86DecoderState* const state, uint8_t opcode)
{
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (IsModRmRmFieldReg(modRm))
		return false;
	if (!DecodeModRmRmFieldMemory(state, 16, &state->instr->operands[0], modRm))
		return false;
	DecodeModRmRegFieldSimd(16, &state->instr->operands[1], modRm, state->rex);

	state->instr->op = X86_MOVNTDQ;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeMaskMovq(X86DecoderState* const state, uint8_t opcode)
{
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!IsModRmRmFieldReg(modRm))
		return false;
	DecodeModRmRegFieldSimd(8, &state->instr->operands[0], modRm, state->rex);
	DecodeModRmRmFieldSimdReg(8, &state->instr->operands[1], modRm, state->rex);

	state->instr->op = X86_MASKMOVQ;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeMaskMovdqu(X86DecoderState* const state, uint8_t opcode)
{
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!IsModRmRmFieldReg(modRm))
		return false;
	DecodeModRmRegFieldSimd(16, &state->instr->operands[0], modRm, state->rex);
	DecodeModRmRmFieldSimdReg(16, &state->instr->operands[1], modRm, state->rex);

	state->instr->op = X86_MASKMOVDQU;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeUd(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	state->instr->op = X86_UD;
	return true;
}


static bool DecodeSimdArithmetic(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[] =
	{
		// Row 0xd
		X86_INVALID, X86_PSRLW, X86_PSRLD, X86_PSRLQ,
		X86_PADDQ, X86_PMULLW, X86_INVALID, X86_INVALID,
		X86_PSUBUSB, X86_PSUBUSW, X86_PMINUB, X86_PAND,
		X86_PADDUSB, X86_PADDUSW, X86_PMAXUB, X86_PANDN,

		// Row 0xe
		X86_PAVGB, X86_PSRAW, X86_PSRAD, X86_PAVGW,
		X86_PMULHUW, X86_PMULHW, X86_INVALID, X86_INVALID,
		X86_PSUBSB, X86_PSUBSW, X86_PMINSW, X86_POR,
		X86_PADDSB, X86_PADDSW, X86_PMAXSW, X86_PXOR,

		// Row 0xf
		X86_INVALID, X86_PSLLW, X86_PSLLD, X86_PSLLQ,
		X86_PMULUDQ, X86_PMADDWD, X86_PSADBW, X86_INVALID,
		X86_PSUBB, X86_PSUBW, X86_PSUBD, X86_PSUBQ,
		X86_PADDB, X86_PADDW, X86_PADDD, X86_INVALID
	};
	static const uint8_t operandSizes[] = {8, 16};
	const uint8_t op = (opcode - 0xd0) | (opcode & 0xf);
	const uint8_t operandSize = operandSizes[state->secondaryTable >> 1];

	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;

	state->instr->op = operations[op];
	if (state->instr->op == X86_INVALID)
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeGroup10(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	state->instr->op = X86_UD1;
	return true;
}


static bool DecodeGroup8(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[] =
	{
		X86_INVALID, X86_INVALID, X86_INVALID, X86_INVALID,
		X86_BT, X86_BTS, X86_BTR, X86_BTC
	};
	const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;

	if (operations[modRm.reg] == X86_INVALID)
		return false;

	if (!DecodeModRmRmField(state, operandSize, &state->instr->operands[0], modRm))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[1], 1))
		return false;

	state->instr->op = operations[modRm.reg];
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeBitScan(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[] = {X86_BSF, X86_BSR};
	const uint8_t op = (opcode & 1);
	const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];

	if (!DecodeModRmRev(state, operandSize, state->instr->operands))
		return false;

	state->instr->op = operations[op];
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeMovSpecialPurpose(X86DecoderState* const state, uint8_t opcode)
{
	static const uint8_t operandSizes[] = {4, 4, 8};
	static const X86OperandType operands[2][8] =
	{
		{X86_CR0, X86_NONE, X86_CR2, X86_CR3, X86_CR4, X86_NONE, X86_NONE, X86_NONE},
		{X86_DR0, X86_DR1, X86_DR2, X86_DR3, X86_DR4, X86_DR5, X86_DR6, X86_DR7}
	};
	const uint8_t direction = ((opcode >> 1) & 1);
	const uint8_t operand0 = direction;
	const uint8_t operand1 = ((~direction) & 1);
	const uint8_t operandSel = (opcode & 1);
	const uint8_t operandSize = operandSizes[state->mode];
	ModRmByte modRm;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!IsModRmRmFieldReg(modRm))
		return false;
	if (!DecodeModRmRmField(state, operandSize, &state->instr->operands[operand0], modRm))
		return false;

	state->instr->operands[operand1].operandType = operands[operandSel][modRm.reg];
	if (state->instr->operands[operand1].operandType == X86_NONE)
		return false;
	state->instr->operands[0].size = operandSize;

	state->instr->op = X86_MOV;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeMovaps(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeSimdDirectionOperands(state, opcode))
		return false;
	state->instr->op = X86_MOVAPS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMovapd(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeSimdDirectionOperands(state, opcode))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_MOVAPD;
	state->instr->operandCount = 2;
	return true;
}


static __inline bool DecodeCvtIntSimdOperandsMmx(X86DecoderState* const state, uint8_t srcSize)
{
	const uint8_t destSize = g_sseOperandSizes[0]; // FIXME: VEX
	ModRmByte modRm;
	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!DecodeModRmRmFieldSimd(state, srcSize, &state->instr->operands[1], modRm))
		return false;
	DecodeModRmRegFieldSimd(destSize, &state->instr->operands[0], modRm, state->rex);
	return true;
}


static __inline bool DecodeCvtIntSimdOperands(X86DecoderState* const state, uint8_t srcSize)
{
	const uint8_t destSize = g_sseOperandSizes[0]; // FIXME: VEX
	ModRmByte modRm;
	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!DecodeModRmRmFieldSimd(state, srcSize, &state->instr->operands[1], modRm))
		return false;
	DecodeModRmRegFieldSimd(destSize, &state->instr->operands[0], modRm, state->rex);
	return true;
}


static bool DecodeCvtpi2ps(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeCvtIntSimdOperandsMmx(state, 8))
		return false;
	state->instr->op = X86_CVTPI2PS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeCvtsi2ss(X86DecoderState* const state, uint8_t opcode)
{
	static const uint8_t operandSizes[] = {4, 4, 8};
	const uint8_t srcSize = operandSizes[state->operandMode];
	(void)opcode;
	if (!DecodeCvtIntSimdOperands(state, srcSize))
		return false;
	state->instr->flags.repne = 0;
	state->instr->op = X86_CVTSI2SS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeCvtpi2pd(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeCvtIntSimdOperandsMmx(state, 8))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_CVTPI2PD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeCvtsi2sd(X86DecoderState* const state, uint8_t opcode)
{
	static const uint8_t operandSizes[] = {4, 4, 8};
	const uint8_t srcSize = operandSizes[state->operandMode];
	(void)opcode;
	if (!DecodeCvtIntSimdOperands(state, srcSize))
		return false;
	state->instr->flags.repe = 0;
	state->instr->op = X86_CVTSI2SD;
	state->instr->operandCount = 2;
	return true;
}


static __inline bool DecodeMovntOperands(X86DecoderState* const state, uint8_t opcode, uint8_t destSize)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (IsModRmRmFieldReg(modRm))
		return false;
	if (!DecodeModRmRmFieldMemory(state, destSize, &state->instr->operands[0], modRm))
		return false;
	DecodeModRmRegFieldSimd(operandSize, &state->instr->operands[1], modRm, state->rex);

	return true;
}


static bool DecodeMovntps(X86DecoderState* const state, uint8_t opcode)
{
	if (!DecodeMovntOperands(state, opcode, 16))
		return false;
	state->instr->op = X86_MOVNTPS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMovntss(X86DecoderState* const state, uint8_t opcode)
{
	if (!DecodeMovntOperands(state, opcode, 4))
		return false;
	state->instr->flags.repne = 0;
	state->instr->op = X86_MOVNTSS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMovntpd(X86DecoderState* const state, uint8_t opcode)
{
	if (!DecodeMovntOperands(state, opcode, 16))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_MOVNTPD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMovntsd(X86DecoderState* const state, uint8_t opcode)
{
	if (!DecodeMovntOperands(state, opcode, 8))
		return false;
	state->instr->flags.repe = 0;
	state->instr->op = X86_MOVNTSD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeCvtPsOperands(X86DecoderState* const state)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	ModRmByte modRm;
	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!DecodeModRmRmFieldSimd(state, operandSize, &state->instr->operands[1], modRm))
		return false;
	DecodeModRmRegFieldSimd(8, &state->instr->operands[0], modRm, state->rex);
	return true;
}


static bool DecodeCvttps2pi(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeCvtPsOperands(state))
		return false;
	state->instr->op = X86_CVTTPS2PI;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeCvttss2si(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t dstSizes[] = {4, 4, 8};
	const uint8_t srcSize = g_sseOperandSizes[0]; // FIXME: VEX
	const uint8_t dstSize = dstSizes[state->operandMode];
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!DecodeModRmRmFieldSimd(state, srcSize, &state->instr->operands[1], modRm))
		return false;
	DecodeModRmRegField(dstSize, &state->instr->operands[0], modRm, state->rex);

	state->instr->flags.repne = 0;
	state->instr->op = X86_CVTTSS2SI;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeCvttpd2pi(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeCvtPsOperands(state))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_CVTTPD2PI;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeCvttsd2si(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t dstSizes[] = {4, 4, 8};
	const uint8_t srcSize = g_sseOperandSizes[0]; // FIXME: VEX
	const uint8_t dstSize = dstSizes[state->operandMode];
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!DecodeModRmRmFieldSimd(state, srcSize, &state->instr->operands[1], modRm))
		return false;
	DecodeModRmRegField(dstSize, &state->instr->operands[0], modRm, state->rex);

	state->instr->flags.repe = 0;
	state->instr->op = X86_CVTTSD2SI;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeCvtps2pi(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeCvtPsOperands(state))
		return false;
	state->instr->op = X86_CVTPS2PI;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeCvtss2si(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t dstSizes[] = {4, 4, 8};
	const uint8_t srcSize = g_sseOperandSizes[0]; // FIXME: VEX
	const uint8_t dstSize = dstSizes[state->operandMode];
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!DecodeModRmRmFieldSimd(state, srcSize, &state->instr->operands[1], modRm))
		return false;
	DecodeModRmRegField(dstSize, &state->instr->operands[0], modRm, state->rex);

	state->instr->flags.repne = 0;
	state->instr->op = X86_CVTSS2SI;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeCvtpd2pi(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeCvtPsOperands(state))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_CVTPD2PI;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeCvtsd2si(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t dstSizes[] = {4, 4, 8};
	const uint8_t srcSize = g_sseOperandSizes[0]; // FIXME: VEX
	const uint8_t dstSize = dstSizes[state->operandMode];
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!DecodeModRmRmFieldSimd(state, srcSize, &state->instr->operands[1], modRm))
		return false;
	DecodeModRmRegField(dstSize, &state->instr->operands[0], modRm, state->rex);

	state->instr->flags.repe = 0;
	state->instr->op = X86_CVTSD2SI;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeUcomiss(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->op = X86_UCOMISS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeComiss(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->op = X86_COMISS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeUcomisd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_UCOMISD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeComisd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_COMISD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMsrTscSys(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[] =
	{
		X86_WRMSR, X86_RDTSC, X86_RDMSR, X86_RDPMC,
		X86_SYSENTER, X86_SYSEXIT
	};
	static const bool validx64[] = {true, true, true, false, false};
	const uint8_t operation = (opcode & 7);

	if ((!validx64[operation]) && (state->addrMode == X86_64BIT))
		return false;
	state->instr->op = operations[operation];

	return true;
}


static bool Decode38Table(X86DecoderState* const state, uint8_t opcode)
{
	// Grab a byte from the machine
	if (!Fetch(state, 1, &opcode))
		return false;

	return g_0f38Decoders[opcode](state, opcode);
}


static bool Decode3aTable(X86DecoderState* const state, uint8_t opcode)
{
	// Grab a byte from the machine
	if (!Fetch(state, 1, &opcode))
		return false;

	return g_0f3aDecoders[opcode](state, opcode);
}


static bool DecodeMovConditional(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[] =
	{
		X86_CMOVO, X86_CMOVNO, X86_CMOVB, X86_CMOVNB,
		X86_CMOVZ, X86_CMOVNZ, X86_CMOVBE, X86_CMOVNBE,
		X86_CMOVS, X86_CMOVNS, X86_CMOVP, X86_CMOVNP,
		X86_CMOVL, X86_CMOVNL, X86_CMOVLE, X86_CMOVNLE
	};
	const uint8_t op = (opcode & 0xf);
	const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];

	if (!DecodeModRmRev(state, operandSize, state->instr->operands))
		return false;

	state->instr->op = operations[op];
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeMovmskps(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;

	DecodeModRmRmFieldSimdReg(operandSize, &state->instr->operands[1], modRm, state->rex);
	DecodeModRmRegField(4, &state->instr->operands[0], modRm, state->rex);

	state->instr->op = X86_MOVMSKPS;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeMovmskpd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;

	DecodeModRmRmFieldSimdReg(operandSize, &state->instr->operands[1], modRm, state->rex);
	DecodeModRmRegField(4, &state->instr->operands[0], modRm, state->rex);

	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_MOVMSKPD;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeSqrtps(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->op = X86_SQRTPS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeSqrtss(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.repne = 0;
	state->instr->op = X86_SQRTSS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeSqrtpd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_SQRTPD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeSqrtsd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.repe = 0;
	state->instr->op = X86_SQRTSD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeRsqrtps(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->op = X86_RSQRTPS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeRsqrtss(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.repne = 0;
	state->instr->op = X86_RSQRTSS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeRcpps(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->op = X86_RCPPS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeRcpss(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.repne = 0;
	state->instr->op = X86_RCPSS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeAndps(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->op = X86_ANDPS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeAndpd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_ANDPD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeAndnps(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->op = X86_ANDNPS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeAndnpd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_ANDNPD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeOrps(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->op = X86_ORPS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeOrpd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_ORPD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeXorps(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->op = X86_XORPS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeXorpd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_XORPD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeAddps(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->op = X86_ADDPS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeAddss(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.repne = 0;
	state->instr->op = X86_ADDSS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeAddpd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_ADDPD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeAddsd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.repe = 0;
	state->instr->op = X86_ADDSD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMulps(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->op = X86_MULPS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMulss(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.repne = 0;
	state->instr->op = X86_MULSS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMulpd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_MULPD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMulsd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.repe = 0;
	state->instr->op = X86_MULSD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeSubps(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->op = X86_SUBPS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeSubss(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.repne = 0;
	state->instr->op = X86_SUBSS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeSubpd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_SUBPD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeSubsd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.repe = 0;
	state->instr->op = X86_SUBSD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMinps(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->op = X86_MINPS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMinss(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.repne = 0;
	state->instr->op = X86_MINSS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMinpd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_MINPD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMinsd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.repe = 0;
	state->instr->op = X86_MINSD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeDivps(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->op = X86_DIVPS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeDivss(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.repne = 0;
	state->instr->op = X86_DIVSS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeDivpd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_DIVPD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeDivsd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.repe = 0;
	state->instr->op = X86_DIVSD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMaxps(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->op = X86_MAXPS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMaxss(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.repne = 0;
	state->instr->op = X86_MAXSS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMaxpd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_MAXPD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMaxsd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.repe = 0;
	state->instr->op = X86_MAXSD;
	state->instr->operandCount = 2;
	return true;
}


static __inline bool DecodeMmxSseUnpackOperands(X86DecoderState* const state)
{
	static const uint8_t srcSizes[2] = {4, 8};
	static const uint8_t regSizes[2] = {8, 16};
	const uint8_t regSel = (state->secondaryTable >> 1);
	const uint8_t regSize = regSizes[regSel];
	ModRmByte modRm;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!DecodeModRmRmFieldSimd(state, regSize, &state->instr->operands[1], modRm))
		return false;
	DecodeModRmRegFieldSimd(regSize, &state->instr->operands[0], modRm, state->rex);

	// Lied about the sizes above to decode as SSE or MMX, now fix up the actual operand size here
	state->instr->operands[1].size = srcSizes[regSel];
	state->instr->operands[0].size = 8;

	return true;
}


static bool DecodePunpcklbw(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeMmxSseUnpackOperands(state))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_PUNPCKLBW;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodePunpcklwd(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeMmxSseUnpackOperands(state))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_PUNPCKLWD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodePunpckldq(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeMmxSseUnpackOperands(state))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_PUNPCKLDQ;
	state->instr->operandCount = 2;
	return true;
}


static __inline bool DecodeMmxSsePackOperands(X86DecoderState* const state)
{
	static const uint8_t regSizes[2] = {8, 16};
	const uint8_t regSel = (state->secondaryTable >> 1);
	const uint8_t regSize = regSizes[regSel];
	if (!DecodeModRmSimdRev(state, regSize, state->instr->operands))
		return false;
	return true;
}


static bool DecodePacksswb(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeMmxSsePackOperands(state))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_PACKSSWB;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodePcmpgtb(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeMmxSsePackOperands(state))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_PCMPGTB;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodePcmpgtw(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeMmxSsePackOperands(state))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_PCMPGTW;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodePcmpgtd(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeMmxSsePackOperands(state))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_PCMPGTD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodePackuswb(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeMmxSsePackOperands(state))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_PACKUSWB;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodePunpckhbw(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeMmxSseUnpackOperands(state))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_PUNPCKHBW;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodePunpckhwd(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeMmxSseUnpackOperands(state))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_PUNPCKHWD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodePunpckhdq(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeMmxSseUnpackOperands(state))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_PUNPCKHDQ;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodePackssdw(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeMmxSsePackOperands(state))
		return false;
	state->instr->op = X86_PACKSSDW;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodePunpcklqdq(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeModRmSimdRev(state, 16, state->instr->operands))
		return false;
	state->instr->operands[0].size = 16;
	state->instr->operands[1].size = 8;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_PUNPCKLQDQ;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodePunpckhqdq(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (!DecodeModRmSimdRev(state, 16, state->instr->operands))
		return false;
	state->instr->operands[0].size = 16;
	state->instr->operands[1].size = 8;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_PUNPCKHQDQ;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMovd(X86DecoderState* const state, uint8_t opcode)
{
	static const uint8_t operandSizes[] = {8, 16};
	const uint8_t direction = ((opcode >> 4) & 1);
	const uint8_t operand0 = direction;
	const uint8_t operand1 = ((~direction) & 1);
	const uint8_t operandSize = operandSizes[state->secondaryTable >> 1];
	ModRmByte modRm;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!DecodeModRmRmField(state, 4, &state->instr->operands[operand1], modRm))
		return false;
	DecodeModRmRegFieldSimd(operandSize, &state->instr->operands[operand0], modRm, state->rex);

	// Lied about the operand size above to decode as SSE reg, now fix it up
	state->instr->operands[operand0].size = 8;

	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_MOVD;
	state->instr->operandCount = 2;

	return true;
}


static __inline bool DecodeMovSimd(X86DecoderState* const state, uint8_t opcode,
	X86Operation op, uint8_t operandSize)
{
	const uint8_t direction = ((opcode >> 4) & 1);
	if (!DecodeModRmSimdDirection(state, operandSize, state->instr->operands, direction))
		return false;
	state->instr->op = op;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMovq(X86DecoderState* const state, uint8_t opcode)
{
	static const uint8_t regSizes[2] = {16, 8};
	const uint8_t regSel = (opcode & 1);
	const uint8_t regSize = regSizes[regSel];
	const uint8_t direction = (((opcode >> 4) & opcode) & 1);

	if (!DecodeModRmSimdDirection(state, regSize, state->instr->operands, direction))
		return false;
	state->instr->operands[0].size = 8;
	state->instr->operands[1].size = 8;

	state->instr->op = X86_MOVQ;
	state->instr->operandCount = 2 ;

	return true;
}


static bool DecodeMovdqu(X86DecoderState* const state, uint8_t opcode)
{
	state->instr->flags.repne = 0;
	return DecodeMovSimd(state, opcode, X86_MOVDQU, 16);
}


static bool DecodeMovdqa(X86DecoderState* const state, uint8_t opcode)
{
	state->instr->flags.operandSizeOverride = 0;
	return DecodeMovSimd(state, opcode, X86_MOVDQA, 16);
}


static __inline bool DecodePshuf(X86DecoderState* const state, X86Operation op, uint8_t operandSize)
{
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;

	state->instr->op = op;
	state->instr->operandCount = 3;

	return true;
}


static bool DecodePshufw(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	return DecodePshuf(state, X86_PSHUFW, 8);
}


static bool DecodePshufhw(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	// This uses half SSE registers. Decode as 16 byte then replace operand size
	if (!DecodePshuf(state, X86_PSHUFHW, 16))
		return false;
	state->instr->flags.repne = 0;
	state->instr->operands[0].size = 8;
	state->instr->operands[1].size = 8;
	return true;
}


static bool DecodePshufd(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	state->instr->flags.operandSizeOverride = 0;
	return DecodePshuf(state, X86_PSHUFD, 16);
}


static bool DecodePshuflw(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	// This uses half SSE registers. Decode as 16 byte then replace operand size
	if (!DecodePshuf(state, X86_PSHUFLW, 16))
		return false;
	state->instr->flags.repe = 0;
	state->instr->operands[0].size = 8;
	state->instr->operands[1].size = 8;
	return true;
}


static __inline bool DecodePackedSingleGroups(X86DecoderState* const state, const X86Operation* const operations)
{
	static const uint8_t operandSizes[2] = {8, 16};
	const uint8_t operandSize = operandSizes[state->secondaryTable >> 1];
	ModRmByte modRm;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!IsModRmRmFieldReg(modRm))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[1], 1))
		return false;
	DecodeModRmRmFieldSimdReg(operandSize, &state->instr->operands[0], modRm, state->rex);

	state->instr->op = operations[modRm.reg];
	if (state->instr->op == X86_INVALID)
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeGroup12(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[] =
	{
		X86_INVALID, X86_INVALID, X86_PSRLW, X86_INVALID,
		X86_PSRAW, X86_INVALID, X86_PSLLW, X86_INVALID,
	};
	(void)opcode;

	if (!DecodePackedSingleGroups(state, operations))
		return false;

	return true;
}


static bool DecodeGroup13(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[] =
	{
		X86_INVALID, X86_INVALID, X86_PSRLD, X86_INVALID,
		X86_PSRAD, X86_INVALID, X86_PSLLD, X86_INVALID,
	};
	(void)opcode;

	if (!DecodePackedSingleGroups(state, operations))
		return false;

	return true;
}


static bool DecodeGroup14(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[2][8] =
	{
		{
			X86_INVALID, X86_INVALID, X86_PSRLQ, X86_INVALID,
			X86_INVALID, X86_INVALID, X86_PSLLQ, X86_INVALID
		},
		{
			X86_INVALID, X86_INVALID, X86_PSRLQ, X86_PSRLDQ,
			X86_INVALID, X86_INVALID, X86_PSLLQ, X86_PSLLDQ
		},
	};

	(void)opcode;

	if (!DecodePackedSingleGroups(state, operations[state->secondaryTable >> 1]))
		return false;

	return true;
}


static bool DecodeGroup17(X86DecoderState* const state, uint8_t opcode)
{
	ModRmByte modRm;
	union
	{
		uint8_t bytes[2];
		struct
		{
			uint8_t imm1;
			uint8_t imm2;
		};
	} args;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (modRm.reg != 0)
		return false;
	if (IsModRmRmFieldReg(modRm))
	{
		// Lie and decode operands as 16 bytes to get SSE reg, then fix size up after
		DecodeModRmRmFieldSimdReg(16, &state->instr->operands[0], modRm, state->rex);
		state->instr->operands[0].size = 8;
	}
	else
	{
		if (!DecodeModRmRmFieldMemory(state, 8, &state->instr->operands[1], modRm))
			return false;
	}

	if (!Fetch(state, 2, args.bytes))
		return false;
	InitImmediate(&state->instr->operands[1], args.imm1, 8);
	InitImmediate(&state->instr->operands[2], args.imm2, 8);

	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_EXTRQ;
	state->instr->operandCount = 3;

	return true;
}


static bool DecodeExtrq(X86DecoderState* const state, uint8_t opcode)
{
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!IsModRmRmFieldReg(modRm))
		return false;
	DecodeModRmRmFieldSimdReg(16, &state->instr->operands[1], modRm, state->rex);
	DecodeModRmRegFieldSimd(16, &state->instr->operands[0], modRm, state->rex);

	// Lied about the size to decode as SSE reg. Fix it up here.
	state->instr->operands[0].size = 8;

	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_EXTRQ;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeHaddHsubPacked(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[2][2] =
	{
		{X86_HADDPD, X86_HSUBPD},
		{X86_HADDPS, X86_HSUBPS}
	};
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	const uint8_t opcodeColBit = (opcode & 1);
	const uint8_t opcodeRowBit = (state->secondaryTable & 1);

	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;

	state->instr->flags.operandSizeOverride = 0;
	state->instr->flags.repe = 0;
	state->instr->op = operations[opcodeRowBit][opcodeColBit];
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeInsertqImm(X86DecoderState* const state, uint8_t opcode)
{
	union
	{
		uint8_t bytes[3];
		struct
		{
			ModRmByte modRm;
			uint8_t imm1;
			uint8_t imm2;
		};
	} args;

	(void)opcode;

	if (!Fetch(state, 3, args.bytes))
		return false;
	if (!IsModRmRmFieldReg(args.modRm))
		return false;
	DecodeModRmRegFieldSimd(16, &state->instr->operands[0], args.modRm, state->rex);
	DecodeModRmRmFieldSimdReg(16, &state->instr->operands[1], args.modRm, state->rex);

	// This encoding is for 8 bytes of 2 SSE regs. Decode as 16 byte above and fixup size here
	state->instr->operands[0].size = 8;
	state->instr->operands[1].size = 8;

	InitImmediate(&state->instr->operands[2], args.imm1, 1);
	InitImmediate(&state->instr->operands[3], args.imm2, 1);

	state->instr->flags.repe = 0;
	state->instr->op = X86_INSERTQ;
	state->instr->operandCount = 4;

	return true;
}


static bool DecodeInsertq(X86DecoderState* const state, uint8_t opcode)
{
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!IsModRmRmFieldReg(modRm))
		return false;
	DecodeModRmRmFieldSimdReg(16, &state->instr->operands[1], modRm, state->rex);
	DecodeModRmRegFieldSimd(16, &state->instr->operands[0], modRm, state->rex);

	// Lied about the size to decode as SSE reg. Fix it up here.
	state->instr->operands[0].size = 8;

	state->instr->op = X86_INSERTQ;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodePackedCmp(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[3] = {X86_PCMPEQB, X86_PCMPEQW, X86_PCMPEQD};
	static const uint8_t operandSizes[] = {8, 16};
	const uint8_t op = (opcode & 3);
	const uint8_t operandSize = operandSizes[state->secondaryTable >> 1];

	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;

	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = operations[op];
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeEmms(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	state->instr->op = X86_EMMS;
	return true;
}


static bool DecodeCvtps2pd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->op = X86_CVTPS2PD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeCvtss2sd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.repne = 0;
	state->instr->op = X86_CVTSS2SD;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeCvtpd2ps(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_CVTPD2PS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeCvtsd2ss(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.repe = 0;
	state->instr->op = X86_CVTSD2SS;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeCvtdq2ps(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!DecodeModRmRmFieldSimd(state, 16, &state->instr->operands[1], modRm))
		return false;
	DecodeModRmRegFieldSimd(operandSize, &state->instr->operands[0], modRm, state->rex);

	state->instr->op = X86_CVTDQ2PS;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeCvttps2dq(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!DecodeModRmRmFieldSimd(state, operandSize, &state->instr->operands[1], modRm))
		return false;
	DecodeModRmRegFieldSimd(16, &state->instr->operands[0], modRm, state->rex);

	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_CVTTPS2DQ;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeCvtps2dq(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!DecodeModRmRmFieldSimd(state, operandSize, &state->instr->operands[1], modRm))
		return false;
	DecodeModRmRegFieldSimd(16, &state->instr->operands[0], modRm, state->rex);

	state->instr->op = X86_CVTPS2DQ;
	state->instr->operandCount = 2;

	return true;
}


static bool DecodeGroup16(X86DecoderState* const state, uint8_t opcode)
{
	static const X86Operation operations[] =
	{
		X86_PREFETCHNTA, X86_PREFETCHT0, X86_PREFETCHT1, X86_PREFETCHT2,
		X86_NOP, X86_NOP, X86_NOP, X86_NOP
	};
	ModRmByte modRm;

	(void)opcode;

	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (IsModRmRmFieldReg(modRm))
	{
		// FIXME: These seem to nop on real hardware.
		return false;
	}
	if (!DecodeModRmRmFieldMemory(state, 1, &state->instr->operands[0], modRm))
		return false;

	state->instr->op = operations[modRm.reg];
	state->instr->operandCount = 1;

	return true;
}


static bool DecodeMovsldup(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0];
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.repne = 0;
	state->instr->op = X86_MOVSLDUP;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMovshdup(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0];
	(void)opcode;
	if (!DecodeModRmSimd(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.repne = 0;
	state->instr->op = X86_MOVSHDUP;
	state->instr->operandCount = 2;
	return true;
}


static bool DecodeMovddup(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0];
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->operands[0].size = 16;
	state->instr->flags.repe = 0;
	state->instr->op = X86_MOVDDUP;
	state->instr->operandCount = 2;
	return true;
}


static const InstructionDecoder g_secondaryDecodersF3[256] =
{
	// Row 0
	DecodeGroup6, DecodeGroup7, DecodeLoadSegmentInfo, DecodeLoadSegmentInfo,
	DecodeInvalid, DecodeSys, DecodeSys, DecodeSys,
	DecodeInvd, DecodeInvd, DecodeInvalid, DecodeUd2,
	DecodeInvalid, DecodeGroupP, DecodeFemms, Decode3dnow,

	// Row 1
	DecodeMovss, DecodeMovss, DecodeMovsldup, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeMovshdup, DecodeInvalid,
	DecodeGroup16, DecodeNopModRm, DecodeNopModRm, DecodeNopModRm,
	DecodeNopModRm, DecodeNopModRm, DecodeNopModRm, DecodeNopModRm,

	// Row 2
	DecodeMovSpecialPurpose, DecodeMovSpecialPurpose, DecodeMovSpecialPurpose, DecodeMovSpecialPurpose,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeCvtsi2ss, DecodeMovntss,
	DecodeCvttss2si, DecodeCvtss2si, DecodeInvalid, DecodeInvalid,

	// Row 3
	DecodeMsrTscSys, DecodeMsrTscSys, DecodeMsrTscSys, DecodeMsrTscSys,
	DecodeMsrTscSys, DecodeMsrTscSys, DecodeInvalid, DecodeInvalid,
	Decode38Table, DecodeInvalid, Decode3aTable, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 4
	DecodeMovConditional, DecodeMovConditional, DecodeMovConditional, DecodeMovConditional,
	DecodeMovConditional, DecodeMovConditional, DecodeMovConditional, DecodeMovConditional,
	DecodeMovConditional, DecodeMovConditional, DecodeMovConditional, DecodeMovConditional,
	DecodeMovConditional, DecodeMovConditional, DecodeMovConditional, DecodeMovConditional,

	// Row 5
	DecodeInvalid, DecodeSqrtss, DecodeRsqrtss, DecodeRcpss,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeAddss, DecodeMulss, DecodeCvtss2sd, DecodeCvttps2dq,
	DecodeSubss, DecodeMinss, DecodeDivss, DecodeMaxss,

	// Row 6
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeMovdqu,

	// Row 7
	DecodePshufhw, DecodeGroup12, DecodeGroup13, DecodeGroup14,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeMovq, DecodeMovdqu,

	// Row 8
	DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional,
	DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional,
	DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional,
	DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional,

	// Row 9
	DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte,
	DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte,
	DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte,
	DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte,

	// Row 0xa
	DecodePushPopFsGs, DecodePushPopFsGs, DecodeCpuid, DecodeBt,
	DecodeShiftd, DecodeShiftd, DecodeInvalid, DecodeInvalid,
	DecodePushPopFsGs, DecodePushPopFsGs, DecodeRsm, DecodeBt,
	DecodeShiftd, DecodeShiftd, DecodeGroup15, DecodeImul,

	// Row 0xb
	DecodeCmpxchg, DecodeCmpxchg, DecodeLss, DecodeBt,
	DecodeLfs, DecodeLgs, DecodeMovExtend, DecodeMovExtend,
	DecodePopcnt, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeTzcnt, DecodeLzcnt, DecodeInvalid, DecodeInvalid,

	// Row 0xc
	DecodeXadd, DecodeXadd, DecodeCmpss, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeGroup9,
	DecodeBswap, DecodeBswap, DecodeBswap, DecodeBswap,
	DecodeBswap, DecodeBswap, DecodeBswap, DecodeBswap,

	// Row 0xd
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeMovq2dq, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 0xe
	DecodeInvalid, DecodeInvalid, DecodeCvtdq2pd, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 0xf
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeUd,
};

static const InstructionDecoder g_secondaryDecoders66[256] =
{
	// Row 0
	DecodeGroup6, DecodeGroup7, DecodeLoadSegmentInfo, DecodeLoadSegmentInfo,
	DecodeInvalid, DecodeSys, DecodeSys, DecodeSys,
	DecodeInvd, DecodeInvd, DecodeInvalid, DecodeUd2,
	DecodeInvalid, DecodeGroupP, DecodeFemms, Decode3dnow,

	// Row 1
	DecodeMovupd, DecodeMovupd, DecodeMovlpd, DecodeMovlpd,
	DecodeUnpcklpd, DecodeUnpckhpd, DecodeMovhpd, DecodeMovhpd,
	DecodeGroup16, DecodeNopModRm, DecodeNopModRm, DecodeNopModRm,
	DecodeNopModRm, DecodeNopModRm, DecodeNopModRm, DecodeNopModRm,

	// Row 2
	DecodeMovSpecialPurpose, DecodeMovSpecialPurpose, DecodeMovSpecialPurpose, DecodeMovSpecialPurpose,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeMovapd, DecodeMovapd, DecodeCvtpi2pd, DecodeMovntpd,
	DecodeCvttpd2pi, DecodeCvtpd2pi, DecodeUcomisd, DecodeComisd,

	// Row 3
	DecodeMsrTscSys, DecodeMsrTscSys, DecodeMsrTscSys, DecodeMsrTscSys,
	DecodeMsrTscSys, DecodeMsrTscSys, DecodeInvalid, DecodeInvalid,
	Decode38Table, DecodeInvalid, Decode3aTable, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 4
	DecodeMovConditional, DecodeMovConditional, DecodeMovConditional, DecodeMovConditional,
	DecodeMovConditional, DecodeMovConditional, DecodeMovConditional, DecodeMovConditional,
	DecodeMovConditional, DecodeMovConditional, DecodeMovConditional, DecodeMovConditional,
	DecodeMovConditional, DecodeMovConditional, DecodeMovConditional, DecodeMovConditional,

	// Row 5
	DecodeMovmskpd, DecodeSqrtpd, DecodeInvalid, DecodeInvalid,
	DecodeAndpd, DecodeAndnpd, DecodeOrpd, DecodeXorpd,
	DecodeAddpd, DecodeMulpd, DecodeCvtpd2ps, DecodeCvtps2dq,
	DecodeSubpd, DecodeMinpd, DecodeDivpd, DecodeMaxpd,

	// Row 6
	DecodePunpcklbw, DecodePunpcklwd, DecodePunpckldq, DecodePacksswb,
	DecodePcmpgtb, DecodePcmpgtw, DecodePcmpgtd, DecodePackuswb,
	DecodePunpckhbw, DecodePunpckhwd, DecodePunpckhdq, DecodePackssdw,
	DecodePunpcklqdq, DecodePunpckhqdq, DecodeMovd, DecodeMovdqa,

	// Row 7
	DecodePshufd, DecodeGroup12, DecodeGroup13, DecodeGroup14,
	DecodePackedCmp, DecodePackedCmp, DecodePackedCmp, DecodeInvalid,
	DecodeGroup17, DecodeExtrq, DecodeInvalid, DecodeInvalid,
	DecodeHaddHsubPacked, DecodeHaddHsubPacked, DecodeMovd, DecodeMovdqa,

	// Row 8
	DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional,
	DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional,
	DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional,
	DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional,

	// Row 9
	DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte,
	DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte,
	DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte,
	DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte,

	// Row 0xa
	DecodePushPopFsGs, DecodePushPopFsGs, DecodeCpuid, DecodeBt,
	DecodeShiftd, DecodeShiftd, DecodeInvalid, DecodeInvalid,
	DecodePushPopFsGs, DecodePushPopFsGs, DecodeRsm, DecodeBt,
	DecodeShiftd, DecodeShiftd, DecodeGroup15, DecodeImul,

	// Row 0xb
	DecodeCmpxchg, DecodeCmpxchg, DecodeLss, DecodeBt,
	DecodeLfs, DecodeLgs, DecodeMovExtend, DecodeMovExtend,
	DecodeInvalid, DecodeGroup10, DecodeGroup8, DecodeBt,
	DecodeBitScan, DecodeBitScan, DecodeMovExtend, DecodeMovExtend,

	// Row 0xc
	DecodeXadd, DecodeXadd, DecodeCmppd, DecodeInvalid,
	DecodePinsrw, DecodePextrw, DecodeShufpd, DecodeGroup9,
	DecodeBswap, DecodeBswap, DecodeBswap, DecodeBswap,
	DecodeBswap, DecodeBswap, DecodeBswap, DecodeBswap,

	// Row 0xd
	DecodeAddSubPacked, DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic,
	DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeMovq, DecodeMovmskb,
	DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic,
	DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic,

	// Row 0xe
	DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic,
	DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeCvttpd2dq, DecodeMovntdq,
	DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic,
	DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic,

	// Row 0xf
	DecodeInvalid, DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic,
	DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeMaskMovdqu,
	DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic,
	DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeUd,
};

static const InstructionDecoder g_secondaryDecodersF2[256] =
{
	// Row 0
	DecodeGroup6, DecodeGroup7, DecodeLoadSegmentInfo, DecodeLoadSegmentInfo,
	DecodeInvalid, DecodeSys, DecodeSys, DecodeSys,
	DecodeInvd, DecodeInvd, DecodeInvalid, DecodeUd2,
	DecodeInvalid, DecodeGroupP, DecodeFemms, Decode3dnow,

	// Row 1
	DecodeMovsd, DecodeMovsd, DecodeMovddup, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeGroup16, DecodeNopModRm, DecodeNopModRm, DecodeNopModRm,
	DecodeNopModRm, DecodeNopModRm, DecodeNopModRm, DecodeNopModRm,

	// Row 2
	DecodeMovSpecialPurpose, DecodeMovSpecialPurpose, DecodeMovSpecialPurpose, DecodeMovSpecialPurpose,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeCvtsi2sd, DecodeMovntsd,
	DecodeCvttsd2si, DecodeCvtsd2si, DecodeInvalid, DecodeInvalid,

	// Row 3
	DecodeMsrTscSys, DecodeMsrTscSys, DecodeMsrTscSys, DecodeMsrTscSys,
	DecodeMsrTscSys, DecodeMsrTscSys, DecodeInvalid, DecodeInvalid,
	Decode38Table, DecodeInvalid, Decode3aTable, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 4
	DecodeMovConditional, DecodeMovConditional, DecodeMovConditional, DecodeMovConditional,
	DecodeMovConditional, DecodeMovConditional, DecodeMovConditional, DecodeMovConditional,
	DecodeMovConditional, DecodeMovConditional, DecodeMovConditional, DecodeMovConditional,
	DecodeMovConditional, DecodeMovConditional, DecodeMovConditional, DecodeMovConditional,

	// Row 5
	DecodeInvalid, DecodeSqrtsd, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeAddsd, DecodeMulsd, DecodeCvtsd2ss, DecodeInvalid,
	DecodeSubsd, DecodeMinsd, DecodeDivsd, DecodeMaxsd,

	// Row 6
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 7
	DecodePshuflw, DecodeGroup12, DecodeGroup13, DecodeGroup14,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInsertqImm, DecodeInsertq, DecodeInvalid, DecodeInvalid,
	DecodeHaddHsubPacked, DecodeHaddHsubPacked, DecodeInvalid, DecodeInvalid,

	// Row 8
	DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional,
	DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional,
	DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional,
	DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional,

	// Row 9
	DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte,
	DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte,
	DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte,
	DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte,

	// Row 0xa
	DecodePushPopFsGs, DecodePushPopFsGs, DecodeCpuid, DecodeBt,
	DecodeShiftd, DecodeShiftd, DecodeInvalid, DecodeInvalid,
	DecodePushPopFsGs, DecodePushPopFsGs, DecodeRsm, DecodeBt,
	DecodeShiftd, DecodeShiftd, DecodeGroup15, DecodeImul,

	// Row 0xb
	DecodeCmpxchg, DecodeCmpxchg, DecodeLss, DecodeBt,
	DecodeLfs, DecodeLgs, DecodeMovExtend, DecodeMovExtend,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 0xc
	DecodeXadd, DecodeXadd, DecodeCmpsd, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeGroup9,
	DecodeBswap, DecodeBswap, DecodeBswap, DecodeBswap,
	DecodeBswap, DecodeBswap, DecodeBswap, DecodeBswap,

	// Row 0xd
	DecodeAddSubPacked, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeMovdq2q, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 0xe
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeCvtpd2dq, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 0xf
	DecodeLddqu, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeUd,
};

static const InstructionDecoder g_secondaryDecodersNormal[256] =
{
	// Row 0
	DecodeGroup6, DecodeGroup7, DecodeLoadSegmentInfo, DecodeLoadSegmentInfo,
	DecodeInvalid, DecodeSys, DecodeSys, DecodeSys,
	DecodeInvd, DecodeInvd, DecodeInvalid, DecodeUd2,
	DecodeInvalid, DecodeGroupP, DecodeFemms, Decode3dnow,

	// Row 1
	DecodeMovups, DecodeMovups,
	DecodeUnalignedPackedSingle, DecodeUnalignedPackedSingle,
	DecodeUnpackSingle, DecodeUnpackSingle, DecodeUnalignedPackedSingle, DecodeUnalignedPackedSingle,
	DecodeGroup16, DecodeNopModRm, DecodeNopModRm, DecodeNopModRm,
	DecodeNopModRm, DecodeNopModRm, DecodeNopModRm, DecodeNopModRm,

	// Row 2
	DecodeMovSpecialPurpose, DecodeMovSpecialPurpose, DecodeMovSpecialPurpose, DecodeMovSpecialPurpose,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeMovaps, DecodeMovaps, DecodeCvtpi2ps, DecodeMovntps,
	DecodeCvttps2pi, DecodeCvtps2pi, DecodeUcomiss, DecodeComiss,

	// Row 3
	DecodeMsrTscSys, DecodeMsrTscSys, DecodeMsrTscSys, DecodeMsrTscSys,
	DecodeMsrTscSys, DecodeMsrTscSys, DecodeInvalid, DecodeInvalid,
	Decode38Table, DecodeInvalid, Decode3aTable, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 4
	DecodeMovConditional, DecodeMovConditional, DecodeMovConditional, DecodeMovConditional,
	DecodeMovConditional, DecodeMovConditional, DecodeMovConditional, DecodeMovConditional,
	DecodeMovConditional, DecodeMovConditional, DecodeMovConditional, DecodeMovConditional,
	DecodeMovConditional, DecodeMovConditional, DecodeMovConditional, DecodeMovConditional,

	// Row 5
	DecodeMovmskps, DecodeSqrtps, DecodeRsqrtps, DecodeRcpps,
	DecodeAndps, DecodeAndnps, DecodeOrps, DecodeXorps,
	DecodeAddps, DecodeMulps, DecodeCvtps2pd, DecodeCvtdq2ps,
	DecodeSubps, DecodeMinps, DecodeDivps, DecodeMaxps,

	// Row 6
	DecodePunpcklbw, DecodePunpcklwd, DecodePunpckldq, DecodePacksswb,
	DecodePcmpgtb, DecodePcmpgtw, DecodePcmpgtd, DecodePackuswb,
	DecodePunpckhbw, DecodePunpckhwd, DecodePunpckhdq, DecodePackssdw,
	DecodeInvalid, DecodeInvalid, DecodeMovd, DecodeMovq,

	// Row 7
	DecodePshufw, DecodeGroup12, DecodeGroup13, DecodeGroup14,
	DecodePackedCmp, DecodePackedCmp, DecodePackedCmp, DecodeEmms,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeMovd, DecodeMovq,

	// Row 8
	DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional,
	DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional,
	DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional,
	DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional, DecodeJmpConditional,

	// Row 9
	DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte,
	DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte,
	DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte,
	DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte, DecodeFlagSetByte,

	// Row 0xa
	DecodePushPopFsGs, DecodePushPopFsGs, DecodeCpuid, DecodeBt,
	DecodeShiftd, DecodeShiftd, DecodeInvalid, DecodeInvalid,
	DecodePushPopFsGs, DecodePushPopFsGs, DecodeRsm, DecodeBt,
	DecodeShiftd, DecodeShiftd, DecodeGroup15, DecodeImul,

	// Row 0xb
	DecodeCmpxchg, DecodeCmpxchg, DecodeLss, DecodeBt,
	DecodeLfs, DecodeLgs, DecodeMovExtend, DecodeMovExtend,
	DecodeInvalid, DecodeGroup10, DecodeGroup8, DecodeBt,
	DecodeBitScan, DecodeBitScan, DecodeMovExtend, DecodeMovExtend,

	// Row 0xc
	DecodeXadd, DecodeXadd, DecodeCmpps, DecodeMovnti,
	DecodePinsrw, DecodePextrw, DecodeShufps, DecodeGroup9,
	DecodeBswap, DecodeBswap, DecodeBswap, DecodeBswap,
	DecodeBswap, DecodeBswap, DecodeBswap, DecodeBswap,

	// Row 0xd
	DecodeInvalid, DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic,
	DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeInvalid, DecodeMovmskb,
	DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic,
	DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic,

	// Row 0xe
	DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic,
	DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeInvalid, DecodeMovntq,
	DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic,
	DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic,

	// Row 0xf
	DecodeInvalid, DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic,
	DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeMaskMovq,
	DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic,
	DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeSimdArithmetic, DecodeUd,
};


static const InstructionDecoder* g_secondaryDecoders[4] =
{
	g_secondaryDecodersNormal,
	g_secondaryDecodersF3,
	g_secondaryDecoders66,
	g_secondaryDecodersF2,
};

static bool DecodeSecondaryOpCodeTable(X86DecoderState* const state, uint8_t opcode)
{
	InstructionDecoder decoder;

	// Grab a byte from the machine
	if (!Fetch(state, 1, &opcode))
		return false;

	decoder = g_secondaryDecoders[state->secondaryTable][opcode];
	if (!decoder(state, opcode))
		return false;

	return true;
}


static bool DecodePshufb(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PSHUFB;
	return true;
}


static bool DecodePhaddw(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PHADDW;
	return true;
}


static bool DecodePhaddd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PHADDD;
	return true;
}


static bool DecodePhaddsw(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PHADDSW;
	return true;
}


static bool DecodePmaddubsw(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PMADDUBSW;
	return true;
}


static bool DecodePhsubw(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PHSUBW;
	return true;
}


static bool DecodePhsubd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PHSUBD;
	return true;
}


static bool DecodePhsubsw(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PHSUBSW;
	return true;
}


static bool DecodePsignb(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PSIGNB;
	return true;
}


static bool DecodePsignw(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PSIGNW;
	return true;
}


static bool DecodePsignd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PSIGND;
	return true;
}


static bool DecodePmulhrsw(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PMULHRSW;
	return true;
}


static bool DecodePblendvb(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PBLENDVB;
	return true;
}


static bool DecodeBlendvps(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_BLENDVPS;
	return true;
}


static bool DecodeBlendvpd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_BLENDVPD;
	return true;
}


static bool DecodePtest(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	// Lied about size above to decode as correct register, now fix up here.
	state->instr->operands[0].size = 8;
	state->instr->operands[1].size = 8;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PTEST;
	return true;
}


static bool DecodePabsb(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PABSB;
	return true;
}


static bool DecodePabsw(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PABSW;
	return true;
}


static bool DecodePabsd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PABSD;
	return true;
}


static __inline bool DecodePmovxOperands(X86DecoderState* const state, uint8_t srcSize)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	ModRmByte modRm;

	if (!Fetch(state, 1, &modRm.byte))
		return false;

	if (!IsModRmRmFieldReg(modRm))
	{
		if (!DecodeModRmRmFieldMemory(state, srcSize, &state->instr->operands[1], modRm))
			return false;
	}
	else
	{
		DecodeModRmRmFieldSimdReg(operandSize, &state->instr->operands[1], modRm, state->rex);
	}

	DecodeModRmRegFieldSimd(operandSize, &state->instr->operands[0], modRm, state->rex);

	return true;
}


static bool DecodePmovsxbw(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodePmovxOperands(state, 8))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PMOVSXBW;
	return true;
}


static bool DecodePmovsxbd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodePmovxOperands(state, 4))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PMOVSXBD;
	return true;
}


static bool DecodePmovsxbq(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodePmovxOperands(state, 2))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PMOVSXBQ;
	return true;
}


static bool DecodePmovsxwd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodePmovxOperands(state, 8))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PMOVSXWD;
	return true;
}


static bool DecodePmovsxwq(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodePmovxOperands(state, 4))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PMOVSXWQ;
	return true;
}


static bool DecodePmovsxdq(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodePmovxOperands(state, 8))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PMOVSXDQ;
	return true;
}


static bool DecodePmuldq(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PMULDQ;
	return true;
}


static bool DecodePcmpeqq(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PCMPEQQ;
	return true;
}


static bool DecodeMovntdqa(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimd(state, operandSize, state->instr->operands))
		return false;
	// Lied about size above to decode as correct register, now fix up here.
	state->instr->operands[0].size = 8;
	state->instr->operands[1].size = 8;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PMULDQ;
	return true;
}


static bool DecodePackusdw(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PACKUSDW;
	return true;
}


static bool DecodePmovzxbw(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodePmovxOperands(state, 8))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PMOVZXBW;
	return true;
}


static bool DecodePmovzxbd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodePmovxOperands(state, 4))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PMOVZXBD;
	return true;
}


static bool DecodePmovzxbq(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodePmovxOperands(state, 2))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PMOVZXBQ;
	return true;
}


static bool DecodePmovzxwd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodePmovxOperands(state, 8))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PMOVZXWD;
	return true;
}


static bool DecodePmovzxwq(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodePmovxOperands(state, 4))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PMOVZXWQ;
	return true;
}


static bool DecodePmovzxdq(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodePmovxOperands(state, 8))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PMOVZXDQ;
	return true;
}


static bool DecodePcmpgtq(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PCMPGTQ;
	return true;
}


static bool DecodePminsb(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PMINSB;
	return true;
}


static bool DecodePminsd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PMINSD;
	return true;
}


static bool DecodePminuw(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PMINUW;
	return true;
}


static bool DecodePminud(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PMINUD;
	return true;
}


static bool DecodePmaxsb(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PMAXSB;
	return true;
}


static bool DecodePmaxsd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PMAXSD;
	return true;
}


static bool DecodePmaxuw(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PMAXUW;
	return true;
}


static bool DecodePmaxud(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PMAXUD;
	return true;
}


static bool DecodePmulld(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PMULLD;
	return true;
}


static bool DecodePhminposuw(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_PHMINPOSUW;
	return true;
}


static bool DecodeAesimc(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_AESIMC;
	return true;
}


static bool DecodeAesenc(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_AESENC;
	return true;
}


static bool DecodeAesenclast(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_AESENCLAST;
	return true;
}


static bool DecodeAesdec(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_AESDEC;
	return true;
}


static bool DecodeAesdeclast(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 2;
	state->instr->op = X86_AESDECLAST;
	return true;
}


static bool DecodeMovbeCrc(X86DecoderState* const state, uint8_t opcode)
{
	ModRmByte modRm;

	if (!Fetch(state, 1, &modRm.byte))
		return false;

	if (state->secondaryTable == SECONDARY_TABLE_NORMAL)
	{
		// MOVBE
		const uint8_t direction = (opcode & 1);
		const uint8_t operand0 = direction;
		const uint8_t operand1 = ((~direction) & 1);
		const uint8_t operandSize = g_decoderModeSizeXref[state->operandMode];

		if (IsModRmRmFieldReg(modRm))
			return false;
		if (!DecodeModRmRmFieldMemory(state, operandSize, &state->instr->operands[operand1], modRm))
			return false;
		DecodeModRmRegField(operandSize, &state->instr->operands[operand0], modRm, state->rex);

		state->instr->op = X86_MOVBE;
	}
	else
	{
		// CRC32
		static const uint8_t destSizes[] = {4, 4, 8};
		const uint8_t srcSizes[] = {1, g_decoderModeSizeXref[state->operandMode]};
		const uint8_t srcSizeBit = (opcode & 1);
		const uint8_t destSize = destSizes[state->operandMode];
		const uint8_t srcSize = srcSizes[srcSizeBit];

		if (!DecodeModRmRmField(state, srcSize, &state->instr->operands[1], modRm))
			return false;
		DecodeModRmRegField(destSize, &state->instr->operands[0], modRm, state->rex);

		state->instr->op = X86_CRC32;
	}

	state->instr->flags.operandSizeOverride = 0;
	state->instr->flags.repe = 0;
	state->instr->flags.repne = 0;

	state->instr->operandCount = 2;

	return true;
}


static const InstructionDecoder g_0f38Decoders[256] =
{
	// Row 0
	DecodePshufb, DecodePhaddw, DecodePhaddd, DecodePhaddsw,
	DecodePmaddubsw, DecodePhsubw, DecodePhsubd, DecodePhsubsw,
	DecodePsignb, DecodePsignw, DecodePsignd, DecodePmulhrsw,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 1
	DecodePblendvb, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeBlendvps, DecodeBlendvpd, DecodeInvalid,  DecodePtest,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodePabsb, DecodePabsw, DecodePabsd, DecodeInvalid,

	// Row 2
	DecodePmovsxbw, DecodePmovsxbd, DecodePmovsxbq, DecodePmovsxwd,
	DecodePmovsxwq, DecodePmovsxdq, DecodeInvalid, DecodeInvalid,
	DecodePmuldq, DecodePcmpeqq, DecodeMovntdqa, DecodePackusdw,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 3
	DecodePmovzxbw, DecodePmovzxbd, DecodePmovzxbq, DecodePmovzxwd,
	DecodePmovzxwq, DecodePmovzxdq, DecodeInvalid, DecodePcmpgtq,
	DecodePminsb, DecodePminsd, DecodePminuw, DecodePminud,
	DecodePmaxsb, DecodePmaxsd, DecodePmaxuw, DecodePmaxud,

	// Row 4
	DecodePmulld, DecodePhminposuw, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 5
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 6
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 7
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 8
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 9
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 0xa
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 0xb
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 0xc
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 0xd
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeAesimc,
	DecodeAesenc, DecodeAesenclast, DecodeAesdec, DecodeAesdeclast,

	// Row 0xe
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	DecodeMovbeCrc, DecodeMovbeCrc, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
};


static bool DecodeRoundps(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;
	state->instr->op = X86_ROUNDPS;
	state->instr->operandCount = 3;
	return true;
}


static bool DecodeRoundpd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;
	state->instr->op = X86_ROUNDPD;
	state->instr->operandCount = 3;
	return true;
}


static bool DecodeRoundss(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;
	state->instr->op = X86_ROUNDSS;
	state->instr->operandCount = 3;
	return true;
}


static bool DecodeRoundsd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;
	state->instr->op = X86_ROUNDSD;
	state->instr->operandCount = 3;
	return true;
}


static bool DecodeBlendps(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;
	state->instr->op = X86_BLENDPS;
	state->instr->operandCount = 3;
	return true;
}


static bool DecodeBlendpd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;
	state->instr->op = X86_BLENDPD;
	state->instr->operandCount = 3;
	return true;
}


static bool DecodePblendw(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;
	state->instr->op = X86_PBLENDW;
	state->instr->operandCount = 3;
	return true;
}


static bool DecodePalignr(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	(void)opcode;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;
	state->instr->op = X86_PALIGNR;
	state->instr->operandCount = 3;
	return true;
}


static bool DecodePextrb(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	ModRmByte modRm;

	(void)opcode;

	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!Fetch(state, 1, &modRm.byte))
		return false;

	if (!IsModRmRmFieldReg(modRm))
	{
		if (!DecodeModRmRmFieldMemory(state, 1, &state->instr->operands[0], modRm))
			return false;
	}
	else
	{
		static const uint8_t srcSizes[] = {4, 4, 8};
		const uint8_t srcSize = srcSizes[state->operandMode];
		DecodeModRmRmFieldReg(srcSize, &state->instr->operands[0], modRm, state->rex);
	}
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;
	DecodeModRmRegFieldSimd(operandSize, &state->instr->operands[1], modRm, state->rex);

	state->instr->op = X86_PEXTRB;
	state->instr->operandCount = 3;

	return true;
}


static bool DecodePextrw3a(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	ModRmByte modRm;

	(void)opcode;

	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!Fetch(state, 1, &modRm.byte))
		return false;

	if (!IsModRmRmFieldReg(modRm))
	{
		if (!DecodeModRmRmFieldMemory(state, 2, &state->instr->operands[0], modRm))
			return false;
	}
	else
	{
		static const uint8_t srcSizes[] = {4, 4, 8};
		const uint8_t srcSize = srcSizes[state->operandMode];
		DecodeModRmRmFieldReg(srcSize, &state->instr->operands[0], modRm, state->rex);
	}
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;
	DecodeModRmRegFieldSimd(operandSize, &state->instr->operands[1], modRm, state->rex);

	state->instr->op = X86_PEXTRW;
	state->instr->operandCount = 3;

	return true;
}


static bool DecodePextrdq(X86DecoderState* const state, uint8_t opcode)
{
	static const uint8_t destSizes[] = {4, 8};
	static const X86Operation operations[] = {X86_PEXTRD, X86_PEXTRQ};
	const uint8_t destSize = destSizes[0]; // FIXME: REX
	ModRmByte modRm;

	(void)opcode;

	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!DecodeModRmRmField(state, destSize, &state->instr->operands[0], modRm))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;
	DecodeModRmRegFieldSimd(16, &state->instr->operands[1], modRm, state->rex);

	state->instr->op = operations[0]; // FIXME: REX prefix makes this PEXTRQ
	state->instr->operandCount = 3;

	return true;
}


static bool DecodeExtractps(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	ModRmByte modRm;

	(void)opcode;

	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!Fetch(state, 1, &modRm.byte))
		return false;

	if (!IsModRmRmFieldReg(modRm))
	{
		if (!DecodeModRmRmFieldMemory(state, 4, &state->instr->operands[0], modRm))
			return false;
	}
	else
	{
		static const uint8_t destSizes[] = {4, 4, 8};
		const uint8_t destSize = destSizes[state->operandMode];
		DecodeModRmRmFieldReg(destSize, &state->instr->operands[0], modRm, state->rex);
	}
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;
	DecodeModRmRegFieldSimd(operandSize, &state->instr->operands[1], modRm, state->rex);

	state->instr->op = X86_EXTRACTPS;
	state->instr->operandCount = 3;

	return true;
}


static bool DecodePinsrb(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	ModRmByte modRm;

	(void)opcode;

	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!DecodeModRmRmField(state, 1, &state->instr->operands[1], modRm))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;
	DecodeModRmRegFieldSimd(operandSize, &state->instr->operands[0], modRm, state->rex);

	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_PINSRB;
	state->instr->operandCount = 3;

	return true;
}


static bool DecodeInsertps(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_simdOperandSizes[state->secondaryTable >> 1];
	ModRmByte modRm;

	(void)opcode;

	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!IsModRmRmFieldReg(modRm))
	{
		if (!DecodeModRmRmFieldMemory(state, 4, &state->instr->operands[1], modRm))
			return false;
	}
	else
	{
		DecodeModRmRmFieldSimdReg(16, &state->instr->operands[1], modRm, state->rex);
	}
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;
	DecodeModRmRegFieldSimd(operandSize, &state->instr->operands[0], modRm, state->rex);

	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = X86_INSERTPS;
	state->instr->operandCount = 3;

	return true;
}


static bool DecodePinsrdq(X86DecoderState* const state, uint8_t opcode)
{
	static const uint8_t srcSizes[] = {4, 8};
	static const X86Operation operations[] = {X86_PINSRD, X86_PINSRQ};
	const uint8_t destSize = g_sseOperandSizes[0]; // FIXME: VEX
	const uint8_t srcSize = srcSizes[0]; // FIXME: REX
	ModRmByte modRm;

	(void)opcode;

	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!Fetch(state, 1, &modRm.byte))
		return false;
	if (!DecodeModRmRmField(state, srcSize, &state->instr->operands[1], modRm))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;
	DecodeModRmRegFieldSimd(destSize, &state->instr->operands[0], modRm, state->rex);

	state->instr->flags.operandSizeOverride = 0;
	state->instr->op = operations[0]; // FIXME: REX
	state->instr->operandCount = 3;

	return true;
}


static bool DecodeDpps(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX

	(void)opcode;

	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;

	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 3;
	state->instr->op = X86_DPPS;

	return true;
}


static bool DecodeDppd(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX

	(void)opcode;

	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;

	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 3;
	state->instr->op = X86_DPPD;

	return true;
}


static bool DecodeMpsadbw(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX

	(void)opcode;

	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;

	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 3;
	state->instr->op = X86_MPSADBW;

	return true;
}


static bool DecodePclmulqdq(X86DecoderState* const state, uint8_t opcode)
{
	const uint8_t operandSize = g_sseOperandSizes[0]; // FIXME: VEX

	(void)opcode;

	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, operandSize, state->instr->operands))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;

	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 3;
	state->instr->op = X86_PCLMULQDQ;

	return true;
}


static bool DecodePcmpestrm(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;

	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, 16, state->instr->operands))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;

	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 3;
	state->instr->op = X86_PCMPESTRM;

	return true;
}


static bool DecodePcmpestri(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;

	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, 16, state->instr->operands))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;

	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 3;
	state->instr->op = X86_PCMPESTRI;

	return true;
}


static bool DecodePcmpistrm(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;

	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, 16, state->instr->operands))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;

	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 3;
	state->instr->op = X86_PCMPISTRM;

	return true;
}


static bool DecodePcmpistri(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;

	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, 16, state->instr->operands))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;

	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 3;
	state->instr->op = X86_PCMPISTRI;

	return true;
}


static bool DecodeAesKeygenAssist(X86DecoderState* const state, uint8_t opcode)
{
	(void)opcode;

	if (state->secondaryTable != SECONDARY_TABLE_66)
		return false;
	if (!DecodeModRmSimdRev(state, 16, state->instr->operands))
		return false;
	if (!DecodeImmediate(state, &state->instr->operands[2], 1))
		return false;

	state->instr->flags.operandSizeOverride = 0;
	state->instr->operandCount = 3;
	state->instr->op = X86_AESKEYGENASSIST;

	return true;
}


static const InstructionDecoder g_0f3aDecoders[256] =
{
	// Row 0
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeRoundps, DecodeRoundpd, DecodeRoundss, DecodeRoundsd,
	DecodeBlendps, DecodeBlendpd, DecodePblendw, DecodePalignr,

	// Row 1
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodePextrb, DecodePextrw3a, DecodePextrdq, DecodeExtractps,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 2
	DecodePinsrb, DecodeInsertps, DecodePinsrdq, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 3
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 4
	DecodeDpps, DecodeDppd, DecodeMpsadbw, DecodeInvalid,
	DecodePclmulqdq, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 5
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 6
	DecodePcmpestrm, DecodePcmpestri, DecodePcmpistrm, DecodePcmpistri,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 7
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 8
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 9
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 0xa
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 0xb
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 0xc
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 0xd
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeAesKeygenAssist,

	/// Row 0xe
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,

	// Row 0xf
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
	DecodeInvalid, DecodeInvalid, DecodeInvalid, DecodeInvalid,
};

