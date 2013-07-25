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
#ifndef __CODEGEN_H__
#define __CODEGEN_H__

#include "salsasm.h"

#define X86_64BIT

#define add_8 0
#define add_16 1
#define add_32 1

typedef enum
{
	add = 0,
	adc = 0x10,
	and = 0x20,
	xor = 0x30,
} ARITHMETIC_OPCODES;

typedef struct CodeGenContext
{
	uint8_t* buf;
	uint8_t* offset;
	size_t len;
	uint8_t mode;
} CodeGenContext;

typedef struct MemoryReference
{
	uint8_t base;
	uint8_t scale;
	uint8_t index;
	uint32_t displacement;
} MemoryReference;


static __inline void __emit_arithmetic_rr(CodeGenContext* const ctxt, uint8_t op, uint8_t size,
	uint8_t destReg, uint8_t srcReg)
{
	const uint8_t modRm = 0xc0 | ((destReg & 7) << 3) | (srcReg & 7);
	uint8_t* code = ctxt->offset;

	// Emit an operand size override prefix if requested size is not the current mode
	if (ctxt->mode == size)
		*code++ = 0x66;

	// Now emit the opcode, set the low bit for 1 byte
	*code++ = op | ((~size) & 1);
	*code++ = modRm;

	ctxt->offset = code;
}


static __inline void __emit_arithmetic_rm(CodeGenContext* const ctxt, uint8_t op, uint8_t size,
	uint8_t destReg, MemoryReference* src)
{
	// const uint8_t modRm = 0x00 | ((destReg & 7) << 3) | (srcReg & 7);
	uint8_t modRm;
	uint8_t* code = ctxt->offset;

	// Emit an operand size override prefix if requested size is not the current mode
	if (ctxt->mode == size)
		*code++ = 0x66;

	// Now emit the opcode, set the low bit for 1 byte
	*code++ = op | ((~size) & 1);
	// *code++ = modRm;

	ctxt->offset = code;
}


#define EMIT_RR(buf, op, dest, src) \
{ \

}

#define EMIT_MR(op, dest, src)
#define EMIT_RM(op, dest, src)
#define EMIT_RI(op, dest, src)


#endif /* __CODEGEN_H__ */
