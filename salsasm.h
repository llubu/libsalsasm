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
#ifndef __SALSASM_H__
#define __SALSASM_H__

#include <stdint.h>

#ifdef _MSC_VER
	#ifndef __cplusplus
		typedef unsigned char bool;
		#define true  1
		#define false 0
	#endif
#else
	#ifndef __cplusplus
		#include <stdbool.h>
	#endif
#endif


typedef enum X86Operation
{
	X86_NOP
} X86Operation;

typedef struct X86Instruction
{
	X86Operation op;
} X86Instruction;


typedef bool (*InstructionFetchCallback)(void* ctxt, uint8_t* result);

bool Disassemble16(InstructionFetchCallback fetch, X86Instruction* instr);
bool Disassemble32(InstructionFetchCallback fetch, X86Instruction* instr);
bool Disassemble64(InstructionFetchCallback fetch, X86Instruction* instr);


#endif /* __SALSASM_H__ */
