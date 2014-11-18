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
#include <stdio.h>

#include "salsasm_types.h"
#include "decode.h"

#ifdef WIN32
#define snprintf _snprintf
#endif

// NOTE: These must be maintained in the same order as X86Operations enum!
static const char* const g_x86Mnemonics[] =
{
	"invalid",
	"aaa", "aad", "aam", "aas", "adc", "add", "addpd",
	"addps", "addsd", "addss", "addsubpd", "addsubps", "adx",
	"aesimc", "aesenc", "aesenclast", "aesdec", "aesdeclast", "aeskeygenassist",
	"amx", "and", "andnpd", "andnps", "andpd", "andps", "arpl",
	"blendpd", "blendps", "blendvpd", "blendvps", "bound", "bsf",
	"bsr", "bswap", "bt", "btc", "btr", "bts", "calln", "callf",
	"cbw", "cwde", "cdqe", "clac", "clc", "cld", "clflush", "clgi", "cli",
	"clts", "cmc", "cmovb", "cmovnae", "cmovc", "cmovbe", "cmovna",
	"cmovl", "cmovnge", "cmovle", "cmovng", "cmovnb", "cmovae",
	"cmovnc", "cmovnbe", "cmova", "cmovnl", "cmovge", "cmovnle",
	"cmovg", "cmovno", "cmovnp", "cmovpo", "cmovns", "cmovnz", "cmovne",
	"cmovo", "cmovp", "cmovpe", "cmovs", "cmovz", "cmove", "cmp",
	"cmppd", "cmpps", "cmps", "cmpsb", "cmpsw", "cmpsd", "cmpsq",
	"cmpss", "cmpxchg", "cmpxchg8b", "cmpxchg16b", "comisd", "comiss",
	"cpuid", "crc32", "cvtdq2pd", "cvtdq2ps", "cvtpd2dq", "cvtpd2pi",
	"cvtpd2ps", "cvtpi2pd", "cvtpi2ps", "cvtps2dq", "cvtps2pd", "cvtps2pi",
	"cvtsd2si", "cvtsd2ss", "cvtsi2sd", "cvtsi2ss", "cvtss2sd", "cvtss2si",
	"cvttpd2dq", "cvttpd2pi", "cvttps2dq", "cvttps2pi", "cvttsd2si", "cvttss2si",
	"cvttps2d", "cwd", "cdq", "cqo", "daa", "das", "dec", "div", "divpd",
	"divps", "divsd", "divss", "dppd", "dpps", "emms", "enter", "extractps", "extrq",
	"f2xm1", "fabs", "fadd", "faddp", "fbld", "fbstp", "fchs", "fclex",
	"fcmovb", "fcmovbe", "fcmove", "fcmovnb", "fcmovnbe", "fcmovne", "fcmovnu",
	"fcmovu", "fcom", "fcom2", "fcomi", "fcomip", "fcomp", "fcomp3", "fcomp5",
	"fcompp", "fcos", "fdecstp", "fdiv", "fdivp", "fdivr", "fdivrp", "femms", "ffree",
	"ffreep", "fiadd", "ficom", "ficomp", "fidiv", "fidivr", "fild", "fimul",
	"fincstp", "finit", "fist", "fistp", "fisttp", "fisub", "fisubr",
	"fld", "fld1", "fldcw", "fldenv", "fldl2e", "fldl2t", "fldlg2", "fldln2",
	"fldpi", "fldz", "fmul", "fmulp", "fnclex", "fndisi", "fneni", "fninit",
	"fnop", "fnsave", "fnsetpm", "fnstcw", "fnstenv", "fnstsw", "fpatan",
	"fprem", "fprem1", "fptan", "frndint", "frstor", "fsave", "fscale", "fsin",
	"fsincos", "fsqrt", "fst", "fstcw", "fstenv", "fstp", "fstp1", "fstp8",
	"fstp9", "fstsw", "fsub", "fsubp", "fsubr", "fsubrp", "ftst", "fucom",
	"fucomi", "fucomip", "fucomp", "fucompp", "fwait", "wait", "fxam", "fxch",
	"fxch4", "fxch7", "fxrstor", "fxsave", "fxtract", "fyl2x", "fyl2xp1", "getsec",
	"haddpd", "haddps", "hint_nop", "hlt", "hsubpd", "hsubps", "idiv", "imul",
	"in", "inc", "ins", "insb", "insw", "insd", "insertps", "insertq", "int", "int1", "int3",
	"icebp", "into", "invd", "invept", "invlpg", "invlpga", "invvpid", "invpcid", "iret", "iretd",
	"iretq", "jb", "jnae", "jc", "jbe", "jna", "jcxz", "jecxz", "jrcxz",
	"jl", "jnge", "jle", "jng", "jmpn", "jmpf", "jnc", "jnb", "jae",
	"ja", "jnbe", "jnl", "jge", "jnle", "jg", "jno", "jpo", "jnp",
	"jns", "jnz", "jne", "jo", "jp", "jpe", "js", "jz", "je", "lahf",
	"lar", "lddqu", "ldmxcsr", "lds", "lea", "leave", "les", "lfence",
	"lfs", "lgdt", "lgs", "lidt", "lldt", "lmsw", "lods", "lodsb",
	"lodsw", "lodsd", "lodsq", "loop", "loopnz", "loopne", "loopz", "loope",
	"lsl", "lss", "ltr", "lzcnt", "maskmovdqu", "maskmovq", "maxpd", "maxps",
	"maxsd", "maxss", "mfence", "minpd", "minps", "minsd", "minss",
	"monitor", "mov", "movapd", "movaps", "movbe", "movd", "movq", "movddup",
	"movdq2q", "movdqa", "movdqu", "movhlps", "movhpd", "movhps", "movlhps",
	"movlpd", "movlps", "movmskpd", "movmskps", "movntdq", "movntdqa", "movnti",
	"movntpd", "movntps", "movntq", "movntss", "movntsd", "movq2dq", "movs", "movsb", "movsw", "movsq",
	"movsd","movshdup", "movsldup", "movss", "movsx", "movsxd", "movupd", "movups", "movzx",
	"mpsadbw", "mul", "mulpd", "mulps", "mulsd", "mulss", "mwait", "neg",
	"nop", "not", "or", "orpd", "orps", "out", "outs", "outsb", "outsw",
	"outsd", "pabsb", "pabsd", "pabsw", "packssdw", "packsswb", "packusdw",
	"packuswb", "paddb", "paddd", "paddq", "paddsb", "paddsw", "paddusb",
	"paddusw", "paddw", "palignr", "pand", "pandn", "pause", "pavgb",
	"pavgw", "pblendvb", "pblendw", "pclmulqdq", "pcmpeqb", "pcmpeqd", "pcmpeqq",
	"pcmpeqw", "pcmpestri", "pcmpestrm", "pcmpgtb", "pcmpgtd", "pcmpgtq",
	"pcmpgtw", "pcmpistri", "pcmpistrm", "pextrb", "pextrd", "pextrq",
	"pextrw", "pfnacc", "pfpnacc", "pfcmpge", "pfmin", "pfrcp", "pfrsqrt", "pfmax",
	"pfsqrt", "pfsub", "pfadd", "pfcmpgt", "pfrcpit1", "pfrsqit1", "pfsubr", "pfacc",
	"pfcmpeq", "pfmul", "pfrcpit2", "pmulhrw", "pswapd", "pavgusb",
	"phaddd", "phaddsw", "phaddw", "phminposuw", "phsubd", "phsubsw",
	"phsubw", "pi2fw", "pi2fd", "pf2iw", "pf2id",
	"pinsrb", "pinsrd", "pinsrq", "pinsrw", "pmaddubsw", "pmaddwd",
	"pmaxsb", "pmaxsd", "pmaxsw", "pmaxub", "pmaxud", "pmaxuw", "pminsb",
	"pminsd", "pminsw", "pminub", "pminud", "pminuw", "pmovmskb", "pmovsxbd",
	"pmovsxbq", "pmovsxbw", "pmovsxdq", "pmovsxwd", "pmovsxwq", "pmovzxbd",
	"pmovzxbq", "pmovzxbw", "pmovzxdq", "pmovzxwd", "pmovzxwq", "pmuldq",
	"pmulhrsw", "pmulhuw", "pmulhw", "pmulld", "pmullw", "pmuludq", "pop",
	"popa", "popad", "popcnt", "popf", "popfq", "popfd", "por",
	"prefetch", "prefetchw", "prefetchnta", "prefetcht0", "prefetcht1", "prefetcht2",
	"psadbw", "pshufb", "pshufd", "pshufhw", "pshuflw", "pshufw", "psignb",
	"psignd", "psignw", "pslld", "pslldq", "psllq", "psllw", "psrad", "psraw", "psrld",
	"psrldq", "psrlq", "psrlw", "psubb", "psubd", "psubq", "psubsb", "psubsw",
	"psubusb", "psubusw", "psubw", "ptest", "punpckhbw", "punpckhdq",
	"punpckhqdq", "punpckhwd", "punpcklbw", "punpckldq", "punpcklqdq",
	"punpcklwd", "push", "pusha", "pushad", "pushf", "pushfq", "pushfd",
	"pxor", "rcl", "rcpps", "rcpss", "rcr", "rdmsr", "rdpmc", "rdrand", "rdseed",
	"rdtsc", "rdtscp", "retf", "retn", "rol", "ror", "roundpd", "roundps", "roundsd",
	"roundss", "rsm", "rsqrtps", "rsqrtss", "sahf", "sal", "shl",
	"salc", "setalc", "sar", "sbb", "scas", "scasb", "scasw",
	"scasd", "scasq", "setb", "setnae", "setc", "setbe", "setna",
	"setl", "setnge", "setle", "setng", "setnb", "setae", "setnc",
	"setnbe", "seta", "setnl", "setge", "setnle", "setg", "setno",
	"setnp", "setpo", "setns", "setnz", "setne", "seto", "setp",
	"setpe", "sets", "setz", "sete", "sfence", "sgdt", "skinit", "sldt", "shld", "shr",
	"shrd", "shufpd", "shufps", "sidt", "smsw", "sqrtpd", "sqrtps",
	"sqrtsd", "sqrtss", "stac", "stc", "std", "stgi", "sti", "stmxcsr", "stos",
	"stosb", "stosw", "stosd", "stosq", "str", "sub", "subpd",
	"subps", "subsd", "subss", "swapgs", "syscall", "sysenter", "sysexit",
	"sysret", "test", "tzcnt", "ucomisd", "ucomiss", "ud", "ud1", "ud2", "unpckhpd",
	"unpckhps", "unpcklpd", "unpcklps", "vblendpd", "vblendps",
	"vblendvpd", "vblendvps", "vdppd", "vdpps", "vextractps", "vinsertps",
	"vmovntdqa", "vmpsadbw", "vpackudsw", "vblendvb", "vpblendw",
	"vpcmpeqq", "vpextrb", "vpextrd", "vpextrw", "vphminposuw",
	"vpinsrb", "vpinsrd", "vpinsrq", "vpmaxsb", "vpmaxsd",
	"vmpaxud", "vpmaxuw", "vpminsb", "vpminsd", "vpminud", "vpminuw",
	"vpmovsxbd", "vpmovsxbq", "vpmovsxbw", "vpmovsxwd", "vpmovsxwq",
	"vpmovsxdq", "vpmovzxbd", "vpmovzxbq", "vpmovzxbw", "vpmovzxwd",
	"vpmovzxwq", "vpmovzxdq", "vpmuldq", "vpmulld", "vptest",
	"vroundpd", "vroundps", "vroundsd", "vroundss", "vpcmpestri",
	"vpcmpestrm", "vpcmpgtq", "vpcmpistri", "vpcmpistrm", "vaesdec",
	"vaesdeclast", "vaesenc", "vaesenclast", "vaesimc", "vaeskeygenassist",
	"vpabsb", "vpabsd", "vpabsw", "vpalignr", "vpahadd", "vphaddw",
	"vphaddsw", "vphsubd", "vphsubw", "vphsubsw", "vpmaddubsw",
	"vpmulhrsw", "vpshufb", "vpsignb", "vpsignd", "vpsignw", "vaddsubpd",
	"vaddsubps", "vhaddpd", "vhaddps", "vhsubpd", "vhsubps", "vlddqu",
	"vmovddup", "vmovhlps", "vmovshdup", "vmovsldup", "vaddpd", "vaddsd",
	"vanpd", "vandnpd", "vcmppd", "vcmpsd", "vcomisd",
	"vcvtdq2pd", "vcvtdq2ps", "vcvtpd2dq", "vcvtpd2ps", "vcvtps2dq",
	"vcvtps2pd", "vcvtsd2si", "vcvtsd2ss", "vcvtsi2sd", "vcvtss2sd",
	"vcvttpd2dq", "vcvttps2dq", "vcvttsd2si", "vdivpd", "vdivsd",
	"vmaskmovdqu", "vmaxpd", "vmaxsd", "vminpd", "vminsd", "vmovapd",
	"vmovd", "vmovq", "vmovdqa", "vmovdqu", "vmovhpd", "vmovlpd",
	"vmovmskpd", "vmovntdq", "vmovntpd", "vmovsd", "vmovupd",
	"vmulpd", "vmulsd", "vorpd", "vpacksswb", "vpackssdw",
	"vpackuswb", "vpaddb", "vpaddw", "vpaddd", "vpaddq", "vpaddsb",
	"vpaddsw", "vpaddusb", "vpaddusw", "vpand", "vpandn", "vpavgb",
	"vpavgw", "vpcmpeqb", "vpcmpeqw", "vpcmpeqd", "vpcmpgtb",
	"vpcmpgtw", "vpcmpgtd", "vpextsrw", "vpmaddwd",
	"vpmaxsw", "vpmaxub", "vpminsw", "vpminub", "vpmovmskb",
	"vpmulhuw", "vpmulhw", "vpmullw", "vpmuludq", "vpor",
	"vpsadbw", "vpshufd", "vpshufhw", "vpshuflw", "vpslldq",
	"vpsllw", "vpslld", "vpsllq", "vpsraw", "vpsrad",
	"vpsrldq", "vpsrlw", "vpsrld", "vpsrlq", "vpsubb",
	"vpsubw", "vpsubd", "vpsqubq", "vpsubsb", "vpsubsw",
	"vpsubusb", "vpsubusw", "vpunpckhbw", "vpunpckhwd", "vpunpckhdq",
	"vpunpckhqdq", "vpunpcklbw", "vpunpcklwd", "vpunpckldq", "vpuncklqdq",
	"vpxor", "vshufpd", "vsqrtpd", "vsqrtsd", "vsubpd", "vsubsd",
	"vucomisd", "vunpckhpd", "vunpckhps", "vunpcklpd", "vunpcklps",
	"vxorpd", "vaddps",  "vaddss", "vandps", "vandnps", "vcmpps",
	"vcmpss", "vcomiss", "vcvtsi2ss", "vcvtss2si", "vcvttss2si",
	"vdivps", "vldmxcsr", "vmaxps", "vmaxss", "vminps", "vminss",
	"vmovaps", "vmovhps", "vmovlhps", "vmovlps", "vmovmskps",
	"vmovntps", "vmovss", "vmovups", "vmulps", "vmulss", "vorps",
	"vrcpps", "vrcpss", "vrsqrtps", "vrsqrtss", "vsqrtps", "vsqrtss",
	"vstmxcsr", "vsubps", "vsubss", "vucomiss", "vxorps",
	"vbroadcast", "vextractf128", "vinsertf128", "vpermilpd", "vpermilps",
	"vperm2f128", "vtestpd", "vtestps", "verr", "verw", "vmcall", "vmmcall",
	"vmrun", "vmclear", "vmlaunch", "vmptrld", "vmptrst", "vmread", "vmfunc",
	"vmresume", "vmwrite", "vmxoff", "vmxon", "vmload", "vmsave",
	"wbinvd", "wrmsr", "xabort", "xadd", "xbegin", "xchg", "xend", "xgetbv", "xlat",
	"xlatb", "xor", "xorpd", "xorps", "xrstor", "xsave", "xsaveopt", "xsetbv", "xtest"
};

// Must be maintained in same order as X86OperandType
const char* const g_operandTypeNames[] =
{
	// X86_NONE = 0,
	// X86_MEM,
	// X86_IMMEDIATE,
	"none", "mem", "imm",

	// Segment registers
	// X86_CS, X86_SS, X86_DS, X86_ES, X86_FS, X86_GS,
	"cs", "ss", "ds", "es", "fs", "gs",

	// Instruction Pointer
	// X86_IP, X86_EIP, X86_RIP,
	"ip", "eip", "rip",

	// Flags
	// X86_FLAGS, X86_EFLAGS, X86_RFLAGS,
	"flags", "eflags", "rflags",

	// GPRs
	// X86_AL, X86_AH, X86_AX, X86_EAX, X86_RAX,
	"al", "ah", "ax", "eax", "rax",

	// X86_CL, X86_CH, X86_CX, X86_ECX, X86_RCX,
	"cl", "ch", "cx", "ecx", "rcx",

	// X86_DL, X86_DH, X86_DX, X86_EDX, X86_RDX,
	"dl", "dh", "dx", "edx", "rdx",

	// X86_BL, X86_BH, X86_BX, X86_EBX, X86_RBX,
	"bl", "bh", "bx", "ebx", "rbx",

	// X86_SPL, X86_SP, X86_ESP, X86_RSP,
	"spl", "sp", "esp", "rsp",

	// X86_BPL, X86_BP, X86_EBP, X86_RBP,
	"bpl", "bp", "ebp", "rbp",

	// X86_SIL, X86_SI, X86_ESI, X86_RSI,
	"sil", "si", "esi", "rsi",

	// X86_DIL, X86_DI, X86_EDI, X86_RDI,
	"dil", "di", "edi", "rdi",

	// X86_R8B, X86_R8W, X86_R8D, X86_R8,
	"r8b", "r8w", "r8d", "r8",

	// X86_R9B, X86_R9W, X86_R9D, X86_R9,
	"r9b", "r9w", "r9d", "r9",

	// X86_R10B, X86_R10W, X86_R10D, X86_R10,
	"r10b", "r10w", "r10d", "r10",

	// X86_R11B, X86_R11W, X86_R11D, X86_R11,
	"r11b", "r11w", "r11d", "r11",

	// X86_R12B, X86_R12W, X86_R12D, X86_R12,
	"r12b", "r12w", "r12d", "r12",

	// X86_R13B, X86_R13W, X86_R13D, X86_R13,
	"r13b", "r13w", "r13d", "r13",

	// X86_R14B, X86_R14W, X86_R14D, X86_R14,
	"r14b", "r14w", "r14d", "r14",

	// X86_R15B, X86_R15W, X86_R15D, X86_R15,
	"r15b", "r15w", "r15d", "r15",

	// FPU, MMX
	// X86_FPU_TAG, X86_FPU_STATUS, X86_FPU_CONTROL, X86_FPU_DATA, X86_FPU_IP, X86_FP_OPCODE,
	"fptag", "fpsw", "fpcw", "fpdata", "fpip", "fpopcode",

	// X86_ST0, X86_ST1, X86_ST2, X86_ST3, X86_ST4, X86_ST5, X86_ST6, X86_ST7,
	"st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7",

	// X86_MM0, X86_MM1, X86_MM2, X86_MM3, X86_MM4, X86_MM5, X86_MM6, X86_MM7,
	"mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7",

	// SSE, AVX, PHI
	// X86_MXCSR,
	"mxcsr",

	// X86_XMM0, X86_XMM1, X86_XMM2, X86_XMM3, X86_XMM4, X86_XMM5, X86_XMM6, X86_XMM7,
	"xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
	// X86_XMM8, X86_XMM9, X86_XMM10, X86_XMM11, X86_XMM12, X86_XMM13, X86_XMM14, X86_XMM15,
	"xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",

	// X86_YMM0, X86_YMM1, X86_YMM2, X86_YMM3, X86_YMM4, X86_YMM5, X86_YMM6, X86_YMM7,
	"ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7",
	// X86_YMM8, X86_YMM9, X86_YMM10, X86_YMM11, X86_YMM12, X86_YMM13, X86_YMM14, X86_YMM15,
	"ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15",

	// X86_ZMM0, X86_ZMM1, X86_ZMM2, X86_ZMM3, X86_ZMM4, X86_ZMM5, X86_ZMM6, X86_ZMM7,
	"zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7",
	// X86_ZMM8, X86_ZMM9, X86_ZMM10, X86_ZMM11, X86_ZMM12, X86_ZMM13, X86_ZMM14, X86_ZMM15,
	"zmm8", "zmm9", "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15",

	// Control Registers
	// X86_CR0, X86_CR2, X86_CR3, X86_CR4, X86_CR8,
	"cr0", "cr2", "cr3", "cr4", "cr8",

	// Debug Registers
	// X86_DR0, X86_DR1, X86_DR2, X86_DR3, X86_DR4, X86_DR5, X86_DR6, X86_DR7,
	"dr0", "dr1", "dr2", "dr3", "dr4", "dr5", "dr6", "dr7",

	// Descriptor Tables
	// X86_IDTR, X86_GDTR, X86_LDTR, X86_TR
	"idtr", "gdtr", "ldtr", "tr"
};


static __inline uint8_t ComputeAddressSize(uint64_t i)
{
	if ((i & 0xffffffff00000000) != 0)
		return 64;

	if ((i & 0xffff0000) != 0)
		return 32;

	if ((i & 0xff00) != 0)
		return 16;

	return 8;
}


static size_t PrintAddress(char* const dest, const size_t maxLen, const uint64_t addr)
{
	const uint8_t bit = ComputeAddressSize(addr);
	if (bit > 32)
		return snprintf(dest, maxLen, "%.16llx", (long long unsigned int)addr);
	else if (bit > 16)
		return snprintf(dest, maxLen, "%.08lx", (long unsigned int)addr);
	else if (bit > 8)
		return snprintf(dest, maxLen, "%.04x", (uint16_t)addr);
	else
		return snprintf(dest, maxLen, "%.02x", (uint8_t)addr);
}


static size_t PrintImmediate(char* const dest, size_t const maxLen, const uint64_t immediate, const uint8_t size)
{
	switch (size)
	{
	case 1:
		return snprintf(dest, maxLen, "%hhx", (uint8_t)immediate);
	case 2:
		return snprintf(dest, maxLen, "%hx", (uint16_t)immediate);
	case 4:
		return snprintf(dest, maxLen, "%x", (uint32_t)immediate);
	case 8:
		return snprintf(dest, maxLen, "%llx", (long long unsigned int)immediate);
	default:
		return 0;
	}
}


static size_t PrintRegister(char* const dest, size_t const maxLen, const X86OperandType reg)
{
	return snprintf(dest, maxLen, "%s", g_operandTypeNames[reg]);
}


static size_t PrintMemoryOperand(char* const dest, size_t const maxLen, const X86Operand* const operand)
{
	size_t remaining;
	size_t len;
	char* dstPtr;

	dstPtr = dest;
	remaining = maxLen;

	len = snprintf(dstPtr, remaining, "[");
	remaining -= len;
	dstPtr += len;

	if (operand->components[0] != X86_NONE)
	{
		len = PrintRegister(dstPtr, remaining, operand->components[0]);
		dstPtr += len;
		remaining -= len;
	}

	if (operand->components[1] != X86_NONE)
	{
		if (operand->components[0] != X86_NONE)
		{
			len = snprintf(dstPtr, remaining, "+");
			dstPtr += len;
			remaining -= len;
		}
		len = PrintRegister(dstPtr, remaining, operand->components[1]);
		dstPtr += len;
		remaining -= len;
		if (operand->scale > 1)
		{
			len = snprintf(dstPtr, remaining, "*%d", operand->scale);
			dstPtr += len;
			remaining -= len;
		}
	}

	if (((operand->components[0] != X86_NONE) || (operand->components[1] != X86_NONE)) && operand->immediate)
	{
		len = snprintf(dstPtr, remaining, "+");
		dstPtr += len;
		remaining -= len;
	}

	if (operand->immediate || ((operand->components[0] == X86_NONE) && (operand->components[1] == X86_NONE)))
	{
		len = PrintAddress(dstPtr, remaining, operand->immediate);
		dstPtr += len;
		remaining -= len;
	}

	remaining -= snprintf(dstPtr, remaining, "]");

	return (maxLen - remaining);
}


static size_t PrintOperands(char* const dest, size_t const maxLen, const X86Operand* const operands)
{
	size_t remaining;
	uint8_t i;
	char* dstPtr;

	dstPtr = dest;
	remaining = maxLen;
	for (i = 0; i < 4; i++)
	{
		size_t len;
		if (operands[i].operandType == X86_NONE)
			break;
		if (i != 0)
		{
			len = snprintf(dstPtr, remaining, ", ");
			dstPtr += len;
			remaining -= len;
		}
		switch (operands[i].operandType)
		{
		case X86_NONE:
			// Handled above. Should never get here.
			len = 0;
			break;
		case X86_MEM:
			len = PrintMemoryOperand(dstPtr, remaining, &operands[i]);
			break;
		case X86_IMMEDIATE:
			len = PrintImmediate(dstPtr, remaining, operands[i].immediate, operands[i].size);
			break;
		default:
			len = PrintRegister(dstPtr, remaining, operands[i].operandType);
			break;
		}

		dstPtr += len;
		remaining -= len;
	}

	return (maxLen - remaining);
}


static size_t PrintInstruction(char* const dest, const size_t maxLen, const X86Instruction* const instr)
{
	const char* mnemonic = g_x86Mnemonics[instr->op];
	char* dstPtr = dest;
	size_t remaining = maxLen;
	size_t len;

	if (instr->op == X86_INVALID)
		mnemonic = "??";

	if (instr->flags.lock)
	{
		len = snprintf(dstPtr, remaining, "lock ");
		dstPtr += len;
		remaining -= len;
	}
	if (instr->flags.repe)
	{
		len = snprintf(dstPtr, remaining, "rep ");
		dstPtr += len;
		remaining -= len;
	}
	if (instr->flags.repne)
	{
		len = snprintf(dstPtr, remaining, "repne ");
		dstPtr += len;
		remaining -= len;
	}

	len = snprintf(dstPtr, remaining, "%s", mnemonic);
	remaining -= len;

	return (maxLen - remaining);
}


static size_t PrintBytes(char* const dest, size_t const maxLen, const uint8_t* const bytes, const size_t instrLen)
{
	size_t i;
	size_t remaining;
	char* dstPtr;
	size_t limit;

	dstPtr = dest;
	remaining = maxLen;
	limit = ((maxLen >> 1) > instrLen) ? instrLen : (maxLen >> 1);
	for (i = 0; i < limit; i++)
	{
		size_t len = snprintf(dstPtr, remaining, "%.02x", bytes[i]);
		remaining -= len;
		dstPtr += len;
	}

	// Pad with spaces so we get a constant field width
	limit = ((maxLen >> 1) > (15 - instrLen)) ? (15 - instrLen) : (maxLen >> 1);
	for (i = 0; i < limit; i++)
	{
		size_t len = snprintf(dstPtr, remaining, "  ");
		remaining -= len;
		dstPtr += len;
	}

	return (maxLen - remaining);
}


size_t GetInstructionString(char* const dest, const size_t maxLen, const char* format, const X86Instruction* const instr)
{
	const char* src;
	char* dstPtr = dest;
	bool delimitter;
	size_t remaining = maxLen - 1;

	if (maxLen == 0)
		return 0;

	delimitter = false;
	for (src = format; *src; src++)
	{
		if (remaining == 0)
			break;

		if (!delimitter)
		{
			if (*src != '%')
			{
				*dstPtr++ = *src;
				remaining--;
				continue;
			}
			else
			{
				delimitter = true;
				continue;
			}
		}
		else
		{
			size_t len;

			switch (*src)
			{
			case 'i':
				len = PrintInstruction(dstPtr, remaining, instr);
				break;
			case 'o':
				if (instr->op == X86_INVALID)
				{
					len = 0;
					break;
				}
				len = PrintOperands(dstPtr, remaining, instr->operands);
				break;
			case 'b':
				len = PrintBytes(dstPtr, remaining, instr->bytes, instr->length);
				break;
			case 'a':
				len = PrintAddress(dstPtr, remaining, instr->rip);
				break;
			case 's':
				// len = PrintSymbol();
				len = 0;
				break;
			default:
				len = 0;
				break;
			}

			dstPtr += len;
			remaining -= len;
			delimitter = false;
		}
	}

	*dstPtr++ = 0;
	return dstPtr - dest;
}


bool Disassemble16(uint16_t ip, InstructionFetchCallback fetch, void* ctxt, X86Instruction* instr)
{
	X86DecoderState state;

	memset(&state, 0, sizeof(X86DecoderState));
	state.fetch = fetch;
	state.ctxt = ctxt;
	state.instr = instr;
	state.mode = X86_16BIT;
	state.addrMode = X86_16BIT;
	state.operandMode = X86_16BIT;

	memset(state.instr, 0, sizeof(X86Instruction));
	state.instr->rip = ip;

	if (!DecodePrimaryOpcodeTable(&state))
		return false;

	return true;
}


bool Disassemble32(uint32_t eip, InstructionFetchCallback fetch, void* ctxt, X86Instruction* instr)
{
	X86DecoderState state;

	memset(&state, 0, sizeof(X86DecoderState));
	state.fetch = fetch;
	state.ctxt = ctxt;
	state.instr = instr;
	state.mode = X86_32BIT;
	state.addrMode = X86_32BIT;
	state.operandMode = X86_32BIT;

	memset(state.instr, 0, sizeof(X86Instruction));
	state.instr->rip = eip;

	if (!DecodePrimaryOpcodeTable(&state))
		return false;

	return true;
}


bool Disassemble64(uint64_t rip, InstructionFetchCallback fetch, void* ctxt, X86Instruction* instr)
{
	X86DecoderState state;

	memset(&state, 0, sizeof(X86DecoderState));
	state.fetch = fetch;
	state.ctxt = ctxt;
	state.instr = instr;
	state.mode = X86_64BIT;
	state.addrMode = X86_64BIT;
	state.operandMode = X86_32BIT;

	memset(state.instr, 0, sizeof(X86Instruction));
	state.instr->rip = rip;

	if (!DecodePrimaryOpcodeTable(&state))
		return false;

	return true;
}
