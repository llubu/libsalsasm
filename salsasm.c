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

// NOTE: These must be maintained in the same order as X86Operations enum!
static const char* const X86Mnemonics[] =
{
	"invalid",
	"aaa", "aad", "aam", "aas", "adc", "add", "addpd",
	"addps", "addsd", "addss", "addsubpd", "addsubps", "adx",
	"amx", "and", "andnpd", "andnps", "andpd", "andps", "arpl",
	"blendpd", "blendps", "blendvpd", "blendvps", "bound", "bsf",
	"bsr", "bswap", "bt", "btc", "btr", "bts", "calln", "callf",
	"cbw", "cwde", "cdqe", "clc", "cld", "clflush", "clgi", "cli",
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
	"cvttps2d", "cwd", "cdq", "cqo", "daa", "dec", "div", "divpd",
	"divps", "divsd", "divss", "dppd", "emms", "extractps", "extrq",
	"f2xm1", "fabs", "fadd", "faddp", "fbld", "fbstp", "fchs", "fclex",
	"fcmovb", "fcmovbe", "fcmove", "fcmovnb", "fcmovnbe", "fcmovne", "fcmovnu",
	"fcmovu", "fcom", "fcom2", "fcomi", "fcomip", "fcomp3", "fcomp5",
	"fcompp", "fdecstp", "fdiv", "fdivp", "fdivr", "fdivrp", "femms", "ffree",
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
	"in", "inc", "ins", "insb", "insw", "insd", "insertps", "int", "int1",
	"icebp", "into", "invd", "invept", "invlpg", "invlpga", "invvpid", "iret", "iretd",
	"iretq", "jb", "jnae", "jc", "jbe", "jna", "jcxz", "jecxz", "jrcxz",
	"jl", "jnge", "jle", "jng", "jmp", "jmpf", "jnc", "jnb", "jae",
	"ja", "jnbe", "jnl", "jge", "jnle", "jg", "jno", "jpo", "jnp",
	"jns", "jnz", "jne", "jo", "jp", "jpe", "js", "jz", "je", "lahf",
	"lar", "lddqu", "ldmxcsr", "lds", "lea", "leave", "les", "lfence",
	"lfs", "lgdt", "lgs", "lidt", "lldt", "lmsw", "lods", "lodsb",
	"lodsw", "lodsd", "lodsq", "loop", "loopnz", "loopne", "loopz", "loope",
	"lsl", "lss", "ltr", "maskmovdqu", "maskmovq", "maxpd", "maxps",
	"maxsd", "maxss", "mfence", "minpd", "minps", "minsd", "minss",
	"monitor", "mov", "movapd", "movaps", "movbe", "movd", "movq", "movddup",
	"movdq2q", "movdqa", "movdqu", "movhlps", "movhpd", "movhps", "movlhps",
	"movlpd", "movlps", "movmskpd", "movmskps", "movntdq", "movntdqa", "movnti",
	"movntpd", "movntps", "movntq", "movntss", "movntsd", "movq2dq", "movs", "movsb", "movsw", "movsq",
	"movsd""," "movshdup", "movsldup", "movss", "movsx", "movsxd", "movupd", "movups", "movzx",
	"mpsadbw", "mul", "mulpd", "mulps", "mulsd", "mulss", "mwait", "neg",
	"nop", "not", "or", "orpd", "orps", "out", "outs", "outsb", "outsw",
	"outsd", "pabsb", "pabsd", "pabsw", "packssdw", "packsswb", "packusdw",
	"packuswb", "paddb", "paddd", "paddq", "paddsb", "paddsw", "paddusb",
	"paddusw", "paddw", "palignr", "pand", "pandn", "pause", "pavgb",
	"pavgw", "pblendvb", "pblendw", "pcmpeqb", "pcmpeqd", "pcmpeqq",
	"pcmpeqw", "pcmpestri", "pcmpestrm", "pcmpgtb", "pcmpgtd", "pcmpgtq",
	"pcmpgtw", "pcmpistri", "pcmpistrm", "pextrb", "pextrd", "pextrq",
	"pextrw", "pfnacc", "pfpnacc", "pfcmpge", "pfmin", "pfrcp", "pfrsqrt", "pfmax",
	"pfsqrt", "pfsub", "pfadd", "pfcmpgt", "pfrcpit1", "pfrsqit1", "pfsubr", "pfacc",
	"pfcmpeq", "pfmul", "pfrcpit2", "pmulhrw", "pswapd", "pavgusb", 
	"phaddd", "phaddsw", "phaddw", "phminposuw", "phsubd", "phsubsw",
	"phsubw", "pinsrb", "pinsrd", "pinsrq", "pinsrw", "pmaddubsw", "pmaddwd",
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
	"psubusb", "psubusw", "psubw", "pi2fw", "pi2fd", "pf2iw", "pf2id",
	"ptest", "punpckhbw", "punpckhdq",
	"punpckhqdq", "punpckhwd", "punpcklbw", "punpckldq", "punpcklqdq",
	"punpcklwd", "push", "pusha", "pushad", "pushf", "pushfq", "pushfd",
	"pxor", "rcl", "rcpps", "rcpss", "rcr", "rdmsr", "rdpmc", "rdtsc", "rdtscp",
	"retf", "retn", "rol", "ror", "roundpd", "roundps", "roundsd",
	"roundss", "rsm", "rsqrtps", "rsqrtss", "sahf", "sal", "shl",
	"salc", "setalc", "sar", "sbb", "scas", "scasb", "scasw",
	"scasd", "scasq", "setb", "setnae", "setc", "setbe", "setna",
	"setl", "setnge", "setle", "setng", "setnb", "setae", "setnc",
	"setnbe", "seta", "setnl", "setge", "setnle", "setg", "setno",
	"setnp", "setpo", "setns", "setnz", "setne", "seto", "setp",
	"setpe", "sets", "setz", "sete", "sfence", "sgdt", "skinit", "sldt", "shld", "shr",
	"shrd", "shufpd", "shufps", "sidt", "smsw", "sqrtpd", "sqrtps",
	"sqrtsd", "sqrtss", "stc", "std", "stgi", "sti", "stmxcsr", "stos",
	"stosb", "stosw", "stosd", "stosq", "str", "sub", "subpd",
	"subps", "subsd", "subss", "swapgs", "syscall", "sysenter", "sysexit",
	"sysret", "test", "ucomisd", "ucomiss", "ud", "ud1", "ud2", "unpckhpd",
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
	"vxorpd", "vaddps",  "vaddss", "vandps", "vandnps", "vcmppS",
	"vcmpss", "vcomiss", "vcvtsi2ss", "vcvtss2si", "vcvttss2si",
	"vdivps", "vldmxcsr", "vmaxps", "vmaxss", "vminps", "vminss",
	"vmovaps", "vmovhps", "vmovlhps", "vmovlps", "vmovmskps",
	"vmovntps", "vmovss", "vmovups", "vmulps", "vmulss", "vorps",
	"vrcpps", "vrcpss", "vrsqrtps", "vrsqrtss", "vsqrtps", "vsqrtss",
	"vstmxcsr", "vsubps", "vsubss", "vucomiss", "vxorps",
	"vbroadcast", "vextractf128", "vinsertf128", "vpermilpd", "vpermilps",
	"vperm2f128", "vtestpd", "vtestps", "verr", "verw", "vmcall",
	"vmclear", "vmlaunch", "vmptrld", "vmptrst", "vmread", "vmfunc",
	"vmresume", "vmwrite", "vmxoff", "vmxon",
	"vmload", "vmmcall", "vmrun", "vmsave",
	"wbinvd", "wrmsr", "xadd", "xchg", "xgetbv", "xlat",
	"xlatb", "xor", "xorpd", "xorps", "xrstor", "xsave", "xsaveopt", "xsetbv"
};


bool Disassemble16(uint16_t ip, InstructionFetchCallback fetch, void* ctxt, X86Instruction* instr)
{
	X86DecoderState state = {0};

	state.fetch = fetch;
	state.ctxt = ctxt;
	state.instr = instr;
	state.valid = true;
	state.mode = X86_16BIT;
	state.operandMode = X86_16BIT;

	memset(state.instr, 0, sizeof(X86Instruction));
	state.instr->rip = SIGN_EXTEND64(ip, 2);

	if (!DecodePrimaryOpcodeTable(&state))
		return false;

	return true;
}


bool Disassemble32(uint32_t eip, InstructionFetchCallback fetch, void* ctxt, X86Instruction* instr)
{
	X86DecoderState state = {0};

	state.fetch = fetch;
	state.ctxt = ctxt;
	state.instr = instr;
	state.valid = true;
	state.mode = X86_32BIT;
	state.operandMode = X86_32BIT;
	state.instr->flags = X86_FLAG_NONE;

	memset(state.instr, 0, sizeof(X86Instruction));
	state.instr->rip = SIGN_EXTEND64(eip, 4);

	if (!DecodePrimaryOpcodeTable(&state))
		return false;

	return true;
}


bool Disassemble64(uint64_t rip, InstructionFetchCallback fetch, void* ctxt, X86Instruction* instr)
{
	return false;
}
