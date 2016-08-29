
// This file was auto-generated from SharpDisasmRegisterToASmJit.tt



using AsmJit.AssemblerContext;
using AsmJit.Common.Operands;
using SharpDisasm.Udis86;
using Program;

namespace Test {
	public class SharpDisasmRegisterToAsmJitTT {
		public static MaybeRegister SharpDisasmRegisterToAsmJitRegister(CodeContext context, ud_type type) {
			var retVal = new MaybeRegister();
			 
				switch (type) {
					case ud_type.UD_R_AL:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Al
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_CL:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Cl
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_DL:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Dl
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_BL:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Bl
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_AH:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Ah
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_CH:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Ch
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_DH:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Dh
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_BH:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Bh
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_SPL:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Spl
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_BPL:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Bpl
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_SIL:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Sil
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_DIL:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Dil
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R8B:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R8B
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R9B:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R9B
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R10B:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R10B
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R11B:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R11B
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R12B:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R12B
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R13B:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R13B
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R14B:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R14B
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R15B:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R15B
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_AX:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Ax
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_CX:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Cx
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_DX:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Dx
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_BX:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Bx
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_SP:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Sp
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_BP:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Bp
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_SI:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Si
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_DI:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Di
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R8W:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R8W
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R9W:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R9W
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R10W:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R10W
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R11W:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R11W
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R12W:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R12W
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R13W:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R13W
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R14W:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R14W
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R15W:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R15W
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_EAX:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Eax
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_ECX:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Ecx
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_EDX:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Edx
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_EBX:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Ebx
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_ESP:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Esp
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_EBP:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Ebp
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_ESI:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Esi
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_EDI:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Edi
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R8D:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R8D
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R9D:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R9D
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R10D:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R10D
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R11D:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R11D
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R12D:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R12D
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R13D:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R13D
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R14D:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R14D
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R15D:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R15D
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_RAX:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Rax
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_RCX:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Rcx
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_RDX:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Rdx
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_RBX:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Rbx
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_RSP:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Rsp
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_RBP:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Rbp
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_RSI:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Rsi
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_RDI:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.Rdi
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R8:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R8
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R9:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R9
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R10:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R10
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R11:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R11
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R12:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R12
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R13:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R13
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R14:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R14
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_R15:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.GpRegister,
							Register = context.R15
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_ES:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.SegRegister,
							Register = context.Es
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_CS:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.SegRegister,
							Register = context.Cs
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_SS:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.SegRegister,
							Register = context.Ss
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_DS:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.SegRegister,
							Register = context.Ds
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_FS:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.SegRegister,
							Register = context.Fs
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_GS:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.SegRegister,
							Register = context.Gs
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_MM0:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.MmRegister,
							Register = context.Mm0
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_MM1:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.MmRegister,
							Register = context.Mm1
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_MM2:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.MmRegister,
							Register = context.Mm2
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_MM3:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.MmRegister,
							Register = context.Mm3
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_MM4:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.MmRegister,
							Register = context.Mm4
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_MM5:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.MmRegister,
							Register = context.Mm5
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_MM6:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.MmRegister,
							Register = context.Mm6
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_MM7:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.MmRegister,
							Register = context.Mm7
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_XMM0:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.XmmRegister,
							Register = context.Xmm0
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_XMM1:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.XmmRegister,
							Register = context.Xmm1
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_XMM2:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.XmmRegister,
							Register = context.Xmm2
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_XMM3:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.XmmRegister,
							Register = context.Xmm3
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_XMM4:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.XmmRegister,
							Register = context.Xmm4
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_XMM5:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.XmmRegister,
							Register = context.Xmm5
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_XMM6:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.XmmRegister,
							Register = context.Xmm6
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_XMM7:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.XmmRegister,
							Register = context.Xmm7
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_XMM8:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.XmmRegister,
							Register = context.Xmm8
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_XMM9:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.XmmRegister,
							Register = context.Xmm9
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_XMM10:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.XmmRegister,
							Register = context.Xmm10
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_XMM11:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.XmmRegister,
							Register = context.Xmm11
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_XMM12:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.XmmRegister,
							Register = context.Xmm12
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_XMM13:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.XmmRegister,
							Register = context.Xmm13
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_XMM14:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.XmmRegister,
							Register = context.Xmm14
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_XMM15:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.XmmRegister,
							Register = context.Xmm15
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_YMM0:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.YmmRegister,
							Register = context.Ymm0
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_YMM1:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.YmmRegister,
							Register = context.Ymm1
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_YMM2:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.YmmRegister,
							Register = context.Ymm2
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_YMM3:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.YmmRegister,
							Register = context.Ymm3
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_YMM4:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.YmmRegister,
							Register = context.Ymm4
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_YMM5:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.YmmRegister,
							Register = context.Ymm5
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_YMM6:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.YmmRegister,
							Register = context.Ymm6
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_YMM7:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.YmmRegister,
							Register = context.Ymm7
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_YMM8:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.YmmRegister,
							Register = context.Ymm8
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_YMM9:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.YmmRegister,
							Register = context.Ymm9
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_YMM10:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.YmmRegister,
							Register = context.Ymm10
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_YMM11:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.YmmRegister,
							Register = context.Ymm11
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_YMM12:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.YmmRegister,
							Register = context.Ymm12
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_YMM13:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.YmmRegister,
							Register = context.Ymm13
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_YMM14:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.YmmRegister,
							Register = context.Ymm14
						};
						break;
				}	
				 
				switch (type) {
					case ud_type.UD_R_YMM15:
						retVal = new MaybeRegister() {
							Present = true,
							Type = RegisterType.YmmRegister,
							Register = context.Ymm15
						};
						break;
				}	
				            return retVal;
        }
	}
}
