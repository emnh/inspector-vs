﻿
// This file was auto-generated from SharpDisasmRegisterToASmJit.tt

using AsmJit.AssemblerContext;
using SharpDisasm.Udis86;

namespace AsmJitAssembleLib {
    public class SharpDisasmRegisterToAsmJit {
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



                case ud_type.UD_R_CL:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Cl
                    };
                    break;



                case ud_type.UD_R_DL:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Dl
                    };
                    break;



                case ud_type.UD_R_BL:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Bl
                    };
                    break;



                case ud_type.UD_R_AH:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Ah
                    };
                    break;



                case ud_type.UD_R_CH:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Ch
                    };
                    break;



                case ud_type.UD_R_DH:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Dh
                    };
                    break;



                case ud_type.UD_R_BH:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Bh
                    };
                    break;



                case ud_type.UD_R_SPL:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Spl
                    };
                    break;



                case ud_type.UD_R_BPL:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Bpl
                    };
                    break;



                case ud_type.UD_R_SIL:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Sil
                    };
                    break;



                case ud_type.UD_R_DIL:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Dil
                    };
                    break;



                case ud_type.UD_R_R8B:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R8B
                    };
                    break;



                case ud_type.UD_R_R9B:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R9B
                    };
                    break;



                case ud_type.UD_R_R10B:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R10B
                    };
                    break;



                case ud_type.UD_R_R11B:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R11B
                    };
                    break;



                case ud_type.UD_R_R12B:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R12B
                    };
                    break;



                case ud_type.UD_R_R13B:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R13B
                    };
                    break;



                case ud_type.UD_R_R14B:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R14B
                    };
                    break;



                case ud_type.UD_R_R15B:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R15B
                    };
                    break;



                case ud_type.UD_R_AX:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Ax
                    };
                    break;



                case ud_type.UD_R_CX:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Cx
                    };
                    break;



                case ud_type.UD_R_DX:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Dx
                    };
                    break;



                case ud_type.UD_R_BX:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Bx
                    };
                    break;



                case ud_type.UD_R_SP:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Sp
                    };
                    break;



                case ud_type.UD_R_BP:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Bp
                    };
                    break;



                case ud_type.UD_R_SI:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Si
                    };
                    break;



                case ud_type.UD_R_DI:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Di
                    };
                    break;



                case ud_type.UD_R_R8W:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R8W
                    };
                    break;



                case ud_type.UD_R_R9W:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R9W
                    };
                    break;



                case ud_type.UD_R_R10W:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R10W
                    };
                    break;



                case ud_type.UD_R_R11W:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R11W
                    };
                    break;



                case ud_type.UD_R_R12W:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R12W
                    };
                    break;



                case ud_type.UD_R_R13W:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R13W
                    };
                    break;



                case ud_type.UD_R_R14W:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R14W
                    };
                    break;



                case ud_type.UD_R_R15W:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R15W
                    };
                    break;



                case ud_type.UD_R_EAX:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Eax
                    };
                    break;



                case ud_type.UD_R_ECX:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Ecx
                    };
                    break;



                case ud_type.UD_R_EDX:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Edx
                    };
                    break;



                case ud_type.UD_R_EBX:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Ebx
                    };
                    break;



                case ud_type.UD_R_ESP:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Esp
                    };
                    break;



                case ud_type.UD_R_EBP:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Ebp
                    };
                    break;



                case ud_type.UD_R_ESI:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Esi
                    };
                    break;



                case ud_type.UD_R_EDI:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Edi
                    };
                    break;



                case ud_type.UD_R_R8D:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R8D
                    };
                    break;



                case ud_type.UD_R_R9D:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R9D
                    };
                    break;



                case ud_type.UD_R_R10D:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R10D
                    };
                    break;



                case ud_type.UD_R_R11D:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R11D
                    };
                    break;



                case ud_type.UD_R_R12D:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R12D
                    };
                    break;



                case ud_type.UD_R_R13D:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R13D
                    };
                    break;



                case ud_type.UD_R_R14D:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R14D
                    };
                    break;



                case ud_type.UD_R_R15D:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R15D
                    };
                    break;



                case ud_type.UD_R_RAX:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Rax
                    };
                    break;



                case ud_type.UD_R_RCX:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Rcx
                    };
                    break;



                case ud_type.UD_R_RDX:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Rdx
                    };
                    break;



                case ud_type.UD_R_RBX:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Rbx
                    };
                    break;



                case ud_type.UD_R_RSP:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Rsp
                    };
                    break;



                case ud_type.UD_R_RBP:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Rbp
                    };
                    break;



                case ud_type.UD_R_RSI:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Rsi
                    };
                    break;



                case ud_type.UD_R_RDI:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.Rdi
                    };
                    break;



                case ud_type.UD_R_R8:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R8
                    };
                    break;



                case ud_type.UD_R_R9:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R9
                    };
                    break;



                case ud_type.UD_R_R10:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R10
                    };
                    break;



                case ud_type.UD_R_R11:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R11
                    };
                    break;



                case ud_type.UD_R_R12:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R12
                    };
                    break;



                case ud_type.UD_R_R13:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R13
                    };
                    break;



                case ud_type.UD_R_R14:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R14
                    };
                    break;



                case ud_type.UD_R_R15:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.GpRegister,
                        Register = context.R15
                    };
                    break;



                case ud_type.UD_R_ES:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.SegRegister,
                        Register = context.Es
                    };
                    break;



                case ud_type.UD_R_CS:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.SegRegister,
                        Register = context.Cs
                    };
                    break;



                case ud_type.UD_R_SS:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.SegRegister,
                        Register = context.Ss
                    };
                    break;



                case ud_type.UD_R_DS:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.SegRegister,
                        Register = context.Ds
                    };
                    break;



                case ud_type.UD_R_FS:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.SegRegister,
                        Register = context.Fs
                    };
                    break;



                case ud_type.UD_R_GS:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.SegRegister,
                        Register = context.Gs
                    };
                    break;



                case ud_type.UD_R_MM0:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.MmRegister,
                        Register = context.Mm0
                    };
                    break;



                case ud_type.UD_R_MM1:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.MmRegister,
                        Register = context.Mm1
                    };
                    break;



                case ud_type.UD_R_MM2:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.MmRegister,
                        Register = context.Mm2
                    };
                    break;



                case ud_type.UD_R_MM3:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.MmRegister,
                        Register = context.Mm3
                    };
                    break;



                case ud_type.UD_R_MM4:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.MmRegister,
                        Register = context.Mm4
                    };
                    break;



                case ud_type.UD_R_MM5:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.MmRegister,
                        Register = context.Mm5
                    };
                    break;



                case ud_type.UD_R_MM6:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.MmRegister,
                        Register = context.Mm6
                    };
                    break;



                case ud_type.UD_R_MM7:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.MmRegister,
                        Register = context.Mm7
                    };
                    break;



                case ud_type.UD_R_XMM0:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.XmmRegister,
                        Register = context.Xmm0
                    };
                    break;



                case ud_type.UD_R_XMM1:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.XmmRegister,
                        Register = context.Xmm1
                    };
                    break;



                case ud_type.UD_R_XMM2:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.XmmRegister,
                        Register = context.Xmm2
                    };
                    break;



                case ud_type.UD_R_XMM3:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.XmmRegister,
                        Register = context.Xmm3
                    };
                    break;



                case ud_type.UD_R_XMM4:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.XmmRegister,
                        Register = context.Xmm4
                    };
                    break;



                case ud_type.UD_R_XMM5:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.XmmRegister,
                        Register = context.Xmm5
                    };
                    break;



                case ud_type.UD_R_XMM6:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.XmmRegister,
                        Register = context.Xmm6
                    };
                    break;



                case ud_type.UD_R_XMM7:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.XmmRegister,
                        Register = context.Xmm7
                    };
                    break;



                case ud_type.UD_R_XMM8:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.XmmRegister,
                        Register = context.Xmm8
                    };
                    break;



                case ud_type.UD_R_XMM9:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.XmmRegister,
                        Register = context.Xmm9
                    };
                    break;



                case ud_type.UD_R_XMM10:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.XmmRegister,
                        Register = context.Xmm10
                    };
                    break;



                case ud_type.UD_R_XMM11:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.XmmRegister,
                        Register = context.Xmm11
                    };
                    break;



                case ud_type.UD_R_XMM12:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.XmmRegister,
                        Register = context.Xmm12
                    };
                    break;



                case ud_type.UD_R_XMM13:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.XmmRegister,
                        Register = context.Xmm13
                    };
                    break;



                case ud_type.UD_R_XMM14:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.XmmRegister,
                        Register = context.Xmm14
                    };
                    break;



                case ud_type.UD_R_XMM15:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.XmmRegister,
                        Register = context.Xmm15
                    };
                    break;



                case ud_type.UD_R_YMM0:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.YmmRegister,
                        Register = context.Ymm0
                    };
                    break;



                case ud_type.UD_R_YMM1:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.YmmRegister,
                        Register = context.Ymm1
                    };
                    break;



                case ud_type.UD_R_YMM2:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.YmmRegister,
                        Register = context.Ymm2
                    };
                    break;



                case ud_type.UD_R_YMM3:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.YmmRegister,
                        Register = context.Ymm3
                    };
                    break;



                case ud_type.UD_R_YMM4:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.YmmRegister,
                        Register = context.Ymm4
                    };
                    break;



                case ud_type.UD_R_YMM5:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.YmmRegister,
                        Register = context.Ymm5
                    };
                    break;



                case ud_type.UD_R_YMM6:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.YmmRegister,
                        Register = context.Ymm6
                    };
                    break;



                case ud_type.UD_R_YMM7:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.YmmRegister,
                        Register = context.Ymm7
                    };
                    break;



                case ud_type.UD_R_YMM8:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.YmmRegister,
                        Register = context.Ymm8
                    };
                    break;



                case ud_type.UD_R_YMM9:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.YmmRegister,
                        Register = context.Ymm9
                    };
                    break;



                case ud_type.UD_R_YMM10:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.YmmRegister,
                        Register = context.Ymm10
                    };
                    break;



                case ud_type.UD_R_YMM11:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.YmmRegister,
                        Register = context.Ymm11
                    };
                    break;



                case ud_type.UD_R_YMM12:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.YmmRegister,
                        Register = context.Ymm12
                    };
                    break;



                case ud_type.UD_R_YMM13:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.YmmRegister,
                        Register = context.Ymm13
                    };
                    break;



                case ud_type.UD_R_YMM14:
                    retVal = new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.YmmRegister,
                        Register = context.Ymm14
                    };
                    break;



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
