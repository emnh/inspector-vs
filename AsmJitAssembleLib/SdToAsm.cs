using System;
using System.Diagnostics;
using AsmJit.AssemblerContext;
using SharpDisasm;
using SharpDisasm.Udis86;

namespace AsmJitAssembleLib {

    public class SdToAsm {

        public static UlongOrLong GetDisplacement(Instruction instruction, SharpDisasm.Operand op) {
            // mostly copied from ud_syn_print_mem_disp
            var retVal = new UlongOrLong();
            if (op.Offset == 0) {
                retVal.Value = 0;
                return retVal;
            }
            if (op.Base == ud_type.UD_NONE && op.Index == ud_type.UD_NONE) {
                ulong v;
                Debug.Assert(op.Scale == 0 && op.Offset != 8);
                /* unsigned mem-offset */
                switch (op.Offset) {
                    case 16: v = op.LvalUWord; break;
                    case 32: v = op.LvalUDWord; break;
                    case 64: v = op.LvalUQWord; break;
                    default: throw new AssembleException("invalid offset: {op.Offset}");
                }
                retVal.Unsigned = true;
                retVal.Value = v;
            } else {
                long v;
                Debug.Assert(op.Offset != 64);
                switch (op.Offset) {
                    case 8: v = op.LvalSByte; break;
                    case 16: v = op.LvalSWord; break;
                    case 32: v = op.LvalSDWord; break;
                    default: throw new AssembleException($"invalid offset: {op.Offset}");
                }
                retVal.Unsigned = false;
                retVal.Value = (ulong)v;
            }
            return retVal;
        }

        public static MaybeRegister SdToAsmJit(CodeContext context, ud_type operandReg) {
            switch (operandReg) {
                case ud_type.UD_R_RIP:
                    return new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.RipRegister,
                        Register = CodeContext.Rip
                    };
                case ud_type.UD_R_ST0:
                    return new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.FpRegister,
                        Register = context.Fp0
                    };
                case ud_type.UD_R_ST1:
                    return new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.FpRegister,
                        Register = context.Fp1
                    };
                case ud_type.UD_R_ST2:
                    return new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.FpRegister,
                        Register = context.Fp2
                    };
                case ud_type.UD_R_ST3:
                    return new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.FpRegister,
                        Register = context.Fp3
                    };
                case ud_type.UD_R_ST4:
                    return new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.FpRegister,
                        Register = context.Fp4
                    };
                case ud_type.UD_R_ST5:
                    return new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.FpRegister,
                        Register = context.Fp5
                    };
                case ud_type.UD_R_ST6:
                    return new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.FpRegister,
                        Register = context.Fp6
                    };
                case ud_type.UD_R_ST7:
                    return new MaybeRegister() {
                        Present = true,
                        Type = RegisterType.FpRegister,
                        Register = context.Fp7
                    };
            }
            return SharpDisasmRegisterToAsmJit.SharpDisasmRegisterToAsmJitRegister(context, operandReg);
        }
    }
}
