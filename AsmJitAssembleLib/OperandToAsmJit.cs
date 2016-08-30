using System;
using AsmJit.AssemblerContext;
using AsmJit.Common.Operands;
using SharpDisasm;
using SharpDisasm.Udis86;

namespace AsmJitAssembleLib {
    public class OperandToAsmJit {
        public static MaybeOption<Label> GetOperand(CodeContext context, Instruction instruction, SharpDisasm.Operand operand, Label overload) {
            // we never get labels from SharpDisasm
            return new MaybeOption<Label>();
        }
        public static MaybeOption<Immediate> GetOperand(CodeContext context, Instruction instruction, SharpDisasm.Operand operand, Immediate overload) {
            var op = operand;
            var insn = instruction;
            // mostly copied from ud_syn_print_imm
            if (operand.Type == ud_type.UD_OP_IMM) {
                ulong v;
                if (op.Opcode == ud_operand_code.OP_sI && op.Size != insn.opr_mode) {
                    if (op.Size == 8) {
                        v = (ulong) op.LvalSByte;
                    }
                    else {
                        if (op.Size != 32) {
                            throw new AssembleException("op.Size != 32");
                        }
                        v = (ulong) op.LvalSDWord;
                    }
                    if (insn.opr_mode < 64) {
                        v = v & ((1ul << insn.opr_mode) - 1ul);
                    }
                }
                else {
                    switch (op.Size) {
                        case 8:
                            v = op.LvalByte;
                            break;
                        case 16:
                            v = op.LvalUWord;
                            break;
                        case 32:
                            v = op.LvalUDWord;
                            break;
                        case 64:
                            v = op.LvalUQWord;
                            break;
                        default:
                            throw new AssembleException("invalid offset");
                    }
                }
                return new MaybeOption<Immediate>() {
                    Present = true,
                    Value = v
                };
            }
            if (operand.Type == ud_type.UD_OP_JIMM) {
                ulong immediate;
                ulong truncMask = 0xffffffffffffffff >> (64 - instruction.opr_mode);
                Console.WriteLine($"opr_mode: {instruction.opr_mode}");
                switch (operand.Size) {
                    case 8:
                        //immediate = (instruction.PC + (ulong)operand.LvalSByte) & truncMask;
                        immediate = (ulong)operand.LvalSByte & truncMask;
                        break;
                    case 16:
                        //immediate = (instruction.PC + (ulong)operand.LvalSWord) & truncMask;
                        immediate = (ulong)operand.LvalSWord & truncMask;
                        break;
                    case 32:
                        //immediate = (instruction.PC + (ulong)operand.LvalSDWord) & truncMask;
                        immediate = (ulong)operand.LvalSDWord & truncMask;
                        break;
                    default:
                        throw new AssembleException("invalid relative offset size.");
                }
                return new MaybeOption<Immediate>() {
                    Present = true,
                    Value = immediate
                };
            }
            return new MaybeOption<Immediate>();
        }
        public static MaybeOption<Memory> GetOperand(CodeContext context, Instruction instruction, SharpDisasm.Operand operand, Memory overload) {
            if (operand.Type == ud_type.UD_OP_MEM) {
                Memory memoryReference = null;
                GpRegister baseRegister = null;
                bool baseRipRegister = false;
                MaybeRegister maybeIndexRegister = null;
                if (operand.Base != ud_type.UD_NONE) {
                    var maybeBaseRegister = SdToAsm.SdToAsmJit(context, operand.Base);
                    if (!maybeBaseRegister.Present) {
                        throw new Exception($"could not map base register for: {instruction}");
                    }
                    if (maybeBaseRegister.Type != RegisterType.GpRegister) {
                        if (maybeBaseRegister.Type == RegisterType.RipRegister) {
                            baseRipRegister = true;
                        } else {
                            throw new Exception("could not map base register to GpRegister");
                        }
                    } else {
                        baseRegister = (GpRegister)maybeBaseRegister.Register;
                    }
                }

                if (operand.Index != ud_type.UD_NONE) {
                    maybeIndexRegister = SdToAsm.SdToAsmJit(context, operand.Index);
                    if (!maybeIndexRegister.Present) {
                        throw new Exception("could not map base register");
                    }
                }

                var displacement = SdToAsm.GetDisplacement(instruction, operand);
                var displacementIntPtr = (IntPtr)displacement.Value;
                var scale = 0;
                switch (operand.Scale) {
                    case 0:
                    case 1:
                        scale = 0;
                        break;
                    case 2:
                        scale = 1;
                        break;
                    case 4:
                        scale = 2;
                        break;
                    case 8:
                        scale = 3;
                        break;
                }

                if (baseRipRegister) {
                    // in our emulator we are going to keep our RIP in target (RAX)
                    if (maybeIndexRegister == null) {
                        switch (operand.Size) {
                            case 8:
                                memoryReference = Memory.Byte(CodeContext.Rip, (int)displacement.Value);
                                break;
                            case 16:
                                memoryReference = Memory.Word(CodeContext.Rip, (int)displacement.Value);
                                break;
                            case 32:
                                memoryReference = Memory.DWord(CodeContext.Rip, (int)displacement.Value);
                                break;
                            case 64:
                                memoryReference = Memory.QWord(CodeContext.Rip, (int)displacement.Value);
                                break;
                            case 80:
                                memoryReference = Memory.TWord(CodeContext.Rip, (int)displacement.Value);
                                break;
                            default:
                                throw new Exception("unsupported operand size");
                        }
                    } else {
                        throw new Exception("index register not supported when base register is RIP");
                    }
                } else {
                    if (baseRegister == null && maybeIndexRegister == null) {
                        switch (operand.Size) {
                            case 8:
                                memoryReference = Memory.ByteAbs(displacementIntPtr);
                                break;
                            case 16:
                                memoryReference = Memory.WordAbs(displacementIntPtr);
                                break;
                            case 32:
                                memoryReference = Memory.DWordAbs(displacementIntPtr);
                                break;
                            case 64:
                                memoryReference = Memory.QWordAbs(displacementIntPtr);
                                break;
                            default:
                                throw new Exception("unsupported operand size");
                        }
                    } else if (baseRegister != null && maybeIndexRegister == null) {
                        switch (operand.Size) {
                            case 8:
                                memoryReference = Memory.Byte(baseRegister, (int)displacement.Value);
                                break;
                            case 16:
                                memoryReference = Memory.Word(baseRegister, (int)displacement.Value);
                                break;
                            case 32:
                                memoryReference = Memory.DWord(baseRegister, (int)displacement.Value);
                                break;
                            case 64:
                                memoryReference = Memory.QWord(baseRegister, (int)displacement.Value);
                                break;
                            case 80:
                                memoryReference = Memory.TWord(baseRegister, (int)displacement.Value);
                                break;
                            default:
                                throw new Exception("unsupported operand size");
                        }
                    } else if (baseRegister == null) {
                        switch (operand.Size) {
                            case 8:
                                switch (maybeIndexRegister.Type) {
                                    case RegisterType.MmRegister:
                                        throw new Exception("mmregister not supported as index by asmjit");
                                    case RegisterType.SegRegister:
                                        throw new Exception("segregister not supported as index by asmjit");
                                    case RegisterType.GpRegister:
                                        memoryReference = Memory.ByteAbs(displacementIntPtr,
                                            (GpRegister)maybeIndexRegister.Register, scale);
                                        break;
                                    case RegisterType.XmmRegister:
                                        memoryReference = Memory.ByteAbs(displacementIntPtr,
                                            (XmmRegister)maybeIndexRegister.Register, scale);
                                        break;
                                    case RegisterType.YmmRegister:
                                        memoryReference = Memory.ByteAbs(displacementIntPtr,
                                            (YmmRegister)maybeIndexRegister.Register, scale);
                                        break;
                                }
                                break;
                            case 16:
                                switch (maybeIndexRegister.Type) {
                                    case RegisterType.MmRegister:
                                        throw new Exception("mmregister not supported as index by asmjit");
                                    case RegisterType.SegRegister:
                                        throw new Exception("segregister not supported as index by asmjit");
                                    case RegisterType.GpRegister:
                                        memoryReference = Memory.WordAbs(displacementIntPtr,
                                            (GpRegister)maybeIndexRegister.Register, scale);
                                        break;
                                    case RegisterType.XmmRegister:
                                        memoryReference = Memory.WordAbs(displacementIntPtr,
                                            (XmmRegister)maybeIndexRegister.Register, scale);
                                        break;
                                    case RegisterType.YmmRegister:
                                        memoryReference = Memory.WordAbs(displacementIntPtr,
                                            (YmmRegister)maybeIndexRegister.Register, scale);
                                        break;
                                }
                                break;
                            case 32:
                                switch (maybeIndexRegister.Type) {
                                    case RegisterType.MmRegister:
                                        throw new Exception("mmregister not supported as index by asmjit");
                                    case RegisterType.SegRegister:
                                        throw new Exception("segregister not supported as index by asmjit");
                                    case RegisterType.GpRegister:
                                        memoryReference = Memory.DWordAbs(displacementIntPtr,
                                            (GpRegister)maybeIndexRegister.Register, scale);
                                        break;
                                    case RegisterType.XmmRegister:
                                        memoryReference = Memory.DWordAbs(displacementIntPtr,
                                            (XmmRegister)maybeIndexRegister.Register, scale);
                                        break;
                                    case RegisterType.YmmRegister:
                                        memoryReference = Memory.DWordAbs(displacementIntPtr,
                                            (YmmRegister)maybeIndexRegister.Register, scale);
                                        break;
                                }
                                break;
                            case 64:
                                switch (maybeIndexRegister.Type) {
                                    case RegisterType.MmRegister:
                                        throw new Exception("mmregister not supported as index by asmjit");
                                    case RegisterType.SegRegister:
                                        throw new Exception("segregister not supported as index by asmjit");
                                    case RegisterType.GpRegister:
                                        memoryReference = Memory.QWordAbs(displacementIntPtr,
                                            (GpRegister)maybeIndexRegister.Register, scale);
                                        break;
                                    case RegisterType.XmmRegister:
                                        memoryReference = Memory.QWordAbs(displacementIntPtr,
                                            (XmmRegister)maybeIndexRegister.Register, scale);
                                        break;
                                    case RegisterType.YmmRegister:
                                        memoryReference = Memory.QWordAbs(displacementIntPtr,
                                            (YmmRegister)maybeIndexRegister.Register, scale);
                                        break;
                                }
                                break;
                            case 80:
                                throw new Exception("unsupported operand size 80");
                            default:
                                throw new Exception("unsupported operand size");
                        }
                    } else {
                        switch (operand.Size) {
                            case 8:
                                switch (maybeIndexRegister.Type) {
                                    case RegisterType.MmRegister:
                                        throw new Exception("mmregister not supported as index by asmjit");
                                    case RegisterType.SegRegister:
                                        throw new Exception("segregister not supported as index by asmjit");
                                    case RegisterType.GpRegister:
                                        memoryReference = Memory.Byte(baseRegister,
                                            (GpRegister)maybeIndexRegister.Register, scale, (int)displacement.Value);
                                        break;
                                    case RegisterType.XmmRegister:
                                        memoryReference = Memory.Byte(baseRegister,
                                            (XmmRegister)maybeIndexRegister.Register, scale, (int)displacement.Value);
                                        break;
                                    case RegisterType.YmmRegister:
                                        memoryReference = Memory.Byte(baseRegister,
                                            (YmmRegister)maybeIndexRegister.Register, scale, (int)displacement.Value);
                                        break;
                                }
                                break;
                            case 16:
                                switch (maybeIndexRegister.Type) {
                                    case RegisterType.MmRegister:
                                        throw new Exception("mmregister not supported as index by asmjit");
                                    case RegisterType.SegRegister:
                                        throw new Exception("segregister not supported as index by asmjit");
                                    case RegisterType.GpRegister:
                                        memoryReference = Memory.Word(baseRegister,
                                            (GpRegister)maybeIndexRegister.Register, scale, (int)displacement.Value);
                                        break;
                                    case RegisterType.XmmRegister:
                                        memoryReference = Memory.Word(baseRegister,
                                            (XmmRegister)maybeIndexRegister.Register, scale, (int)displacement.Value);
                                        break;
                                    case RegisterType.YmmRegister:
                                        memoryReference = Memory.Word(baseRegister,
                                            (YmmRegister)maybeIndexRegister.Register, scale, (int)displacement.Value);
                                        break;
                                }
                                break;
                            case 32:
                                switch (maybeIndexRegister.Type) {
                                    case RegisterType.MmRegister:
                                        throw new Exception("mmregister not supported as index by asmjit");
                                    case RegisterType.SegRegister:
                                        throw new Exception("segregister not supported as index by asmjit");
                                    case RegisterType.GpRegister:
                                        memoryReference = Memory.DWord(baseRegister,
                                            (GpRegister)maybeIndexRegister.Register, scale, (int)displacement.Value);
                                        break;
                                    case RegisterType.XmmRegister:
                                        memoryReference = Memory.DWord(baseRegister,
                                            (XmmRegister)maybeIndexRegister.Register, scale, (int)displacement.Value);
                                        break;
                                    case RegisterType.YmmRegister:
                                        memoryReference = Memory.DWord(baseRegister,
                                            (YmmRegister)maybeIndexRegister.Register, scale, (int)displacement.Value);
                                        break;
                                }
                                break;
                            case 64:
                                switch (maybeIndexRegister.Type) {
                                    case RegisterType.MmRegister:
                                        throw new Exception("mmregister not supported as index by asmjit");
                                    case RegisterType.SegRegister:
                                        throw new Exception("segregister not supported as index by asmjit");
                                    case RegisterType.GpRegister:
                                        memoryReference = Memory.QWord(baseRegister,
                                            (GpRegister)maybeIndexRegister.Register, scale, (int)displacement.Value);
                                        break;
                                    case RegisterType.XmmRegister:
                                        memoryReference = Memory.QWord(baseRegister,
                                            (XmmRegister)maybeIndexRegister.Register, scale, (int)displacement.Value);
                                        break;
                                    case RegisterType.YmmRegister:
                                        memoryReference = Memory.QWord(baseRegister,
                                            (YmmRegister)maybeIndexRegister.Register, scale, (int)displacement.Value);
                                        break;
                                }
                                break;
                            case 80:
                                throw new Exception("unsupported operand size 80");
                            default:
                                throw new Exception("unsupported operand size");
                        }
                    }
                }
                if (memoryReference == null) {
                    throw new AssembleException("could not parse SharpDisasm memory reference");
                }
                return new MaybeOption<Memory>() {
                    Present = true,
                    Value = memoryReference
                };
            }
            return new MaybeOption<Memory>();
        }
        public static MaybeOption<GpRegister> GetOperand(CodeContext context, Instruction instruction, SharpDisasm.Operand operand, GpRegister overload) {
            if (operand.Type == ud_type.UD_OP_REG) {
                var reg = SdToAsm.SdToAsmJit(context, operand.Base);
                if (reg.Present && reg.Type == RegisterType.GpRegister) {
                    return new MaybeOption<GpRegister>() {
                        Present = true,
                        Value = (GpRegister) reg.Register
                    };
                }
            }
            return new MaybeOption<GpRegister>();
        }
        public static MaybeOption<FpRegister> GetOperand(CodeContext context, Instruction instruction, SharpDisasm.Operand operand, FpRegister overload) {
            if (operand.Type == ud_type.UD_OP_REG) {
                var reg = SdToAsm.SdToAsmJit(context, operand.Base);
                if (reg.Present && reg.Type == RegisterType.FpRegister) {
                    return new MaybeOption<FpRegister>() {
                        Present = true,
                        Value = (FpRegister)reg.Register
                    };
                }
            }
            return new MaybeOption<FpRegister>();
        }
        public static MaybeOption<SegRegister> GetOperand(CodeContext context, Instruction instruction, SharpDisasm.Operand operand, SegRegister overload) {
            if (operand.Type == ud_type.UD_OP_REG) {
                var reg = SdToAsm.SdToAsmJit(context, operand.Base);
                if (reg.Present && reg.Type == RegisterType.SegRegister) {
                    return new MaybeOption<SegRegister>() {
                        Present = true,
                        Value = (SegRegister)reg.Register
                    };
                }
            }
            return new MaybeOption<SegRegister>();
        }
        public static MaybeOption<MmRegister> GetOperand(CodeContext context, Instruction instruction, SharpDisasm.Operand operand, MmRegister overload) {
            if (operand.Type == ud_type.UD_OP_REG) {
                var reg = SdToAsm.SdToAsmJit(context, operand.Base);
                if (reg.Present && reg.Type == RegisterType.MmRegister) {
                    return new MaybeOption<MmRegister>() {
                        Present = true,
                        Value = (MmRegister)reg.Register
                    };
                }
            }
            return new MaybeOption<MmRegister>();
        }
        public static MaybeOption<XmmRegister> GetOperand(CodeContext context, Instruction instruction, SharpDisasm.Operand operand, XmmRegister overload) {
            if (operand.Type == ud_type.UD_OP_REG) {
                var reg = SdToAsm.SdToAsmJit(context, operand.Base);
                if (reg.Present && reg.Type == RegisterType.XmmRegister) {
                    return new MaybeOption<XmmRegister>() {
                        Present = true,
                        Value = (XmmRegister)reg.Register
                    };
                }
            }
            return new MaybeOption<XmmRegister>();
        }
        public static MaybeOption<YmmRegister> GetOperand(CodeContext context, Instruction instruction, SharpDisasm.Operand operand, YmmRegister overload) {
            if (operand.Type == ud_type.UD_OP_REG) {
                var reg = SdToAsm.SdToAsmJit(context, operand.Base);
                if (reg.Present && reg.Type == RegisterType.YmmRegister) {
                    return new MaybeOption<YmmRegister>() {
                        Present = true,
                        Value = (YmmRegister)reg.Register
                    };
                }
            }
            return new MaybeOption<YmmRegister>();
        }
        public static MaybeOption<long> GetOperand(CodeContext context, Instruction instruction, SharpDisasm.Operand operand, long overload) {
            // Immediate should cover us
            return new MaybeOption<long>();
        }
        public static MaybeOption<ulong> GetOperand(CodeContext context, Instruction instruction, SharpDisasm.Operand operand, ulong overload) {
            // Immediate should cover us
            return new MaybeOption<ulong>();
        }
        public static MaybeOption<IntPtr> GetOperand(CodeContext context, Instruction instruction, SharpDisasm.Operand operand, IntPtr overload) {
            return new MaybeOption<IntPtr>();
        }
    }
}
