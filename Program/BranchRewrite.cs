using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AsmJit.AssemblerContext;
using AsmJit.Common.Operands;
using AsmJitAssembleLib;
using SharpDisasm;
using SharpDisasm.Udis86;

namespace Program {

    public enum BranchInstruction : byte {
        Jmp,
        Call,
        Ret,
        Loop,
        Loope,
        Loopne,
        Ja,
        Jae,
        Jb,
        Jbe,
        Jcxz,
        Jecxz,
        Jg,
        Jge,
        Jl,
        Jle,
        Jno,
        Jnp,
        Jns,
        Jnz,
        Jo,
        Jp,
        Jrcxz,
        Js,
        Jz
    }

    public class MaybeJump {
        public bool Present;
        // if IsRelative is true, we should add target to instruction pointer
        public bool IsRelative;
        public BranchInstruction Branch;
        public Action<CodeContext, Label> AddBranchOfSameType;
        public Action<CodeContext, GpRegister> AddInstrToGetBranchTarget;
        public Action<CodeContext, GpRegister> ApplyStackModifierBefore;
        public Action<CodeContext, GpRegister> ApplyStackModifierAfter;
    }

    public class BranchRewrite {
        public static MaybeJump IsBranch(Instruction instruction) {
            var retVal = new MaybeJump();
            //instruction.Operands.First()
            switch (instruction.Mnemonic) {

                // UNCONDITIONAL BRANCHES

                case ud_mnemonic_code.UD_Ijmp:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jmp;
                    retVal.AddBranchOfSameType = (context, label) => context.Jmp(label);
                    break;
                case ud_mnemonic_code.UD_Icall:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Call;
                    retVal.AddBranchOfSameType = (context, label) => context.Jmp(label);
                    retVal.ApplyStackModifierBefore = (context, target) => context.Push(target);
                    break;
                case ud_mnemonic_code.UD_Iret:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Ret;
                    retVal.AddBranchOfSameType = (context, label) => context.Jmp(label);
                    retVal.AddInstrToGetBranchTarget = (context, target) => {
                        context.Mov(target, Memory.QWord(context.Rsp));
                    };
                    retVal.ApplyStackModifierAfter = (context, target) => context.Pop(target);
                    break;

                // CONDITIONAL BRANCHES

                case ud_mnemonic_code.UD_Iloop:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Loop;
                    retVal.AddBranchOfSameType = (context, label) => {
                        context.Sub(context.Rcx, 1);
                        context.Jnz(label);
                    };
                    break;
                case ud_mnemonic_code.UD_Iloope:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Loope;
                    retVal.AddBranchOfSameType = (context, label) => {
                        context.Jz(label);
                        context.Sub(context.Rcx, 1);
                        context.Jnz(label);
                    };
                    break;
                case ud_mnemonic_code.UD_Iloopne:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Loopne;
                    retVal.AddBranchOfSameType = (context, label) => {
                        context.Jnz(label);
                        context.Sub(context.Rcx, 1);
                        context.Jnz(label);
                    };
                    break;

                // jump if above
                case ud_mnemonic_code.UD_Ija:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Ja;
                    retVal.AddBranchOfSameType = (context, label) => context.Ja(label);
                    break;
                // jump if above or equal
                case ud_mnemonic_code.UD_Ijae:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jae;
                    retVal.AddBranchOfSameType = (context, label) => context.Jae(label);
                    break;
                // jump if below
                case ud_mnemonic_code.UD_Ijb:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jb;
                    retVal.AddBranchOfSameType = (context, label) => context.Jb(label);
                    break;
                // jump if below or equal
                case ud_mnemonic_code.UD_Ijbe:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jbe;
                    retVal.AddBranchOfSameType = (context, label) => context.Jbe(label);
                    break;
                // jump if cx register is 0
                case ud_mnemonic_code.UD_Ijcxz:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jcxz;
                    retVal.AddBranchOfSameType = (context, label) => context.Jecxz(context.Cx, label);
                    break;
                // jump if ecx register is 0
                case ud_mnemonic_code.UD_Ijecxz:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jecxz;
                    retVal.AddBranchOfSameType = (context, label) => context.Jecxz(context.Ecx, label);
                    break;
                // jump if greater
                case ud_mnemonic_code.UD_Ijg:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jg;
                    retVal.AddBranchOfSameType = (context, label) => context.Jg(label);
                    break;
                // jump if greater or equal
                case ud_mnemonic_code.UD_Ijge:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jge;
                    retVal.AddBranchOfSameType = (context, label) => context.Jge(label);
                    break;
                // jump if less than
                case ud_mnemonic_code.UD_Ijl:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jl;
                    retVal.AddBranchOfSameType = (context, label) => context.Jl(label);
                    break;
                // jump if less than or equal
                case ud_mnemonic_code.UD_Ijle:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jle;
                    retVal.AddBranchOfSameType = (context, label) => context.Jle(label);
                    break;
                // jump if not overflow
                case ud_mnemonic_code.UD_Ijno:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jno;
                    retVal.AddBranchOfSameType = (context, label) => context.Jno(label);
                    break;
                // jump if not parity
                case ud_mnemonic_code.UD_Ijnp:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jnp;
                    retVal.AddBranchOfSameType = (context, label) => context.Jnp(label);
                    break;
                // jump if not sign
                case ud_mnemonic_code.UD_Ijns:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jns;
                    retVal.AddBranchOfSameType = (context, label) => context.Jns(label);
                    break;
                // jump if not zero
                case ud_mnemonic_code.UD_Ijnz:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jnz;
                    retVal.AddBranchOfSameType = (context, label) => context.Jnz(label);
                    break;
                // jump if overflow
                case ud_mnemonic_code.UD_Ijo:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jno;
                    retVal.AddBranchOfSameType = (context, label) => context.Jno(label);
                    break;
                // jump if parity
                case ud_mnemonic_code.UD_Ijp:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jp;
                    retVal.AddBranchOfSameType = (context, label) => context.Jp(label);
                    break;
                // jump if rcx zero
                case ud_mnemonic_code.UD_Ijrcxz:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jrcxz;
                    retVal.AddBranchOfSameType = (context, label) => context.Jecxz(context.Rcx, label);
                    break;
                // jump if signed
                case ud_mnemonic_code.UD_Ijs:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Js;
                    retVal.AddBranchOfSameType = (context, label) => context.Js(label);
                    break;
                // jump if zero
                case ud_mnemonic_code.UD_Ijz:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jz;
                    retVal.AddBranchOfSameType = (context, label) => context.Jz(label);
                    break;
            }
            if (retVal.Present && retVal.Branch != BranchInstruction.Ret) {
                retVal.AddInstrToGetBranchTarget = (context, target) => {
                    GetBranchTarget(instruction, context, target);
                };
            }
            return retVal;
        }


        private static void GetBranchTarget(Instruction instruction, CodeContext context, GpRegister target) {
            var operand = instruction.Operands.First();
            switch (operand.Type) {
                case ud_type.UD_OP_REG:
                    var maybeRegister = SdToAsm.SdToAsmJit(context, operand.Base);
                    if (!maybeRegister.Present) {
                        throw new Exception("could not map register");
                    }
                    switch (maybeRegister.Type) {
                        case RegisterType.GpRegister:
                            context.Mov(target, (GpRegister)maybeRegister.Register);
                            break;
                        case RegisterType.SegRegister:
                            context.Mov(target, (SegRegister)maybeRegister.Register);
                            break;
                        default:
                            throw new Exception("unsupported register");
                    }
                    break;
                case ud_type.UD_OP_MEM:
                    CreateLea(context, target, instruction);
                    break;
                case ud_type.UD_OP_JIMM:
                    ulong immediate;
                    ulong truncMask = 0xffffffffffffffff >> (64 - instruction.opr_mode);
                    // Console.WriteLine($"opr_mode: {instruction.opr_mode}");
                    switch (operand.Size) {
                        case 8:
                            immediate = (instruction.PC + (ulong)operand.LvalSByte) & truncMask;
                            break;
                        case 16:
                            immediate = (instruction.PC + (ulong)operand.LvalSWord) & truncMask;
                            break;
                        case 32:
                            immediate = (instruction.PC + (ulong)operand.LvalSDWord) & truncMask;
                            break;
                        default:
                            throw new Exception("invalid relative offset size.");
                    }
                    // in our emulator we are going to keep RIP in target (RAX)
                    context.Lea(target, Memory.QWord(target, (int)immediate));
                    break;
                default:
                    throw new Exception("unsupported operand type");
            }
        }

        public static void CreateLea(CodeContext context, GpRegister target, Instruction instruction) {
            var operand = instruction.Operands.First();
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
                baseRegister = target;
                if (maybeIndexRegister == null) {
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
            context.Lea(target, memoryReference);
        }


    }
}
