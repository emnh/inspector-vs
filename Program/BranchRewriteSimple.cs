using System;
using System.Text.RegularExpressions;
using SharpDisasm;
using SharpDisasm.Udis86;

namespace Program {
    class BranchRewriteSimple {

        public enum RegisterMask : byte
        {
            Eax = 1 << 1,
            Ebx = 1 << 2,
            Ecx = 1 << 3,
            Edx = 1 << 4
        }

        public class MaybeJumpSimple {
            public bool Present;
            public BranchInstruction Branch;
            public RegisterMask RipEquals;
            public Func<string, string> AddBranchOfSameType;
            public Func<string[]> AddInstrToGetBranchTarget;
        }

        public static RegisterMask FindFreeRegister(string asm) {
            if (!asm.Contains("eax")) {
                return RegisterMask.Eax;
            }
            if (!asm.Contains("ebx")) {
                return RegisterMask.Ebx;
            }
            if (!asm.Contains("ecx")) {
                return RegisterMask.Ecx;
            }
            if (!asm.Contains("edx")) {
                return RegisterMask.Edx;
            }
            throw new Exception("could not find free register");
        }

        public static MaybeJumpSimple IsBranch(Instruction instruction) {
            var retVal = new MaybeJumpSimple();
            var asm = instruction.ToString();
            var mnemonic = udis86.ud_lookup_mnemonic(instruction.Mnemonic);
            var asmOperands = Regex.Replace(asm, "^.*" + mnemonic + " ", "");
            var freeRegister = FindFreeRegister(asm);
            retVal.RipEquals = freeRegister;

            string ripRegister = freeRegister.ToString().ToLower();
            string targetRegister64 = "rax";
            string targetRegister = "rax";
            if (asmOperands.Contains("far word")) {
                asmOperands = asmOperands.Replace("far word", "word");
                targetRegister = AssemblyUtil.Get16BitRegisterFrom64BitRegister(targetRegister.ToUpper()).ToLower();
            }
            if (asmOperands.Contains("far dword")) {
                asmOperands = asmOperands.Replace("far dword", "dword");
                targetRegister = AssemblyUtil.Get32BitRegisterFrom64BitRegister(targetRegister.ToUpper()).ToLower();
            }
            if (asmOperands.Contains("far qword")) {
                asmOperands = asmOperands.Replace("far qword", "qword");
            }
            asmOperands = asmOperands.Replace("rip", ripRegister);

            Func<bool> getRelative = () => instruction.Operands.Length > 0 && instruction.Operands[0].Type == ud_type.UD_OP_JIMM;
            Func<string> getTargetInstruction = () => getRelative() ? "add" : "mov";

            retVal.AddBranchOfSameType = (label) => $"{mnemonic} {label}";
            retVal.AddInstrToGetBranchTarget = () => new[] {
                $";; {asm}",
                $"{getTargetInstruction()} {targetRegister}, {asmOperands}"
            };

            switch (instruction.Mnemonic) {

                // UNCONDITIONAL BRANCHES

                case ud_mnemonic_code.UD_Ijmp:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jmp;
                    retVal.AddBranchOfSameType = (label) => $"jmp {label}";
                    break;
                case ud_mnemonic_code.UD_Icall:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Call;
                    retVal.AddBranchOfSameType = (label) => $"jmp {label}";
                    retVal.AddInstrToGetBranchTarget = () => new[] {
                        $";; {asm}",
                        $"{getTargetInstruction()} {targetRegister}, {asmOperands}",
                        $"push {targetRegister64}"
                    };
                    break;
                case ud_mnemonic_code.UD_Iret:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Ret;
                    retVal.AddBranchOfSameType = (label) => $"jmp {label}";
                    retVal.AddInstrToGetBranchTarget = () => new[] {
                        $";; {asm}",
                        $"pop {targetRegister64}"
                    };
                    break;

                // CONDITIONAL BRANCHES

                // loop
                case ud_mnemonic_code.UD_Iloop:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Loop;
                    break;
                // loop if equal
                case ud_mnemonic_code.UD_Iloope:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Loope;
                    break;
                // loop if not equal
                case ud_mnemonic_code.UD_Iloopne:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Loopne;
                    break;
                // jump if above
                case ud_mnemonic_code.UD_Ija:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Ja;
                    break;
                // jump if above or equal
                case ud_mnemonic_code.UD_Ijae:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jae;
                    break;
                // jump if below
                case ud_mnemonic_code.UD_Ijb:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jb;
                    break;
                // jump if below or equal
                case ud_mnemonic_code.UD_Ijbe:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jbe;
                    break;
                // jump if cx register is 0
                case ud_mnemonic_code.UD_Ijcxz:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jcxz;
                    break;
                // jump if ecx register is 0
                case ud_mnemonic_code.UD_Ijecxz:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jecxz;
                    break;
                // jump if greater
                case ud_mnemonic_code.UD_Ijg:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jg;
                    break;
                // jump if greater or equal
                case ud_mnemonic_code.UD_Ijge:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jge;
                    break;
                // jump if less than
                case ud_mnemonic_code.UD_Ijl:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jl;
                    break;
                // jump if less than or equal
                case ud_mnemonic_code.UD_Ijle:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jle;
                    break;
                // jump if not overflow
                case ud_mnemonic_code.UD_Ijno:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jno;
                    break;
                // jump if not parity
                case ud_mnemonic_code.UD_Ijnp:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jnp;
                    break;
                // jump if not sign
                case ud_mnemonic_code.UD_Ijns:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jns;
                    break;
                // jump if not zero
                case ud_mnemonic_code.UD_Ijnz:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jnz;
                    break;
                // jump if overflow
                case ud_mnemonic_code.UD_Ijo:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jno;
                    break;
                // jump if parity
                case ud_mnemonic_code.UD_Ijp:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jp;
                    break;
                // jump if rcx zero
                case ud_mnemonic_code.UD_Ijrcxz:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jrcxz;
                    break;
                // jump if signed
                case ud_mnemonic_code.UD_Ijs:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Js;
                    break;
                // jump if zero
                case ud_mnemonic_code.UD_Ijz:
                    retVal.Present = true;
                    retVal.Branch = BranchInstruction.Jz;
                    break;
            }
            return retVal;
        }
    }
}
