using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using AsmJit.AssemblerContext;
using AsmJit.Common.Operands;
using AsmJitAssembleLib;
using diStorm;
using SharpDisasm;
using SharpDisasm.Udis86;

namespace Program {

    public class MaybeUdType {
        public bool Present;
        public ud_type Type;
    }

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

    public class DecodeException : Exception {
        public DecodeException(string message) : base(message) {
        }
    }

    public class AssemblyUtil {
        public const int MaxInstructionBytes = 15;
        public const int MaxInstructions = 1;
        public const byte Nop = 0x90;
        public const byte Int3 = 0xCC;
        public static byte[] InfiniteLoop = new byte[] { 0xEB, 0xFE };
        public static Func<Win32Imports.ContextX64, string> FormatContext;
        public static Func<Win32Imports.ContextX64, Win32Imports.ContextX64, Instruction, string> FormatContextDiff;
        // MaxBranchBytes is sum of size of:
        // 2: jnz rel8
        // 4: sub rcx,1
        // 2: jnz rel8
        // 5: jmp afterMov
        // 10: mov rax, imm64
        // afterMov:
        public const int MaxBranchBytes = 31;

        static AssemblyUtil() {
            CreateFormatContext();
            CreateFormatContextDiff();
        }

        public static Instruction Reassemble(Instruction instruction) {
            var c = Assembler.CreateContext<Action>();
            AsmJitAssembler.AsmJitAssemble(c, instruction);
            var bs = AssemblyUtil.GetAsmJitBytes(c);
            var newInstruction = AssemblyUtil.Disassemble(bs);
            return newInstruction;
        }

        private static void CreateFormatContext() {
            var registers = new List<Expression>();
            ParameterExpression contextParam = Expression.Parameter(typeof(Win32Imports.ContextX64), "context");
            bool first = true;
            MethodInfo miFormatValue = typeof(AssemblyUtil).GetMethod(nameof(FormatValue),
                BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static);
            MethodInfo miFormatFlags = typeof(AssemblyUtil).GetMethod(nameof(FormatFlags),
                BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static);
            foreach (var field in typeof(Win32Imports.ContextX64).GetFields(BindingFlags.Instance |
                                                                            BindingFlags.NonPublic |
                                                                            BindingFlags.Public)) {
                var reg = field.Name.ToUpper();
                var titleExpr = Expression.Constant((first ? "" : " ") + reg + "=", typeof(string));
                if (!(field.FieldType == typeof(ulong) ||
                      field.FieldType == typeof(uint) ||
                      field.FieldType == typeof(EflagsEnum))) {
                    continue;
                }
                if (reg.Equals("EFLAGS")) {
                    var strValueExpr = 
                        Expression.Call(
                            miFormatFlags,
                            Expression.Field(contextParam, typeof(Win32Imports.ContextX64), field.Name));
                    registers.Add(titleExpr);
                    registers.Add(strValueExpr);
                } else {
                    var valueExpr = Expression.Convert(Expression.Field(contextParam, typeof(Win32Imports.ContextX64), field.Name), typeof(ulong));
                    var strValueExpr = Expression.Call(miFormatValue, valueExpr);
                    registers.Add(titleExpr);
                    registers.Add(strValueExpr);
                }
                first = false;
            }
            var arrayExpr = Expression.NewArrayInit(typeof(string), registers);
            MethodInfo miConcat = typeof(String).GetMethod("Concat",
                BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static,
                null,
                CallingConventions.Any,
                new[] {typeof(string[])},
                null);
            // Console.WriteLine($"mi: {miConcat}");
            var concatExpr = Expression.Call(miConcat, new Expression[] {arrayExpr});
            var expr = Expression.Lambda<Func<Win32Imports.ContextX64, string>>(concatExpr, contextParam);
            // Console.WriteLine($"expr: {expr}");
            FormatContext = expr.Compile();
        }

        // log only changed registers and operands
        public static void CreateFormatContextDiff() {
            var registers = new List<Expression>();
            ParameterExpression contextParam = Expression.Parameter(typeof(Win32Imports.ContextX64), "context");
            ParameterExpression oldContextParam = Expression.Parameter(typeof(Win32Imports.ContextX64), "oldContext");
            ParameterExpression oldInstructionParam = Expression.Parameter(typeof(Instruction), "oldInstruction");
            bool first = true;

            MethodInfo miFormatValueDiff = typeof(AssemblyUtil).GetMethod(nameof(FormatValueDiff),
                BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static);
            MethodInfo miFormatFlags = typeof(AssemblyUtil).GetMethod(nameof(FormatFlagsDiff),
                BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static);
            // Console.WriteLine($"miFVD: {miFormatValueDiff}");

            /*
            Dictionary<string, ud_type> regStringToUdType = new Dictionary<string, ud_type>();
            foreach (var field in typeof(Win32Imports.ContextX64).GetFields(BindingFlags.Instance |
                                                                            BindingFlags.NonPublic |
                                                                            BindingFlags.Public)) {
            }*/

            foreach (var field in typeof(Win32Imports.ContextX64).GetFields(BindingFlags.Instance |
                                                                            BindingFlags.NonPublic |
                                                                            BindingFlags.Public)) {
                var reg = field.Name.ToUpper();
                if (reg.Equals("RIP")) {
                    // instruction pointer is always logged before. don't need it twice
                    continue;
                }
                if (!(field.FieldType == typeof(ulong) ||
                      field.FieldType == typeof(uint) ||
                      field.FieldType == typeof(EflagsEnum))) {
                    continue;
                }

                var titleExpr = Expression.Constant((first ? "" : " ") + reg, typeof(string));

                if (reg.Equals("EFLAGS")) {
                    var strValueExpr =
                        Expression.Call(
                            miFormatFlags,
                            titleExpr,
                            Expression.Field(contextParam, typeof(Win32Imports.ContextX64), field.Name),
                            Expression.Field(oldContextParam, typeof(Win32Imports.ContextX64), field.Name));
                    registers.Add(strValueExpr);
                } else {
                    Func<string, MaybeUdType> lookup = (s) => {
                        if (s == null || 
                            s.Contains("HOME") ||
                            s.Contains("CONTEXT") ||
                            s.Equals("MXCSR") ||
                            s.Equals("VECTORCONTROL") ||
                            s.Equals("DEBUGCONTROL") ||
                            s.Equals("LASTBRANCHTORIP") ||
                            s.Equals("LASTBRANCHFROMRIP") ||
                            s.Equals("LASTEXCEPTIONTORIP") ||
                            s.Equals("LASTEXCEPTIONFROMRIP")) {
                            return new MaybeUdType();
                        }
                        var udstr = "UD_R_" + s;
                        ud_type udval;
                        
                        if (!Enum.TryParse(udstr, out udval)) {
                            throw new Exception($"could not find register {s} in ud_type");
                        }
                        return new MaybeUdType() {
                            Present = true,
                            Type = udval
                        };
                    };
                    Func<string, Expression> wrap = (s) => Expression.Constant(lookup(s), typeof(MaybeUdType));
                    var reg64 = wrap(reg);
                    var reg32 = wrap(Get32BitRegisterFrom64BitRegister(reg));
                    var reg16 = wrap(Get16BitRegisterFrom64BitRegister(reg));
                    var reg8U = wrap(Get8BitUpperRegisterFrom64BitRegister(reg));
                    var reg8L = wrap(Get8BitLowerRegisterFrom64BitRegister(reg));

                    var valueExpr =
                        Expression.Convert(Expression.Field(contextParam, typeof(Win32Imports.ContextX64), field.Name),
                            typeof(ulong));
                    var oldValueExpr =
                        Expression.Convert(
                            Expression.Field(oldContextParam, typeof(Win32Imports.ContextX64), field.Name),
                            typeof(ulong));
                    var strValueExpr = Expression.Call(miFormatValueDiff,
                        titleExpr,
                        reg64, reg32, reg16, reg8U, reg8L,
                        valueExpr, oldValueExpr,
                        oldInstructionParam
                        );
                    registers.Add(strValueExpr);
                    first = false;
                }
            }
            var arrayExpr = Expression.NewArrayInit(typeof(string), registers);
            MethodInfo miConcat = typeof(String).GetMethod(nameof(String.Concat),
                BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static,
                null,
                CallingConventions.Any,
                new[] { typeof(string[]) },
                null);
            var concatExpr = Expression.Call(miConcat, new Expression[] { arrayExpr });
            var expr = Expression.Lambda<Func<Win32Imports.ContextX64, Win32Imports.ContextX64, Instruction, string>>
                (concatExpr, contextParam, oldContextParam, oldInstructionParam);
            // Console.WriteLine($"expr: {expr}");
            FormatContextDiff = expr.Compile();
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
                    }
                    else {
                        throw new Exception("could not map base register to GpRegister");
                    }
                }
                else {
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
                            memoryReference = Memory.Byte(baseRegister, (int) displacement.Value);
                            break;
                        case 16:
                            memoryReference = Memory.Word(baseRegister, (int) displacement.Value);
                            break;
                        case 32:
                            memoryReference = Memory.DWord(baseRegister, (int) displacement.Value);
                            break;
                        case 64:
                            memoryReference = Memory.QWord(baseRegister, (int) displacement.Value);
                            break;
                        case 80:
                            memoryReference = Memory.TWord(baseRegister, (int) displacement.Value);
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

        public static string BytesToHex(byte[] mem) {
            var s = "";
            foreach (var b in mem) {
                s += $"{b:X2} ";
            }
            return s;
        }

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
                            context.Mov(target, (GpRegister) maybeRegister.Register);
                            break;
                        case RegisterType.SegRegister:
                            context.Mov(target, (SegRegister) maybeRegister.Register);
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
                    Console.WriteLine($"opr_mode: {instruction.opr_mode}");
                    switch (operand.Size) {
                        case 8:
                            immediate = (instruction.PC + (ulong) operand.LvalSByte) & truncMask;
                            break;
                        case 16:
                            immediate = (instruction.PC + (ulong) operand.LvalSWord) & truncMask;
                            break;
                        case 32:
                            immediate = (instruction.PC + (ulong) operand.LvalSDWord) & truncMask;
                            break;
                        default:
                            throw new Exception("invalid relative offset size.");
                    }
                    // in our emulator we are going to keep RIP in target (RAX)
                    context.Lea(target, Memory.QWord(target, (int) immediate));
                    break;
                default:
                    throw new Exception("unsupported operand type");
            }
        }

        public static string Get32BitRegisterFrom64BitRegister(string reg) {
            switch (reg) {
                case "RAX":
                    return "EAX";
                case "RCX":
                    return "ECX";
                case "RDX":
                    return "EDX";
                case "RBX":
                    return "EBX";
                case "RSP":
                    return "ESP";
                case "RBP":
                    return "EBP";
                case "RSI":
                    return "ESI";
                case "RDI":
                    return "EDI";
                case "RIP":
                    return "EIP";
            }
            return null;
        }

        public static string Get16BitRegisterFrom64BitRegister(string reg) {
            switch (reg) {
                case "RAX":
                    return "AX";
                case "RCX":
                    return "CX";
                case "RDX":
                    return "DX";
                case "RBX":
                    return "BX";
                case "RSP":
                    return "SP";
                case "RBP":
                    return "BP";
                case "RSI":
                    return "SI";
                case "RDI":
                    return "DI";
                case "RIP":
                    return "IP";
            }
            return null;
        }

        public static string Get8BitLowerRegisterFrom64BitRegister(string reg) {
            switch (reg) {
                case "RAX":
                    return "AL";
                case "RCX":
                    return "CL";
                case "RDX":
                    return "DL";
                case "RBX":
                    return "BL";
            }
            return null;
        }

        public static string Get8BitUpperRegisterFrom64BitRegister(string reg) {
            switch (reg) {
                case "RAX":
                    return "AH";
                case "RCX":
                    return "CH";
                case "RDX":
                    return "DH";
                case "RBX":
                    return "BH";
            }
            return null;
        }

        private static string FormatValueDiff(
            string regTitle,
            MaybeUdType reg64, MaybeUdType reg32, MaybeUdType reg16, MaybeUdType reg8U, MaybeUdType reg8L,
            ulong value, ulong oldValue,
            Instruction oldInstruction) {

            // if value changed, log both values, otherwise don't log it.
            if (oldValue != value) {
                return $" {regTitle}={FormatValue(oldValue)}->{FormatValue(value)}";
            }
            // always log operand registers
            var match = false;
            foreach (var op in oldInstruction.Operands) {
                if ((reg64.Present && op.Index == reg64.Type) ||
                    (reg32.Present && op.Index == reg32.Type) ||
                    (reg16.Present && op.Index == reg16.Type) ||
                    (reg8U.Present && op.Index == reg8U.Type) ||
                    (reg8L.Present && op.Index == reg8L.Type)) {
                    match = true;
                    break;
                }
                if ((reg64.Present && op.Base == reg64.Type) ||
                    (reg32.Present && op.Base == reg32.Type) ||
                    (reg16.Present && op.Base == reg16.Type) ||
                    (reg8U.Present && op.Base == reg8U.Type) ||
                    (reg8L.Present && op.Base == reg8L.Type)) {
                    match = true;
                    break;
                }
            }
            if (match) {
                return $" {regTitle}={FormatValue(value)}";
            }
            return "";
        }
        private static string FormatFlagsDiff(string regTitle, EflagsEnum flags, EflagsEnum oldFlags) {
            return flags != oldFlags ?
                regTitle + "=" + String.Join("|", oldFlags.GetIndividualFlags()) + "->" + String.Join("|", flags.GetIndividualFlags()) :
                "";
        }

        public static Instruction Disassemble(Process process, ulong address) {
            var mem = DebugProcessUtils.ReadBytes(process, address, MaxInstructionBytes);
            return Disassemble(mem);
        }

        public static Instruction ReadOneAndDisassemble(Process process, ulong address) {
            var mem = DebugProcessUtils.ReadBytes(process, address, MaxInstructionBytes);
            return Disassemble(mem);
        }

        public static Instruction Disassemble(byte[] mem, ulong address = 0) {
            using (new DebugAssertControl((x) => { throw new DecodeException("failed to decode"); })) {
                var mode = ArchitectureMode.x86_64;
                Disassembler.Translator.IncludeAddress = false;
                Disassembler.Translator.IncludeBinary = false;

                var disasm = new Disassembler(mem, mode, address, true);
                // Disassemble each instruction and output to console
                try {
                    foreach (var instruction in disasm.Disassemble()) {
                        return instruction;
                    }
                }
                catch (IndexOutOfRangeException) {
                    // ignore
                    throw new DecodeException("failed to decode");
                }
            }
            throw new DecodeException("failed to decode");
        }

        public static Instruction[] DisassembleMany(Process process, ulong address, ulong targetOffset) {
            var mem = DebugProcessUtils.ReadBytes(process, address, (int) (targetOffset - address));
            return DisassembleMany(mem, targetOffset);
        }

        public static Instruction[] DisassembleMany(byte[] mem, ulong targetOffset) {
            var retInstructions = new List<Instruction>();
            ulong offset = 0;
            using (new DebugAssertControl((x) => {
                // ReSharper disable once AccessToModifiedClosure
                if (offset <= targetOffset) {
                    throw new DecodeException($"could not reach {nameof(targetOffset)}: Debug.Assert in udis decode: {x}");
                }
                
            })) {
                var mode = ArchitectureMode.x86_64;
                Disassembler.Translator.IncludeAddress = false;
                Disassembler.Translator.IncludeBinary = false;

                var disasm = new Disassembler(mem, mode, 0, true);
                // Disassemble each instruction and output to console
                try {
                    foreach (var instruction in disasm.Disassemble()) {
                        if (offset + (ulong) instruction.Length <= targetOffset) {
                            retInstructions.Add(instruction);
                        } else {
                            break;
                        }
                        offset += (ulong) instruction.Length;
                    }
                }
                catch (IndexOutOfRangeException) {
                    throw new DecodeException($"could not reach {nameof(targetOffset)}");
                }
            }
            return retInstructions.ToArray();
        }

        private static string FormatFlags(EflagsEnum flags) {
            //return $"{Convert.ToString((uint) flags, 2)}:" + string.Join("|", flags.GetIndividualFlags());
            return String.Join("|", flags.GetIndividualFlags());
        }

        private static string FormatValue(ulong value) {
            if (value > 0xFFFF) {
                return $"0x{value:X}";
            }
            else {
                return value.ToString();
            }
        }

        public static string FormatInstruction(Instruction decodedInstruction) {
            //var asm = $"{decodedInstruction.Mnemonic} {decodedInstruction.Operands}";
            return decodedInstruction.ToString();
        }

        public static string FormatInstruction(CodeInfo ci, DecomposedInst decodedInstruction) {
            var x = diStorm3.Format(ci, decodedInstruction);
            var asm = $"{x.Mnemonic} {x.Operands}";
            return asm;
        }

        [Obsolete]
        public static string FormatContextReflection(Win32Imports.ContextX64 context) {
            var registers = "";
            foreach (var field in typeof(Win32Imports.ContextX64).GetFields(BindingFlags.Instance |
                                BindingFlags.NonPublic |
                                BindingFlags.Public)) {
                var reg = field.Name.ToUpper();
                string value;
                try {
                    value = field.GetValue(context).ToString();
                }
                catch {
                    value = "?";
                }
                ulong n;
                if (UInt64.TryParse(value, out n)) {
                    value = FormatValue(UInt64.Parse(value));
                    registers += $" {reg}={value}";
                }
            }
            return registers;
        }
        
        [Obsolete]
        public static string FormatContextDiffReflection(Win32Imports.ContextX64 context, Win32Imports.ContextX64 oldContext, DecodedInst oldInstruction) {
            var registers = "";

            // log only changed registers and operands
            foreach (var field in typeof(Win32Imports.ContextX64).GetFields(BindingFlags.Instance |
                            BindingFlags.NonPublic |
                            BindingFlags.Public)) {
                // log registers that changed
                var reg = field.Name.ToUpper();
                if (reg.Equals("RIP")) {
                    continue;
                }
                string oldValue;
                try {
                    oldValue = field.GetValue(oldContext).ToString();
                } catch {
                    oldValue = "?";
                }
                string value;
                try {
                    value = field.GetValue(context).ToString();
                } catch {
                    value = "?";
                }
                if (!oldValue.Equals(value)) {
                    oldValue = FormatValue(UInt64.Parse(oldValue));
                    value = FormatValue(UInt64.Parse(value));
                    registers += $" {reg}={oldValue}->{value}";
                } else {
                    // log operand registers
                    var ops = oldInstruction.Operands;
                    var reg32 = Regex.Replace(reg, "^R", "E");
                    var reg16 = Regex.Replace(reg, "^R", "");
                    int n;
                    if (ops.Contains(reg) || ops.Contains(reg32) || (!Int32.TryParse(reg16, out n) && ops.Contains(reg16))) {
                        value = FormatValue(UInt64.Parse(value));
                        registers += $" {reg}={value}";
                    }
                }
            }
            return registers;
        }

        public static byte[] GetAsmJitBytes(CodeContext<Action> c) {
            IntPtr patchSiteCodeJitRaw;
            int patchSiteCodeJitSize;
            c.Compile(out patchSiteCodeJitRaw, out patchSiteCodeJitSize);
            var patchSiteCodeJitBytes = new byte[patchSiteCodeJitSize];
            Marshal.Copy(patchSiteCodeJitRaw, patchSiteCodeJitBytes, 0, patchSiteCodeJitSize);
            return patchSiteCodeJitBytes;
        }

        // see also StackWalk64, but I'm not sure I can use that, because I don't have a function table
        public static void LogStackTrace(ImportResolver ir, Logger log, Process process, ulong stackPointer) {
            int size = 4096;
            var mem = DebugProcessUtils.ReadBytes(process, stackPointer, 4096);
            var ptrSize = Marshal.SizeOf(typeof(IntPtr));
            for (var offset = 0; offset + ptrSize < size; offset += 1) {
                ulong ptr = (ulong)BitConverter.ToInt64(mem, offset);
                if (ptr == 0) {
                    continue;
                }
                Tuple<string, ulong> ret = null;
                try {
                    ret = ir.LookupAddress(ptr);
                }
                catch (Exception)
                {
                    // ignored
                }
                string module = "lookup-failed";
                ulong relative = 0;
                if (ret != null) {
                    module = ret.Item1;
                    var functionAddress = ret.Item2;
                    relative = ptr - functionAddress;
                }

                byte[] ptrMem = null;
                try {
                    ptrMem = DebugProcessUtils.ReadBytes(process, ptr, ptrSize);
                }
                catch (Exception)
                {
                    // ignored
                }
                ulong data = 0;
                if (ptrMem != null) {
                    data = (ulong)BitConverter.ToInt64(ptrMem, 0);
                }
                for (ulong potentialCallOffset = 0; potentialCallOffset <= 6; potentialCallOffset++) {
                    try {
                        var callLocation = ptr - potentialCallOffset;
                        var instr = Disassemble(process, callLocation);
                        var asm = FormatInstruction(instr);
                        if (instr.Mnemonic == ud_mnemonic_code.UD_Icall || potentialCallOffset == 0) {
                            log.WriteLine($"stack call {offset}-{potentialCallOffset}: {module}+0x{relative:X} 0x{ptr:X}: asm 0x{data:X} {asm}");
                        }
                    } catch (Exception) {
                        if (potentialCallOffset == 0) {
                            log.WriteLine($"stack trace {offset}-{potentialCallOffset}: {module}+0x{relative:X} 0x{ptr:X}: asm 0x{data:X} exception");
                        }
                    }
                }
            }
        }
    }
}
