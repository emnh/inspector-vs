using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using diStorm;
using SharpDisasm;
using SharpDisasm.Udis86;

// TODO: rename file from ASMUtil to AsmUtil

namespace Program {

    public class MaybeUdType {
        public bool Present;
        public ud_type Type;
    }

    public class DecodeException : Exception {
        public DecodeException(string message) : base(message) {
        }
    }

    public class AsmUtil {
        public const int MaxInstructionBytes = 15;
        public const int MaxInstructions = 1;
        public const byte Nop = 0x90;
        public const byte Int3 = 0xCC;
        public static byte[] InfiniteLoop = new byte[] { 0xEB, 0xFE };
        public static Func<Win32Imports.ContextX64, string> FormatContext;
        public static Func<Win32Imports.ContextX64, Win32Imports.ContextX64, Instruction, string> FormatContextDiff;

        static AsmUtil() {
            CreateFormatContext();
            CreateFormatContextDiff();
        }

        private static void CreateFormatContext() {
            var registers = new List<Expression>();
            ParameterExpression contextParam = Expression.Parameter(typeof(Win32Imports.ContextX64), "context");
            bool first = true;
            MethodInfo miFormatValue = typeof(AsmUtil).GetMethod(nameof(FormatValue),
                BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static);
            MethodInfo miFormatFlags = typeof(AsmUtil).GetMethod(nameof(FormatFlags),
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

            MethodInfo miFormatValueDiff = typeof(AsmUtil).GetMethod(nameof(FormatValueDiff),
                BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static);
            MethodInfo miFormatFlags = typeof(AsmUtil).GetMethod(nameof(FormatFlagsDiff),
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
                regTitle + "=" + string.Join("|", oldFlags.GetIndividualFlags()) + "->" + string.Join("|", flags.GetIndividualFlags()) :
                "";
        }

        [Obsolete]
        public static DecodedInst Disassemble(Process process, ulong address) {
            var mem = DebugProcessUtils.ReadBytes(process, address, MaxInstructionBytes);
            var ci = new CodeInfo(0, mem, DecodeType.Decode64Bits, 0);
            var dr = new DecodedResult(MaxInstructions);
            diStorm3.Decode(ci, dr);
            var decodedInstruction = dr.Instructions.First();
            return decodedInstruction;
        }

        public static Instruction DisassembleDecode(Process process, ulong address) {
            var mem = DebugProcessUtils.ReadBytes(process, address, MaxInstructionBytes);
            using (
                DebugAssertControl dbg = new DebugAssertControl((x) => {
                    throw new DecodeException("failed to decode");
                })) {
                SharpDisasm.ArchitectureMode mode = SharpDisasm.ArchitectureMode.x86_64;
                SharpDisasm.Disassembler.Translator.IncludeAddress = false;
                SharpDisasm.Disassembler.Translator.IncludeBinary = false;

                var disasm = new SharpDisasm.Disassembler(mem, mode, 0, true);
                // Disassemble each instruction and output to console
                try {
                    foreach (var instruction in disasm.Disassemble()) {
                        return instruction;
                    }
                } catch (IndexOutOfRangeException) {
                    // ignore
                    throw new DecodeException("failed to decode");
                }
            }
            throw new DecodeException("failed to decode");
        }

        public static DecodedInst[] DisassembleMany(Process process, ulong address, int instructions = MaxInstructions) {
            var mem = DebugProcessUtils.ReadBytes(process, address, MaxInstructionBytes * instructions);
            var ci = new CodeInfo(0, mem, DecodeType.Decode64Bits, 0);
            var dr = new DecodedResult(instructions);
            diStorm3.Decode(ci, dr);
            return dr.Instructions;
        }

        private static string FormatFlags(EflagsEnum flags) {
            //return $"{Convert.ToString((uint) flags, 2)}:" + string.Join("|", flags.GetIndividualFlags());
            return string.Join("|", flags.GetIndividualFlags());
        }

        private static string FormatValue(ulong value) {
            if (value > 0xFFFF) {
                return $"0x{value:X}";
            }
            else {
                return value.ToString();
            }
        }

        public static string FormatInstruction(DecodedInst decodedInstruction) {
            var asm = $"{decodedInstruction.Mnemonic} {decodedInstruction.Operands}";
            return asm;
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
                if (ulong.TryParse(value, out n)) {
                    value = FormatValue(ulong.Parse(value));
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
                    oldValue = FormatValue(ulong.Parse(oldValue));
                    value = FormatValue(ulong.Parse(value));
                    registers += $" {reg}={oldValue}->{value}";
                } else {
                    // log operand registers
                    var ops = oldInstruction.Operands;
                    var reg32 = Regex.Replace(reg, "^R", "E");
                    var reg16 = Regex.Replace(reg, "^R", "");
                    int n;
                    if (ops.Contains(reg) || ops.Contains(reg32) || (!int.TryParse(reg16, out n) && ops.Contains(reg16))) {
                        value = FormatValue(ulong.Parse(value));
                        registers += $" {reg}={value}";
                    }
                }
            }
            return registers;
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
                        if (instr.Mnemonic.Equals("CALL") || potentialCallOffset == 0) {
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
