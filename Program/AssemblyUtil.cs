﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using AsmJit.AssemblerContext;
using diStorm;
using SharpDisasm;
using SharpDisasm.Udis86;

namespace Program {

    public class MaybeUdType {
        public bool Present;
        public ud_type Type;
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
        public static byte[] InfiniteLoop = { 0xEB, 0xFE };
        public static Func<Win32Imports.ContextX64, string> FormatContext;
        public static Func<Win32Imports.ContextX64, Win32Imports.ContextX64, Instruction, string> FormatContextDiff;

        // MaxBranchBytes is greater than sum of size of:
        // 1: db flags
        // 2: jnz rel8
        // 1: clc
        // 2: jmp afterMov
        // 10: mov rax, imm64
        // 1: stc
        // afterMov:
        public const int MaxBranchBytes = 20;

        static AssemblyUtil() {
            CreateFormatContext();
            CreateFormatContextDiff();
        }

        public static Instruction Reassemble(Instruction instruction) {
            throw new NotImplementedException("removed AsmJitAssemble because the big file took a toll on VS and Resharper, plus crashing at runtime. using nasm now");
            /*
            var c = Assembler.CreateContext<Action>();
            AsmJitAssembler.AsmJitAssemble(c, instruction);
            var bs = AssemblyUtil.GetAsmJitBytes(c);
            var newInstruction = AssemblyUtil.Disassemble(bs);
            return newInstruction;
            */
        }

        [Obsolete]
        public static Instruction ReassembleMl64(Instruction instruction) {
            var template = @"
.CODE
main PROC
  mov rax, 0102030405060708h
  $REPLACEME
  mov rax, 807060504030201h
main ENDP
END
";

            string tempPath = Path.GetTempPath();
            string tempName = "scrap.asm";
            string fullPath = Path.Combine(tempPath, tempName);
            //SharpDisasm.Disassembler.Translator = new SharpDisasm.Translators.MasmTranslator();
            //var asm = new MasmTranslator().Translate(instruction);
            var asm = instruction.ToString();
            Console.WriteLine($"masm: {asm}");
            //SharpDisasm.Disassembler.Translator = new SharpDisasm.Translators.IntelTranslator();
            File.WriteAllText(fullPath, template.Replace("$REPLACEME", asm));
            //Process cl = Process.Start(@"CMD.exe", @"/K ""C:\Program Files(x86)\Microsoft Visual Studio 14.0\VC\bin\cl.exe"" " + cfile);

            Console.WriteLine($"tempPath: {tempPath}");

            Process cmd = new Process {
                StartInfo = {
                    FileName = @"CMD.exe",
                    WorkingDirectory = tempPath,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true,
                    UseShellExecute = false
                }
            };


            //cmd.StandardInput.WriteLine("echo Oscar");
            //cmd.StandardInput.Flush();
            cmd.Start();
            cmd.StandardInput.WriteLine("\"" + @"C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" + "\"" + " amd64");
            cmd.StandardInput.WriteLine(@"ml64.exe " + tempName + @" /link /subsystem:console /entry:main ");
            //cmd.StandardInput.WriteLine(tempName.Replace(".c", ".exe"));
            cmd.StandardInput.WriteLine(@"exit");
            cmd.StandardInput.Close();
            cmd.WaitForExit();
            Console.WriteLine(cmd.StandardOutput.ReadToEnd());

            var bs = File.ReadAllBytes(fullPath.Replace(".asm", ".obj"));

            var startMarker = new byte[] { 0x48, 0xB8, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 };
            var endMarker = new byte[] { 0x48, 0xB8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
            int start = 0;
            int end = 0;
            for (var i = 0; i < bs.Length; i++) {
                bool foundStart = true;
                for (var j = 0; j < startMarker.Length; j++) {
                    if (bs[i + j] != startMarker[j]) {
                        foundStart = false;
                        break;
                    }
                }
                if (foundStart) {
                    start = i + startMarker.Length;
                }
                bool foundEnd = true;
                for (var j = 0; j < endMarker.Length; j++) {
                    if (bs[i + j] != endMarker[j]) {
                        foundEnd = false;
                        break;
                    }
                }
                if (foundEnd) {
                    end = i;
                    break;
                }
            }

            var instructionBytes = bs.Skip(start).Take(end - start).ToArray();
            var hex = BytesToHex(instructionBytes);

            Console.WriteLine($"start: {start}, end: {end}, hex: {hex}");
            Instruction instr = null;
            if (instructionBytes.Length > 0) {
                instr = Disassemble(instructionBytes);
            }

            return instr;
        }

        public static long LongRandom(long min, long max, Random rand) {
            byte[] buf = new byte[8];
            rand.NextBytes(buf);
            long longRand = BitConverter.ToInt64(buf, 0);

            return (Math.Abs(longRand % (max - min)) + min);
        }

        public static Instruction ReassembleNasm64(Instruction instruction) {
            var template = @"
BITS 64
%idefine rip rel $+next-prev
prev:
$REPLACEME
next:
";
            // %idefine rip rel $

            string tempPath = Path.GetTempPath();
            var num = LongRandom(0, long.MaxValue, new Random());
            string tempName = $"scrap{num}.asm";
            string fullPath = Path.Combine(tempPath, tempName);
            
            //var asm = new NasmTranslator().Translate(instruction);
            var asm = instruction.ToString();
            //Console.WriteLine($"nasm: {asm}, optype: {instruction.Operands.First().Type}");
            
            File.WriteAllText(fullPath, template.Replace("$REPLACEME", asm));
            //Process cl = Process.Start(@"CMD.exe", @"/K ""C:\Program Files(x86)\Microsoft Visual Studio 14.0\VC\bin\cl.exe"" " + cfile);

            //Console.WriteLine($"tempPath: {tempPath}");

            Process cmd = new Process {
                StartInfo = {
                    FileName = @"CMD.exe",
                    WorkingDirectory = tempPath,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    UseShellExecute = false
                }
            };

            //cmd.StandardInput.WriteLine("echo Oscar");
            //cmd.StandardInput.Flush();
            cmd.Start();
            
            cmd.StandardInput.WriteLine(@"C:\Users\hvide\AppData\Local\NASM\nasmpath.bat");
            cmd.StandardInput.WriteLine(@"nasm.exe -f bin " + tempName);
            //cmd.StandardInput.WriteLine(tempName.Replace(".c", ".exe"));
            cmd.StandardInput.WriteLine(@"exit");
            cmd.StandardInput.Close();
            cmd.WaitForExit();
            cmd.StandardOutput.ReadToEnd();
            //Console.WriteLine(cmd.StandardOutput.ReadToEnd());
            foreach (var s in cmd.StandardError.ReadToEnd().Split(new[] { Environment.NewLine }, StringSplitOptions.None)) {
                if (!s.Contains("warning: absolute address can not be RIP-relative")) {
                    Console.WriteLine(s);
                }
            }
            

            var bs = File.ReadAllBytes(fullPath.Replace(".asm", ""));
            var instructionBytes = bs;

            //var hex = BytesToHex(instructionBytes);
            //Console.WriteLine($"hex: {hex}");

            Instruction instr = null;
            if (instructionBytes.Length > 0) {
                instr = Disassemble(instructionBytes);
            }

            return instr;
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

        public static bool IsNasmValid(Instruction instruction, string asm) {
            return !asm.Contains("invalid") &&
                   // unsupported instructions
                   !asm.Contains("frstpm") &&
                   !asm.Contains("fnsetpm") &&
                   !asm.Contains("fstp1") &&
                   !asm.Contains("fstp8") &&
                   !asm.Contains("fstp9") &&
                   !asm.Contains("fxch4") &&
                   !asm.Contains("fxch7") &&
                   !asm.Contains("fcom2") &&
                   !asm.Contains("fcomp3") &&
                   !asm.Contains("fcomp5") &&
                   !asm.Contains("repne j") &&
                   !asm.Contains("repne ret") &&
                   !asm.Contains("minsd") &&
                   // unsupported operands
                   !asm.Contains("pinsrw") &&
                   !asm.Contains("vmptrld") &&
                   !asm.Contains("vmptrst") &&
                   !asm.Contains("vmaskmovpd") &&
                   !asm.Contains("vpinsrw") &&
                   !asm.Contains("divsd") &&
                   !asm.Contains("pmulhrw") &&
                   !(instruction.Mnemonic == ud_mnemonic_code.UD_Inop && instruction.Operands.Length > 0) &&
                   !(instruction.Mnemonic == ud_mnemonic_code.UD_Ipause && instruction.Operands.Length > 0);
        }

        public static string BytesToHex(byte[] mem, string separator = " ") {
            var s = new List<string>();
            foreach (var b in mem) {
                s.Add($"{b:X2}");
            }
            return String.Join(separator, s);
        }

        public static string BytesToHexZeroX(byte[] mem, string separator = " ") {
            var s = new List<string>();
            foreach (var b in mem) {
                s.Add($"0x{b:X2}");
            }
            return String.Join(separator, s);
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
