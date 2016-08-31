using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using AsmJit.AssemblerContext;
using AsmJit.Common.Operands;
using Program;
using SharpDisasm;

namespace Test {

    class MyProgram {

        [DllImport("ContextLib.dll")]
        public static extern void testMain();

        public static void TestSharpDisasm() {
            
        }

        [HandleProcessCorruptedStateExceptions]
        static void Main() {

            // Process process = DebugProcessUtils.GetFirstProcessByName(Specifics.ProcessName);

            var c = Assembler.CreateContext<Action>();
            //c.Sub(c.Rcx, 1);
            c.Jae(0);
            c.Call((uint) 0x100);
            c.Jmp(c.Rax);
            c.Jmp(Memory.QWord(c.Rax));
            c.Fadd(c.Fp0, c.Fp1);
            c.Mov(c.Rax, (Immediate) 0x0102030405060708);
            c.Mov(c.Rax, 0x0102030405060708);
            c.Mov(c.Rax, (ulong)0x0102030405060708);
            c.Call(Memory.QWord(CodeContext.Rip, 10));
            //c.Call((Immediate) 0);
            //c.Nop();
            var length = AssemblyUtil.GetAsmJitBytes(c).Length;
            Console.WriteLine($"length: 0x{length:X}");
            //c.Call(0x0102030405060708);
            //c.Call(new IntPtr(0x0102030405060708));
            //c.Compile();
            byte[] bs = AssemblyUtil.GetAsmJitBytes(c);
            
            //bs = new byte[] { 0xEB, 0xFF - 0xA };
            Console.WriteLine($"bytes: {AssemblyUtil.BytesToHex(bs)}");

            var asms = AssemblyUtil.DisassembleMany(bs, 100);

            foreach (var asm in asms) {
                Console.WriteLine($"asm: {asm}, bytes: {AssemblyUtil.BytesToHex(asm.Bytes)}");
                var asm2 = AssemblyUtil.ReassembleNasm64(asm);
                Console.WriteLine($"asm: {asm}, asm2: {asm2}");
                // PrintAsmDetails(asm);
            }

            // TestFormatContext(process);

            // TestDisassemble();

            // TestResolve(process);

            //var instr = dr2.Instructions.First();
            //instr.Operands

            // HexStartAddr();
            // DumpModuleSizes(process);

            // var ir = new ImportResolver(process);
            // ir.DumpDebug();

            // SizeOfDebugStuff();

            // testMain();

            Console.WriteLine("done");
            Console.ReadKey();
        }

        public static void PrintAsmDetails(Instruction asm) {
            Console.WriteLine($"asm PC: {asm.PC}");
            Console.WriteLine($"asm LValSByte: {asm.Operands.First().LvalSByte}");
            Console.WriteLine($"asm (ulong) LValSByte: {(ulong) asm.Operands.First().LvalSByte:X}");
            Console.WriteLine($"asm PC + (ulong) LValSByte: {asm.PC + (ulong) asm.Operands.First().LvalSByte:X}");
            ulong truncMask = 0xffffffffffffffff >> (64 - asm.opr_mode);
            Console.WriteLine($"asm truncMask: {truncMask:X}");
            Console.WriteLine(
                $"asm (PC + (ulong) LValSByte) & truncMask: {(asm.PC + (ulong) asm.Operands.First().LvalSByte) & truncMask:X}");
        }

        public static void TestResolve(Process process) {
            ImportResolver ir = new ImportResolver(process);
            Console.WriteLine($"baseAddress: {(ulong) process.MainModule.BaseAddress:X}");
            var address = ir.ResolveRelativeAddress(Specifics.StartAddress);
            Console.WriteLine($"address: {address:X}");
        }

        public static void TestDisassemble() {
            var mem = new byte[] {0xCD, 0x2D};
            var asm = AssemblyUtil.Disassemble(mem);
            Console.WriteLine($"asm: {asm}, {asm.Mnemonic}, {asm.Operands[0].Value:X}");
        }

        public static void TestFormatContext(Process process) {
            var context = new Win32Imports.ContextX64();
            ContextManager.getRip((uint) process.Threads[0].Id, ref context, ContextManager.GetRipAction.ActionGetContext);
            var context2 = new Win32Imports.ContextX64();
            ContextManager.getRip((uint) process.Threads[0].Id, ref context2, ContextManager.GetRipAction.ActionGetContext);
            var instr = AssemblyUtil.ReadOneAndDisassemble(process, context2.Rip);
            var asm = instr.ToString();
            Console.WriteLine($"0x{context2.Rip:X}: {asm} {AssemblyUtil.FormatContext(context)}");
            Console.WriteLine($"0x{context2.Rip:X}: {asm} {AssemblyUtil.FormatContext(context2)}");
            Console.WriteLine($"0x{context2.Rip:X}: {asm} {AssemblyUtil.FormatContextDiff(context2, context, instr)}");
        }

        public static void DumpModuleSizes(Process process) {
            foreach (ProcessModule module in process.Modules) {
                var hexAddr = module.BaseAddress.ToString("X");
                Console.WriteLine($"{module.ModuleName}: {hexAddr} {module.ModuleMemorySize}");
            }
        }

        public static void HexStartAddr(Process process) {    
            var hex = process.MainModule.BaseAddress.ToString("X");
            Console.WriteLine($"baseaddr: 0x{hex}");
        }

        public static void SizeOfDebugStuff() {
            var offset = ulong.Parse("ffffffffffffffa0", System.Globalization.NumberStyles.AllowHexSpecifier);
            Console.WriteLine($"long: {(long) offset}");

            Console.WriteLine($"sizeof DEBUG_EVENT: {Marshal.SizeOf(typeof(Win32Imports.DebugEvent))}");

            Console.WriteLine($"sizeof EXCEPTION_DEBUG_INFO: {Marshal.SizeOf(typeof(Win32Imports.ExceptionDebugInfo))}");

            Console.WriteLine($"sizeof MEMORY_BASIC_INFORMATION: {Marshal.SizeOf(typeof(Win32Imports.MemoryBasicInformation))}");

            Console.WriteLine($"sizeof SYSTEM_INFO: {Marshal.SizeOf(typeof(Win32Imports.SystemInfo))}");
        }
    }
}
