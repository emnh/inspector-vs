using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using AsmJit.AssemblerContext;
using AsmJit.Common;
using AsmJit.Common.Operands;
using Program;

namespace Test {

    class MyProgram {

        [DllImport("ContextLib.dll")]
        public static extern void testMain();

        public static void TestSharpDisasm() {
            
        }

        static void Main() {

            Process process = DebugProcessUtils.GetFirstProcessByName(Specifics.ProcessName);

            var c = Assembler.CreateContext<Action>();
            c.Sub(c.Rcx, 1);
            c.Compile();
            var bs = AsmUtil.GetAsmJitBytes(c);
            Console.WriteLine($"bytes: {AsmUtil.BytesToHex(bs)}");
            var asm = AsmUtil.Disassemble(bs.Skip(0).ToArray());
            Console.WriteLine($"asm: {asm}");

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

        private static void TestResolve(Process process) {
            ImportResolver ir = new ImportResolver(process);
            Console.WriteLine($"baseAddress: {(ulong) process.MainModule.BaseAddress:X}");
            var address = ir.ResolveRelativeAddress(Specifics.StartAddress);
            Console.WriteLine($"address: {address:X}");
        }

        private static void TestDisassemble() {
            var mem = new byte[] {0xCD, 0x2D};
            var asm = AsmUtil.Disassemble(mem);
            Console.WriteLine($"asm: {asm}, {asm.Mnemonic}, {asm.Operands[0].Value:X}");
        }

        private static void TestFormatContext(Process process) {
            var context = new Win32Imports.ContextX64();
            ContextManager.getRip((uint) process.Threads[0].Id, ref context, ContextManager.GetRipAction.ActionGetContext);
            var context2 = new Win32Imports.ContextX64();
            ContextManager.getRip((uint) process.Threads[0].Id, ref context2, ContextManager.GetRipAction.ActionGetContext);
            var instr = AsmUtil.ReadOneAndDisassemble(process, context2.Rip);
            var asm = instr.ToString();
            Console.WriteLine($"0x{context2.Rip:X}: {asm} {AsmUtil.FormatContext(context)}");
            Console.WriteLine($"0x{context2.Rip:X}: {asm} {AsmUtil.FormatContext(context2)}");
            Console.WriteLine($"0x{context2.Rip:X}: {asm} {AsmUtil.FormatContextDiff(context2, context, instr)}");
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
