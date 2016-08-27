using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Program;

namespace Test {    

    class MyProgram {

        [DllImport("ContextLib.dll")]
        public static extern void testMain();

        static void Main() {

            Process process = DebugProcessUtils.GetFirstProcessByName(Specifics.ProcessName);

            var context = new Win32Imports.ContextX64();
            ContextManager.getRip((uint) process.Threads[0].Id, ref context, ContextManager.GetRipAction.ActionGetContext);
            var context2 = new Win32Imports.ContextX64();
            ContextManager.getRip((uint)process.Threads[0].Id, ref context2, ContextManager.GetRipAction.ActionGetContext);
            var instr = AsmUtil.Disassemble(process, context2.Rip);
            Console.WriteLine($"0x{context2.Rip:X}: {AsmUtil.FormatInstruction(instr)} {AsmUtil.FormatContext(context)}");
            Console.WriteLine($"0x{context2.Rip:X}: {AsmUtil.FormatInstruction(instr)} {AsmUtil.FormatContext(context2)}");
            Console.WriteLine($"0x{context2.Rip:X}: {AsmUtil.FormatInstruction(instr)} {AsmUtil.FormatContextDiff(context2, context, instr)}");

            // HexStartAddr();
            // DumpModuleSizes(process);

            // var ir = new ImportResolver(process);
            // ir.DumpDebug();
            
            // SizeOfDebugStuff();

            // testMain();

            Console.WriteLine("done");
            Console.ReadKey();
        }

        private static void DumpModuleSizes(Process process) {
            foreach (ProcessModule module in process.Modules) {
                var hexAddr = module.BaseAddress.ToString("X");
                Console.WriteLine($"{module.ModuleName}: {hexAddr} {module.ModuleMemorySize}");
            }
        }

        private static void HexStartAddr(Process process) {
            
            var hex = process.MainModule.BaseAddress.ToString("X");
            Console.WriteLine($"baseaddr: 0x{hex}");
        }

        private static void SizeOfDebugStuff() {
            var offset = ulong.Parse("ffffffffffffffa0", System.Globalization.NumberStyles.AllowHexSpecifier);
            Console.WriteLine($"long: {(long) offset}");

            Console.WriteLine($"sizeof DEBUG_EVENT: {Marshal.SizeOf(typeof(Win32Imports.DebugEvent))}");

            Console.WriteLine($"sizeof EXCEPTION_DEBUG_INFO: {Marshal.SizeOf(typeof(Win32Imports.ExceptionDebugInfo))}");

            Console.WriteLine($"sizeof MEMORY_BASIC_INFORMATION: {Marshal.SizeOf(typeof(Win32Imports.MemoryBasicInformation))}");

            Console.WriteLine($"sizeof SYSTEM_INFO: {Marshal.SizeOf(typeof(Win32Imports.SystemInfo))}");
        }
    }
}
