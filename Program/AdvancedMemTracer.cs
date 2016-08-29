using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using AsmJit.AssemblerContext;
using AsmJit.Common.Operands;
using SharpDisasm;

namespace Program {

    public class AdvancedMemTracer {
        public class TraceState {
            public ulong TraceLogAddress;
            public ulong CodeAddress;
        }

        public byte[] LoadAsmSizes(string path) {
            return File.ReadAllBytes(path);
        }

        public static TraceState InstallTracer(Process process, ulong patchSite, Logger logger, byte[] asmSizes, ImportResolver ir) {
            var processHandle = Win32Imports.OpenProcess(Win32Imports.ProcessAccessFlags.All, false, process.Id);

            var traceState = new TraceState();

            if ((ulong)processHandle == 0)
            {
                logger.WriteLine("could not open process");
                return null;
            }

            const int patchSiteSize = 24;
            const int codeSize = 1024;
            const int traceLogSize = 1024;

            var originalCode = DebugProcessUtils.ReadBytes(process, (ulong) process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);

            var originalCodeAddress = Win32Imports.VirtualAllocEx(
                processHandle,
                new IntPtr(0),
                new IntPtr(originalCode.Length),
                Win32Imports.AllocationType.Commit | Win32Imports.AllocationType.Reserve,
                Win32Imports.MemoryProtection.ReadWrite);
            if ((ulong) originalCodeAddress == 0) {
                logger.WriteLine($"could not allocate memory for {nameof(originalCodeAddress)}");
                return null;
            }

            var traceLogAddress = Win32Imports.VirtualAllocEx(
                processHandle,
                new IntPtr(0),
                new IntPtr(traceLogSize),
                Win32Imports.AllocationType.Commit | Win32Imports.AllocationType.Reserve,
                Win32Imports.MemoryProtection.ReadWrite);
            if ((ulong) traceLogAddress == 0) {
                logger.WriteLine($"could not allocate memory for {nameof(traceLogAddress)}");
                return null;
            }

            var injectedCodeAddress = Win32Imports.VirtualAllocEx(
                processHandle,
                new IntPtr(0),
                new IntPtr(codeSize),
                Win32Imports.AllocationType.Commit | Win32Imports.AllocationType.Reserve,
                Win32Imports.MemoryProtection.ExecuteReadWrite);
            if ((ulong) injectedCodeAddress == 0) {
                logger.WriteLine($"could not allocate memory for {nameof(injectedCodeAddress)}");
                return null;
            }

            var asmSizesAddress = Win32Imports.VirtualAllocEx(
                processHandle,
                new IntPtr(0),
                new IntPtr(asmSizes.Length),
                Win32Imports.AllocationType.Commit | Win32Imports.AllocationType.Reserve,
                Win32Imports.MemoryProtection.ReadWrite);
            if ((ulong) asmSizesAddress == 0) {
                logger.WriteLine($"could not allocate memory for {nameof(asmSizesAddress)}");
                return null;
            }

            traceState.CodeAddress = (ulong) injectedCodeAddress;
            traceState.TraceLogAddress = (ulong) traceLogAddress;

            int addrSize = Marshal.SizeOf(typeof(IntPtr));

            var c1 = Assembler.CreateContext<Action>();

            // save rax
            c1.Push(c1.Rax);
            
            // push return address
            c1.Lea(c1.Rax, Memory.QWord(CodeContext.Rip, -addrSize));
            c1.Push(c1.Rax);

            // push "call" address
            c1.Mov(c1.Rax, (ulong) injectedCodeAddress);
            c1.Push(c1.Rax);

            // "call" codeAddress
            c1.Ret();

            c1.Nop();
            c1.Nop();
            c1.Nop();

            var patchSiteCodeJit = AsmUtil.GetAsmJitBytes(c1);
            Debug.Assert(patchSiteCodeJit.Length == patchSiteSize, "patch site size incorrect");

            var c = Assembler.CreateContext<Action>();

            c.Push(c.Rbp);
            c.Mov(c.Rbp, c.Rsp);
            c.Pushf();
            c.Push(c.Rbx);
            c.Push(c.Rcx);
            c.Push(c.Rdx);

            // log thread id
            var getThreadContext = ir.LookupFunction("KERNEL32.DLL:GetCurrentThreadId");
            //c.Call(getThreadContext);
            c.Lea(c.Rax, Memory.QWord(CodeContext.Rip, 13)); // skips next instructions
            c.Push(c.Rax);
            c.Mov(c.Rax, getThreadContext);
            c.Push(c.Rax);
            c.Ret();
            c.Mov(c.Rbx, (ulong) traceLogAddress);
            c.Mov(Memory.Word(c.Rbx), c.Eax);

            // reserve space for instruction counter, the 01-08 is just so AsmJit doesn't shorten the instruction
            // we overwrite the value to 0 later on
            c.Mov(c.Rax, (ulong) 0x0102030405060708);
            var smcLastRipJit = AsmUtil.GetAsmJitBytes(c).Length - addrSize;
            c.Lea(c1.Rax, Memory.QWord(CodeContext.Rip, -7 - addrSize));
            c.Mov(c.Rcx, Memory.QWord(c.Rax));
            c.Inc(c.Rcx);
            c.Xchg(Memory.QWord(c.Rax), c.Rcx);

            // find return address and store size of instruction at return address in rcx
            c.Mov(c.Rdx, Memory.QWord(c.Rbp, addrSize));
            c.Mov(c.Rbx, c.Rdx);
            c.Mov(c.Rax, (ulong) process.MainModule.BaseAddress);
            c.Sub(c.Rdx, c.Rax);
            c.Mov(c.Rax, (ulong) asmSizesAddress);
            c.Add(c.Rdx, c.Rax);
            c.Movzx(c.Rcx, Memory.Byte(c.Rdx));

            // RESTORE ORIGINAL CODE

            // get address of original code in Rdx
            c.Mov(c.Rdx, c.Rbx);
            c.Mov(c.Rax, (ulong)process.MainModule.BaseAddress);
            c.Sub(c.Rdx, c.Rax);
            // TODO: compare Rdx with process.MainModule.ModuleMemorySize - patchSiteSize and abort if greater
            c.Mov(c.Rax, (ulong) originalCodeAddress);
            c.Add(c.Rdx, c.Rax);

            // restore call site 1
            c.Mov(c.Rax, Memory.QWord(c.Rdx));
            c.Mov(Memory.QWord(c.Rbx), c.Rax);

            // restore call site 2
            c.Mov(c.Rax, Memory.QWord(c.Rdx, addrSize));
            c.Mov(Memory.QWord(c.Rbx, addrSize), c.Rax);

            // restore call site 3
            c.Mov(c.Rax, Memory.QWord(c.Rdx, addrSize * 2));
            c.Mov(Memory.QWord(c.Rbx, addrSize * 2), c.Rax);

            // CLEAN UP AND RETURN

            // put new patch in place

            // add instruction size to return address, so we write patch at next instruction
            c.Add(c.Rbx, c.Rcx);

            // restore patch site 1
            c.Mov(c.Rax, BitConverter.ToUInt64(patchSiteCodeJit, 0));
            c.Mov(Memory.QWord(c.Rbx), c.Rax);
            
            // restore patch site 2
            c.Mov(c.Rax, BitConverter.ToUInt64(patchSiteCodeJit, addrSize));
            c.Mov(Memory.QWord(c.Rbx, addrSize), c.Rax);

            // restore patch site 3
            c.Mov(c.Rax, BitConverter.ToUInt64(patchSiteCodeJit, addrSize * 2));
            c.Mov(Memory.QWord(c.Rbx, addrSize * 2), c.Rax);

            // end put new patch in place

            // restore rax from call site
            c.Mov(c.Rax, Memory.QWord(c.Rbp, 2 * addrSize));
            
            c.Pop(c.Rdx);
            c.Pop(c.Rcx);
            c.Pop(c.Rbx);            
            c.Popf();
            c.Pop(c.Rbp);            
            c.Ret((ulong) 8);

            // overwrite some pieces of the code with values computed later on
            var codeSiteCodeJit = AsmUtil.GetAsmJitBytes(c);
            for (var j = 0; j < 8; j++) {
                codeSiteCodeJit[smcLastRipJit + j] = 0;
            }

            var i = 0;
            var nextOffset1 = 0;
            using (var sw = new StreamWriter(Specifics.PatchAsmDumpFileName)) {
                foreach (var s in codeSiteCodeJit.Select((b1) => $"b: 0x{b1:X2}")) {
                    var asm1S = "";
                    try {
                        var asm1 = AsmUtil.Disassemble(codeSiteCodeJit.Skip(i).Take(AsmUtil.MaxInstructionBytes).ToArray());
                        asm1S = i == nextOffset1 ? asm1.ToString() : "";
                        if (i == nextOffset1) {
                            nextOffset1 += asm1.Length;
                        }
                    }
                    catch (DecodeException) {
                        asm1S = "failed";
                    }
                    
                    sw.WriteLine($"{s}: ASM: {asm1S}");

                    i++;
                }
            }

            if (codeSiteCodeJit.Length > codeSize) {
                throw new Exception("did not reserve enough memory for code");
            }

            // write process memory
            DebugProcessUtils.WriteBytes(process, (ulong) originalCodeAddress, originalCode);
            DebugProcessUtils.WriteBytes(process, (ulong) asmSizesAddress, asmSizes);
            DebugProcessUtils.WriteBytes(process, (ulong) injectedCodeAddress, codeSiteCodeJit);
            DebugProcessUtils.WriteBytes(process, patchSite, patchSiteCodeJit);

            return traceState;
        }

        public class OldState {
            public Win32Imports.ContextX64 OldContext;
            public Instruction OldInstruction;
        }
    }
}
