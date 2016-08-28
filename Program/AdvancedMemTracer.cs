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
            public ulong CodeAddress;
        }

        public byte[] LoadAsmSizes(string path) {
            return File.ReadAllBytes(path);
        }

        public static void InstallTracer(Process process, ulong patchSite, Logger logger) {
            var processHandle = Win32Imports.OpenProcess(Win32Imports.ProcessAccessFlags.All, false, process.Id);

            var retVal = new TraceState();

            if ((ulong)processHandle == 0)
            {
                logger.WriteLine("could not open process");
                return;
            }

            const int patchSiteSize = 24;
            const int patchAreaSize = 100;
            const int codeSize = 1024 + patchAreaSize * 100;
            var originalCode = DebugProcessUtils.ReadBytes(process, patchSite, patchAreaSize);

            // minus patchSiteSize because we need to restore patchSiteSize bytes
            // var decodedInstructions = AsmUtil.DisassembleMany(originalCode.Take(patchAreaSize - patchSiteSize).ToArray(), patchAreaSize);
            var decodedInstructions = AsmUtil.DisassembleMany(originalCode, patchAreaSize - patchSiteSize);

            var bogusAddress = Win32Imports.VirtualAllocEx(
                processHandle,
                new IntPtr(0),
                new IntPtr(patchSiteSize * 2),
                Win32Imports.AllocationType.Commit | Win32Imports.AllocationType.Reserve,
                Win32Imports.MemoryProtection.ReadWrite);

            var codeAddress = Win32Imports.VirtualAllocEx(
                processHandle,
                new IntPtr(0),
                new IntPtr(codeSize),
                Win32Imports.AllocationType.Commit | Win32Imports.AllocationType.Reserve,
                Win32Imports.MemoryProtection.ExecuteReadWrite);

            retVal.CodeAddress = (ulong)codeAddress;

            if ((ulong)codeAddress == 0)
            {
                logger.WriteLine("could not allocate memory");
                return;
            }

            int addrSize = Marshal.SizeOf(typeof(IntPtr));

            var c1 = Assembler.CreateContext<Action>();

            // save rax
            c1.Push(c1.Rax);
            
            // push return address
            c1.Lea(c1.Rax, Memory.QWord(CodeContext.Rip, -addrSize));
            c1.Push(c1.Rax);

            // push "call" address
            c1.Mov(c1.Rax, (ulong) codeAddress);
            c1.Push(c1.Rax);

            // "call" codeAddress
            c1.Ret();

            c1.Nop();
            c1.Nop();
            c1.Nop();

            var patchSiteCodeJit = GetAsmJitBytes(c1);
            Debug.Assert(patchSiteCodeJit.Length == patchSiteSize, "patch site size incorrect");

            var c = Assembler.CreateContext<Action>();

            c.Push(c.Rbp);
            c.Mov(c.Rbp, c.Rsp);
            c.Pushf();
            c.Push(c.Rbx);
            c.Push(c.Rcx);
            c.Push(c.Rdx);

            // reserve space for last Rip address
            c.Mov(c.Rax, (ulong) 0x0102030405060708);
            var raxConstantJit = GetAsmJitBytes(c).Length - addrSize;
            var smcLastRipJit = GetAsmJitBytes(c).Length - addrSize;

            c.Lea(c1.Rax, Memory.QWord(CodeContext.Rip, -7 - addrSize));
            c.Mov(c.Rcx, Memory.QWord(c.Rax));
            c.Inc(c.Rcx);
            c.Xchg(Memory.QWord(c.Rax), c.Rcx);

            // find return address
            c.Mov(c.Rbx, Memory.QWord(c.Rbp, addrSize));

            // call pastEndCode
            var pastEndCode = c.Label();
            c.Call(pastEndCode);

            // start of function end code
            
            // put new patch in place          

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

            c.Bind(pastEndCode);

            c.Imul(c.Rcx, c.Rcx, 1);
            var multiplyImmediateJit = GetAsmJitBytes(c).Length - 1;

            c.Lea(c.Rcx, Memory.QWord(c.Rcx,c.Rax,0, 1));
            var leaRcxConstantJit = GetAsmJitBytes(c).Length - 1;

            c.Jmp(c.Rcx);

            var leaRcxConstantJitValue = GetAsmJitBytes(c).Length - smcLastRipJit;

            // restore function
            uint offset = 0;
            uint offsetJit = 0;
            var lastReturn = 0;
            var lastReturnJit = 0;
            var restoreLengthJit = 0;
            foreach (var instruction in decodedInstructions) {
                var startOfRestoreJit = GetAsmJitBytes(c).Length;

                var originalOffsetJit = 0;
                var patchOffsetJit = 0;
                var restorePatchMix = new byte[3 * addrSize];
                var restorePatchMixPtr = 0;
                foreach (var b in originalCode.Skip((int) offsetJit).Take(restorePatchMix.Length)) {
                    if (originalOffsetJit < instruction.Length) {
                        restorePatchMix[restorePatchMixPtr++] = b;
                    }
                    else {
                        restorePatchMix[restorePatchMixPtr++] = patchSiteCodeJit[patchOffsetJit++];
                    }
                    originalOffsetJit++;
                }

                // restore call site 1
                c.Mov(c.Rax, BitConverter.ToUInt64(restorePatchMix, 0));
                c.Mov(Memory.QWord(c.Rbx), c.Rax);

                // restore call site 2
                c.Mov(c.Rax, BitConverter.ToUInt64(restorePatchMix, addrSize));
                c.Mov(Memory.QWord(c.Rbx, addrSize), c.Rax);

                // restore call site 3
                c.Mov(c.Rax, BitConverter.ToUInt64(restorePatchMix, addrSize * 2));
                c.Mov(Memory.QWord(c.Rbx, addrSize * 2), c.Rax);
                
                // prepare rbx to put new patch in place
                c.Add(c.Rbx, (byte) instruction.Length);

                // return
                lastReturnJit = GetAsmJitBytes(c).Length;
                c.Ret();

                restoreLengthJit = GetAsmJitBytes(c).Length - startOfRestoreJit;

                offsetJit += (uint) instruction.Length;
            }
            
            // we set rbx to bogus so that patch is not written for last instruction in set
            c.Mov(c.Rbx, (ulong) bogusAddress);
            c.Ret();

            // overwrite some pieces of the code with values computed later on
            var codeSiteCodeJit = GetAsmJitBytes(c);
            for (var j = 0; j < 8; j++) {
                codeSiteCodeJit[raxConstantJit + j] = 0;
            }
            codeSiteCodeJit[multiplyImmediateJit] = (byte) restoreLengthJit;
            codeSiteCodeJit[leaRcxConstantJit] = (byte) leaRcxConstantJitValue;
            // overwrite last ret with nop
            codeSiteCodeJit[lastReturnJit] = 0x90;

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
            
            DebugProcessUtils.WriteBytes(process, (ulong) codeAddress, codeSiteCodeJit);
            DebugProcessUtils.WriteBytes(process, patchSite, patchSiteCodeJit);
        }

        private static byte[] GetAsmJitBytes(CodeContext<Action> c) {
            IntPtr patchSiteCodeJitRaw;
            int patchSiteCodeJitSize;
            c.Compile(out patchSiteCodeJitRaw, out patchSiteCodeJitSize);
            var patchSiteCodeJitBytes = new byte[patchSiteCodeJitSize];
            Marshal.Copy(patchSiteCodeJitRaw, patchSiteCodeJitBytes, 0, patchSiteCodeJitSize);
            return patchSiteCodeJitBytes;
        }

        public class OldState {
            public Win32Imports.ContextX64 OldContext;
            public Instruction OldInstruction;
        }

    }
}
