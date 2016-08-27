using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Numerics;

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
            var ci = new diStorm.CodeInfo(0, originalCode.Take(patchAreaSize - patchSiteSize).ToArray(), diStorm.DecodeType.Decode64Bits, 0);
            var dr = new diStorm.DecodedResult(patchAreaSize);
            diStorm.diStorm3.Decode(ci, dr);
            var decodedInstructions = dr.Instructions;

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

            var patchSiteCode = new byte[patchSiteSize];
            var codeSiteCode = new byte[codeSize];
            var patchPtr = 0;
            var ptr = 0;

            //patchSiteCode[patchPtr++] = 0xCC;
            // push rax, see RESTORE_RAX
            patchSiteCode[patchPtr++] = 0x50;
            // lea rax, [rip-8]
            patchSiteCode[patchPtr++] = 0x48;
            patchSiteCode[patchPtr++] = 0x8D;
            patchSiteCode[patchPtr++] = 0x05;
            patchSiteCode[patchPtr++] = 0xF8;
            patchSiteCode[patchPtr++] = 0xFF;
            patchSiteCode[patchPtr++] = 0xFF;
            patchSiteCode[patchPtr++] = 0xFF;
            // push rax (rip)
            patchSiteCode[patchPtr++] = 0x50;
            // mov rax, constant
            patchSiteCode[patchPtr++] = 0x48;
            patchSiteCode[patchPtr++] = 0xB8;
            foreach (var b in BitConverter.GetBytes((ulong) codeAddress)) {
                patchSiteCode[patchPtr++] = b;
            }
            // push rax
            patchSiteCode[patchPtr++] = 0x50;
            // ret
            patchSiteCode[patchPtr++] = 0xC3;
            patchPtr += 3;

            if (patchPtr != patchSiteSize)
            {
                logger.WriteLine($"made a mistake: {patchPtr} != {patchSiteSize}");
                return;
            }

            // push rbp
            codeSiteCode[ptr++] = 0x55;
            // mov rbp, rsp
            codeSiteCode[ptr++] = 0x48;
            codeSiteCode[ptr++] = 0x89;
            codeSiteCode[ptr++] = 0xE5;
            // push flags
            codeSiteCode[ptr++] = 0x9C;
            // push rbx
            codeSiteCode[ptr++] = 0x53;
            // push rcx
            codeSiteCode[ptr++] = 0x51;
            // push rdx
            codeSiteCode[ptr++] = 0x52;

            // reserve space for last Rip address
            // mov rax, constant
            codeSiteCode[ptr++] = 0x48;
            codeSiteCode[ptr++] = 0xB8;
            var smcLastRip = ptr;
            ptr += 8;

            // lea rax, [rip-7-8]
            codeSiteCode[ptr++] = 0x48;
            codeSiteCode[ptr++] = 0x8D;
            codeSiteCode[ptr++] = 0x05;
            codeSiteCode[ptr++] = 0xF1;
            codeSiteCode[ptr++] = 0xFF;
            codeSiteCode[ptr++] = 0xFF;
            codeSiteCode[ptr++] = 0xFF;

            // mov rcx, [rax]
            codeSiteCode[ptr++] = 0x48;
            codeSiteCode[ptr++] = 0x8B;
            codeSiteCode[ptr++] = 0x08;

            // inc rcx
            codeSiteCode[ptr++] = 0x48;
            codeSiteCode[ptr++] = 0xFF;
            codeSiteCode[ptr++] = 0xC1;

            // xchg [rax], rcx
            codeSiteCode[ptr++] = 0x48;
            codeSiteCode[ptr++] = 0x87;
            codeSiteCode[ptr++] = 0x08;

            // find return address
            // mov rbx, [rbp+8]
            codeSiteCode[ptr++] = 0x48;
            codeSiteCode[ptr++] = 0x8B;
            codeSiteCode[ptr++] = 0x5D;
            codeSiteCode[ptr++] = 0x08;

            // call pastEndCode
            codeSiteCode[ptr++] = 0xE8;
            var callPastEndCodeImmediate = ptr;
            ptr += 4;
            var callPastEndCodeBaseOffset = ptr;

            // END FUNCTION

            // put new patch in place          
            // mov rax, constant
            codeSiteCode[ptr++] = 0x48;
            codeSiteCode[ptr++] = 0xB8;
            foreach (var b in patchSiteCode.Skip(0).Take(8)) {
                codeSiteCode[ptr++] = b;
            }

            // restore patch site 1
            // mov [rbx], rax
            codeSiteCode[ptr++] = 0x48;
            codeSiteCode[ptr++] = 0x89;
            codeSiteCode[ptr++] = 0x03;

            // mov rax, constant
            codeSiteCode[ptr++] = 0x48;
            codeSiteCode[ptr++] = 0xB8;
            foreach (var b in patchSiteCode.Skip(8).Take(8)) {
                codeSiteCode[ptr++] = b;
            }

            // restore patch site 2
            // mov [rbx+8], rax
            codeSiteCode[ptr++] = 0x48;
            codeSiteCode[ptr++] = 0x89;
            codeSiteCode[ptr++] = 0x43;
            codeSiteCode[ptr++] = 0x08;

            // mov rax, constant
            codeSiteCode[ptr++] = 0x48;
            codeSiteCode[ptr++] = 0xB8;
            foreach (var b in patchSiteCode.Skip(16).Take(8)) {
                codeSiteCode[ptr++] = b;
            }

            // restore patch site 3
            // mov [rbx+16], rax
            codeSiteCode[ptr++] = 0x48;
            codeSiteCode[ptr++] = 0x89;
            codeSiteCode[ptr++] = 0x43;
            codeSiteCode[ptr++] = 0x10;
            
            // end put new patch in place

            // mov rax,[rbp+16]
            codeSiteCode[ptr++] = 0x48;
            codeSiteCode[ptr++] = 0x8B;
            codeSiteCode[ptr++] = 0x45;
            codeSiteCode[ptr++] = 0x10;
            
            // pop rdx
            codeSiteCode[ptr++] = 0x5A;
            // pop rcx
            codeSiteCode[ptr++] = 0x59;
            // pop rbx
            codeSiteCode[ptr++] = 0x5B;
            // pop flags
            codeSiteCode[ptr++] = 0x9D;
            // pop rbp
            codeSiteCode[ptr++] = 0x5D;
            // ret 8
            codeSiteCode[ptr++] = 0xC2;
            codeSiteCode[ptr++] = 0x08;
            codeSiteCode[ptr++] = 0x00;

            codeSiteCode[callPastEndCodeImmediate] = (byte) (ptr - callPastEndCodeBaseOffset);

            // imul rcx,rcx,constant
            codeSiteCode[ptr++] = 0x48;
            codeSiteCode[ptr++] = 0x6B;
            codeSiteCode[ptr++] = 0xC9;
            // = size of restore function
            var multiplyImmediate = ptr;
            codeSiteCode[ptr++] = 0x00;

            // lea rcx, rcx+eax+constant
            codeSiteCode[ptr++] = 0x48;
            codeSiteCode[ptr++] = 0x8D;
            codeSiteCode[ptr++] = 0x4C;
            codeSiteCode[ptr++] = 0x08;
            var leaRcxConstant = ptr;
            codeSiteCode[ptr++] = 0x00;

            // jmp rcx
            codeSiteCode[ptr++] = 0xFF;
            codeSiteCode[ptr++] = 0xE1;

            codeSiteCode[leaRcxConstant] = (byte)(ptr - smcLastRip);

            // restore function
            uint offset = 0;
            var lastReturn = 0;
            foreach (var instr in decodedInstructions.Select((value, index) => new { Value = value, Index = index })) {
                var startOfRestore = ptr;

                Console.WriteLine($"instruction {instr.Value.Mnemonic}, size: {instr.Value.Size}");
                // reserve space for call site restore 1
                // mov rax, constant
                codeSiteCode[ptr++] = 0x48;
                codeSiteCode[ptr++] = 0xB8;
                var originalOffset = 0;
                var patchOffset = 0;
                foreach (var b in originalCode.Skip((int) offset).Take(8)) {
                    if (originalOffset < instr.Value.Size) {
                        codeSiteCode[ptr++] = b;
                    } else {
                        codeSiteCode[ptr++] = patchSiteCode[patchOffset++];
                    }
                    originalOffset++;
                }

                // restore call site 1
                // mov [rbx], rax
                codeSiteCode[ptr++] = 0x48;
                codeSiteCode[ptr++] = 0x89;
                codeSiteCode[ptr++] = 0x03;

                // reserve space for call site restore 2
                // mov rax, constant
                codeSiteCode[ptr++] = 0x48;
                codeSiteCode[ptr++] = 0xB8;
                foreach (var b in originalCode.Skip((int)offset + 8).Take(8)) {
                    if (originalOffset < instr.Value.Size) {
                        codeSiteCode[ptr++] = b;
                    }
                    else {
                        codeSiteCode[ptr++] = patchSiteCode[patchOffset++];
                    }
                    originalOffset++;
                }

                // restore call site 2
                // mov [rbx+8], rax
                codeSiteCode[ptr++] = 0x48;
                codeSiteCode[ptr++] = 0x89;
                codeSiteCode[ptr++] = 0x43;
                codeSiteCode[ptr++] = 0x08;

                // reserve space for call site restore 3
                // mov rax, constant
                codeSiteCode[ptr++] = 0x48;
                codeSiteCode[ptr++] = 0xB8;
                foreach (var b in originalCode.Skip((int)offset + 16).Take(8)) {
                    if (originalOffset < instr.Value.Size) {
                        codeSiteCode[ptr++] = b;
                    }
                    else {
                        codeSiteCode[ptr++] = patchSiteCode[patchOffset++];
                    }
                    originalOffset++;
                }

                // restore call site 3
                // mov [rbx+16], rax
                codeSiteCode[ptr++] = 0x48;
                codeSiteCode[ptr++] = 0x89;
                codeSiteCode[ptr++] = 0x43;
                codeSiteCode[ptr++] = 0x10;

                // prepare rbx to put new patch in place
                // add rbx,instrSize
                codeSiteCode[ptr++] = 0x48;
                codeSiteCode[ptr++] = 0x83;
                codeSiteCode[ptr++] = 0xC3;
                codeSiteCode[ptr++] = (byte) (instr.Value.Size);

                // return
                lastReturn = ptr;
                codeSiteCode[ptr++] = 0xC3;
                var endOfRestore = ptr;

                Console.WriteLine($"mul: {endOfRestore - startOfRestore}");
                codeSiteCode[multiplyImmediate] = (byte) (endOfRestore - startOfRestore);

                offset += instr.Value.Size;
            }

            ptr = lastReturn;
            
            // we set rbx to bogus so that patch is not written for last instruction in set
            // mov rbx, constant
            codeSiteCode[ptr++] = 0x48;
            codeSiteCode[ptr++] = 0xBB;
            foreach (var b in BitConverter.GetBytes((ulong) bogusAddress)) {
                codeSiteCode[ptr++] = b;
            }

            // return
            codeSiteCode[ptr] = 0xC3;

            DebugProcessUtils.WriteBytes(process, (ulong) codeAddress, codeSiteCode);
            DebugProcessUtils.WriteBytes(process, patchSite, patchSiteCode);
        }

        public class OldState {
            public Win32Imports.ContextX64 OldContext;
            public diStorm.DecodedInst OldInstruction;
        }

        public static void TraceIt(Process process, ulong patchSite, Logger logger, bool debug = true) {
            if (debug) {
                if (!Win32Imports.DebugActiveProcess(process.Id)) {
                    throw new Win32Exception();
                }

                if (!Win32Imports.DebugSetProcessKillOnExit(false)) {
                    throw new Win32Exception();
                }
            }
            foreach (ProcessThread thread in process.Threads) {
                var threadId = thread.Id;
                var context = new Win32Imports.ContextX64();
                ContextManager.getRip((uint) threadId, ref context, ContextManager.GetRipAction.ActionSuspend);
            }

            InstallTracer(process, patchSite, logger);

            var mainThread = 0;

            foreach (ProcessThread thread in process.Threads) {
                var threadId = thread.Id;
                var context = new Win32Imports.ContextX64();
                var breakAddress = ContextManager.getRip((uint)threadId, ref context, ContextManager.GetRipAction.ActionGetContext);
                var diff = new BigInteger(breakAddress) - new BigInteger(patchSite);
                diff = diff < 0 ? -diff : diff;
                if (diff < 1000) {
                    mainThread = threadId;
                    logger.WriteLine($"thread {threadId} setting Rip to patch site: {patchSite:X}");
                    ContextManager.setRip((uint)threadId, false, patchSite);
                    if (debug) {
                        ContextManager.setTrace((uint)threadId, false);
                    }
                }
                ContextManager.getRip((uint)threadId, ref context, ContextManager.GetRipAction.ActionResume);
            }

            /*if (!Win32Imports.DebugBreakProcess(process.Id)) {
                throw new Win32Exception();
            }*/

            if (debug) {
                Dictionary<int, OldState> oldThreadState = new Dictionary<int, OldState>();
                try {
                    while (true)
                    {
                        Win32Imports.DebugEvent evt;
                        if (Win32Imports.WaitForDebugEvent(out evt, -1)) {
                            Console.WriteLine($"debug event {evt.dwDebugEventCode}");
                            var continueCode = Win32Imports.DbgContinue;
                            if (evt.dwDebugEventCode == Win32Imports.DebugEventType.ExceptionDebugEvent && evt.dwThreadId == mainThread) {
                                var exceptionAddress = (ulong)evt.Exception.ExceptionRecord.ExceptionAddress.ToInt64();
                                var context = new Win32Imports.ContextX64();
                                var breakAddress = ContextManager.getRip((uint)evt.dwThreadId, ref context, ContextManager.GetRipAction.ActionGetContext);
                                var code = evt.Exception.ExceptionRecord.ExceptionCode;
                                Console.WriteLine($"thread {evt.dwThreadId} break at 0x{exceptionAddress:X} code {code}, 0x{breakAddress:X}");
                                ContextManager.setTrace((uint)evt.dwThreadId);

                                var instr = AsmUtil.Disassemble(process, exceptionAddress);
                                var asm = AsmUtil.FormatInstruction(instr);
                                var strContext = oldThreadState.ContainsKey(evt.dwThreadId) ? 
                                    AsmUtil.FormatContextDiff(context, oldThreadState[evt.dwThreadId].OldContext, oldThreadState[evt.dwThreadId].OldInstruction) : 
                                    AsmUtil.FormatContext(context);
                                logger.WriteLine($"thread {evt.dwThreadId} break at 0x{exceptionAddress:X}, 0x{breakAddress:X} code {code}: {asm}, regs-1: {strContext}");

                                oldThreadState[evt.dwThreadId] = new OldState {
                                    OldContext = context,
                                    OldInstruction = instr
                                };

                                if (code == Win32Imports.ExceptionCodeStatus.ExceptionAccessViolation) {
                                    continueCode = Win32Imports.DbgExceptionNotHandled;
                                }
                            }

                            if (!Win32Imports.ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, continueCode)) {
                                throw new Win32Exception();
                            }
                        }
                    }
                }
                finally {
                    if (!Win32Imports.DebugActiveProcessStop(process.Id)) {
                        throw new Win32Exception();
                    }
                }
            }
        }
    }
}
