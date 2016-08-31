using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Numerics;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using SharpDisasm;
using static Program.Win32Imports;

namespace Program {
    public class MemScan {

        public static List<ulong> LookForByteArray(Process process, ImportResolver ir, byte[] toLookFor) {
            var matches = new List<ulong>();
            foreach (ProcessModule mod in process.Modules) {
                if (mod.ModuleName.Equals(Specifics.TraceModuleName)) {
                    byte[] mem;
                    try {
                        mem = DebugProcessUtils.ReadBytes(process, (ulong) mod.BaseAddress, mod.ModuleMemorySize);
                    } catch {
                        throw new Exception("could not read process main module memory");
                    }
                    for (var i = 0; i < mem.Length; i++) {
                        var equal = true;
                        for (var j = 0; j < toLookFor.Length; j++) {
                            if (mem[i + j] != toLookFor[j]) {
                                equal = false;
                                break;
                            }
                        }
                        if (equal) {
                            matches.Add((ulong) mod.BaseAddress + (ulong) i);
                        }
                    }
                    break;
                }
            }
            return matches;
        }

        public static void MemModuleScan(Process process, ImportResolver ir) {
            using (StreamWriter sw = new StreamWriter(Specifics.FunctionsRegionsDumpFileName),
                                sw2 = new StreamWriter(Specifics.ModuleRegionsDumpFileName)) {
                // option 1: scan all functions separately
                var totalSize = ScanFunctions(process, ir, sw);

                // options 2: scan all modules separately
                ProcessModule traceModule;
                byte[] traceMemory;
                var totalSize2 = ScanModules(process, sw2, out traceModule, out traceMemory);

                // dump the main module to asm file
                if (traceModule == null) {
                    Console.WriteLine("could not locate trace module, no dump generated");
                } else {
                    DumpAssembly(traceMemory);
                }

                Console.WriteLine($"total functions size: {totalSize/1024/1024} MiB");
                Console.WriteLine($"total modules size: {totalSize2/1024/1024} MiB");
            }
        }

        private static int ScanFunctions(Process process, ImportResolver ir, StreamWriter sw) {
            var totalSize = 0;
            foreach (var mi in ir.ModuleFunctions) {
                var result = "success";
                try {
                    DebugProcessUtils.ReadBytes(process, mi.Address, (int) mi.Size);
                    totalSize += (int) mi.Size;
                }
                catch {
                    result = "failed";
                }
                sw.WriteLine($"function: {mi.Module.ModuleName}.{mi.FunctionName}, size: {mi.Size} result: {result}");
            }
            return totalSize;
        }

        private static int ScanModules(Process process, StreamWriter sw, out ProcessModule traceModule,
            out byte[] traceMemory) {
            var totalSize2 = 0;
            traceModule = null;
            traceMemory = new byte[] {};
            foreach (ProcessModule mod in process.Modules) {
                if (mod.ModuleName.Equals(Specifics.TraceModuleName)) {
                    traceModule = mod;
                }
                var result = "success";
                try {
                    var mem = DebugProcessUtils.ReadBytes(process, (ulong) mod.BaseAddress, mod.ModuleMemorySize);
                    if (mod.ModuleName.Equals(Specifics.TraceModuleName)) {
                        Console.WriteLine($"mem: {mem.Length}");
                        traceMemory = mem;
                    }
                    totalSize2 += mod.ModuleMemorySize;
                } catch {
                    result = "failed";
                }
                sw.WriteLine($"module: {mod.ModuleName}, size: {mod.ModuleMemorySize} result: {result}");
            }
            sw.Close();
            return totalSize2;
        }

        [HandleProcessCorruptedStateExceptions]
        private static void DumpAssembly(byte[] traceMemory) {
            BigInteger oldProgress = 0;
            var subRange = new byte[AssemblyUtil.MaxInstructionBytes];
            using (StreamWriter sw2 = new StreamWriter(Specifics.AsmDumpFileName)) {
                using (FileStream asmSizesFs = new FileStream(Specifics.WriteAsmSizesDumpFileName, FileMode.Create)) {
                    using (BinaryWriter asmSizesBw = new BinaryWriter(asmSizesFs)) {
                        StreamWriter asmBranchesNasm = null;

                        for (ulong i = 0; i < (ulong)traceMemory.Length; i++) {
                            ulong instructionsPerFile = 50000;
                            if (i % instructionsPerFile == 0) {
                                asmBranchesNasm?.Close();
                                asmBranchesNasm = new StreamWriter(Specifics.WriteAsmBranchNasmDumpFileName + $"{(i / instructionsPerFile):D8}.asm");
                                asmBranchesNasm.Write(@"BITS 64
; %idefine rip rel $+(.next-.prev)
");
                            }
                            if (asmBranchesNasm == null) {
                                throw new Exception("shouldn't happen");
                            }

                            Array.Copy(traceMemory, (int)i, subRange, 0,
                                (int)Math.Min(AssemblyUtil.MaxInstructionBytes, (ulong)traceMemory.Length - i));
                            var progress = new BigInteger(i) * 100 / traceMemory.Length;
                            //Console.WriteLine($"progress: {progress}");

                            if (progress != oldProgress) {
                                Console.WriteLine($"decoding asm, progress: {progress}");
                            }
                            oldProgress = progress;

                            byte instructionLength = 0;

                            Instruction instruction = null;
                            try {
                                instruction = AssemblyUtil.Disassemble(subRange);
                                instructionLength = (byte) instruction.Length;
                            } catch (IndexOutOfRangeException) {
                                // ignore
                                sw2.WriteLine("SharpDisasm: failed with IndexOutOfRangeException");
                            } catch (DecodeException) {
                                // ignore
                                sw2.WriteLine("SharpDisasm: failed with DecodeException");
                            }

                            string asm;
                            bool toStringWorked = false;
                            try {
                                asm = instruction?.ToString();
                                toStringWorked = true;
                            } catch (IndexOutOfRangeException) {
                                asm = "IndexOutOfRangeException";
                            }

                            asmBranchesNasm.WriteLine($"instr{i}:");
                            asmBranchesNasm.WriteLine(".prev:");
                            if (toStringWorked &&
                                instruction != null &&
                                AssemblyUtil.IsNasmValid(instruction, asm)) {

                                var maybeJump = BranchRewriteSimple.IsBranch(instruction);

                                sw2.WriteLine($"{i:X}: {asm}");

                                if (maybeJump.Present) {
                                    asmBranchesNasm.WriteLine($"db 0x{(byte) maybeJump.RipEquals:X2}");
                                    asmBranchesNasm.WriteLine($"{maybeJump.AddBranchOfSameType(".setrip")}");
                                    asmBranchesNasm.WriteLine("jmp .next");
                                    asmBranchesNasm.WriteLine(".setrip:");
                                    foreach (var s in maybeJump.AddInstrToGetBranchTarget()) {
                                        asmBranchesNasm.WriteLine(s);
                                    }
                                } else {
                                    // flags
                                    var freeRegister = BranchRewriteSimple.FindFreeRegister(asm);
                                    string ripRegister = freeRegister.ToString().ToLower();
                                    asm = asm.Replace("rip", ripRegister);
                                    asmBranchesNasm.WriteLine($"db 0x{(byte) freeRegister:X2}");
                                    asmBranchesNasm.WriteLine(asm);
                                }
                            } else {
                                asmBranchesNasm.WriteLine("; failed to decode");
                                // flags
                                asmBranchesNasm.WriteLine("db 0xFF");
                                asmBranchesNasm.WriteLine("db " + AssemblyUtil.BytesToHexZeroX(subRange, ","));
                            }
                            asmBranchesNasm.WriteLine(".next:");
                            asmBranchesNasm.WriteLine($"%if {AssemblyUtil.MaxBranchBytes}-(.next-.prev) < 0");
                            asmBranchesNasm.WriteLine("%error Not enough space allocated");
                            asmBranchesNasm.WriteLine("%endif");
                            asmBranchesNasm.WriteLine($"times {AssemblyUtil.MaxBranchBytes}-(.next-.prev) nop");
                            asmBranchesNasm.WriteLine("");

                            asmSizesBw.Write(instructionLength);
                        }
                        asmBranchesNasm?.Close();
                    }
                }
            }
        }

        public static void MemMain(Process process, ImportResolver ir, bool setPageExecuteReadWrite = false) {
            // getting minimum & maximum address

            SystemInfo sysInfo;
            GetSystemInfo(out sysInfo);

            var procMinAddress = sysInfo.minimumApplicationAddress;
            var procMaxAddress = sysInfo.maximumApplicationAddress;

            // saving the values as long ints so I won't have to do a lot of casts later
            var procMinAddressL = (ulong) procMinAddress;
            var procMaxAddressL = (ulong) procMaxAddress;

            // opening the process with desired access level
            // IntPtr processHandle = OpenProcess(ProcessAccessFlags.QueryInformation | ProcessAccessFlags.VirtualMemoryRead, false, process.Id);
            var processHandle = OpenProcess(ProcessAccessFlags.All, false, process.Id);

            if ((ulong) processHandle == 0) {
                throw new Win32Exception();
            }

            var sw = new StreamWriter(Specifics.RawRegionsDumpFileName);

            // this will store any information we get from VirtualQueryEx()

            var bytesRead = new IntPtr(0); // number of bytes read with ReadProcessMemory
            ulong totalBytesRead = 0;

            // expect 4 gig
            var progressTotal = new BigInteger(1024*1024*1024);
            progressTotal *= 4;
            BigInteger lastProgress = 0;

            Console.WriteLine("start scanning");
            while (procMinAddressL < procMaxAddressL) {
                // 28 = sizeof(MEMORY_BASIC_INFORMATION)
                MemoryBasicInformation memBasicInfo;
                if (
                    (ulong)
                        VirtualQueryEx(processHandle, procMinAddress, out memBasicInfo,
                            new IntPtr(Marshal.SizeOf(typeof(MemoryBasicInformation)))) == 0) {
                    throw new Win32Exception();
                }

                if (setPageExecuteReadWrite) {
                    AllocationProtectEnum oldProtection;
                    if (
                        !VirtualProtectEx(processHandle, memBasicInfo.BaseAddress,
                            new UIntPtr((ulong)memBasicInfo.RegionSize),
                            AllocationProtectEnum.PageExecuteReadwrite, out oldProtection)) {
                        //throw new Win32Exception();
                    }
                }

                var regionStartModule = ir.LookupAddress((ulong) memBasicInfo.BaseAddress);
                var regionEndModule =
                    ir.LookupAddress((ulong) memBasicInfo.BaseAddress + (ulong) memBasicInfo.RegionSize);

                var isAccessible = memBasicInfo.Protect.HasFlag(AllocationProtectEnum.PageReadwrite) ||
                                   memBasicInfo.Protect.HasFlag(AllocationProtectEnum.PageExecuteReadwrite);

                if (isAccessible && memBasicInfo.State.HasFlag(StateEnum.MemCommit)) {
                    var buffer = new byte[(ulong) memBasicInfo.RegionSize];

                    // read everything in the buffer above
                    var success = "";
                    if (
                        !ReadProcessMemory(processHandle, memBasicInfo.BaseAddress, buffer, memBasicInfo.RegionSize,
                            ref bytesRead)) {
                        success = "false";
                    }
                    else {
                        totalBytesRead += (ulong) bytesRead;
                    }

                    var regionStart = memBasicInfo.BaseAddress.ToString("X");
                    var regionEnd = ((ulong) memBasicInfo.BaseAddress + (ulong) memBasicInfo.RegionSize).ToString("X");
                    sw.WriteLine(
                        $"region 0x{regionStart}({regionStartModule})-0x{regionEnd}({regionEndModule}): size {memBasicInfo.RegionSize}: {success}");
                    // then output this in the file
                    /*for (int i = 0; i < mem_basic_info.RegionSize; i++) {
                        //sw.WriteLine("0x{0} : {1}", (mem_basic_info.BaseAddress + i).ToString("X"), (char)buffer[i]);
                    }*/
                }
                else {
                    var regionStart = memBasicInfo.BaseAddress.ToString("X");
                    var regionEnd = ((ulong) memBasicInfo.BaseAddress + (ulong) memBasicInfo.RegionSize).ToString("X");
                    sw.WriteLine(
                        $"NOT READ region 0x{regionStart}({regionStartModule})-0x{regionEnd}({regionEndModule}): size {memBasicInfo.RegionSize}");
                }

                // move to the next memory chunk
                procMinAddressL += (ulong) memBasicInfo.RegionSize;
                procMinAddress = new IntPtr((long) procMinAddressL);

                var progress = new BigInteger(totalBytesRead)*100/progressTotal;
                if (progress != lastProgress) {
                    Console.WriteLine($"scanning memory: estimated {progress}%, totalSize: ");
                }
                lastProgress = progress;
            }
            Console.WriteLine($"end scanning. total MB: {totalBytesRead/1024/1024}");

            sw.Close();
        }
    }
}