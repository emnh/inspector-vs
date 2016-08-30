using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using AsmJit.AssemblerContext;
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

        private static void DumpAssembly(byte[] traceMemory) {
            BigInteger oldProgress = 0;
            var subRange = new byte[AsmUtil.MaxInstructionBytes];
            using (var sw2 = new StreamWriter(Specifics.AsmDumpFileName)) {
                using (FileStream asmSizesFs = new FileStream(Specifics.WriteAsmSizesDumpFileName, FileMode.Create),
                                  asmBranchesFs = new FileStream(Specifics.WriteAsmBranchDumpFileName, FileMode.Create)) {
                    using (BinaryWriter asmSizesBw = new BinaryWriter(asmSizesFs),
                        asmBranchesBw = new BinaryWriter(asmBranchesFs)) {
                        for (ulong i = 0; i < (ulong)traceMemory.Length; i++) {
                            Array.Copy(traceMemory, (int)i, subRange, 0,
                                (int)Math.Min(AsmUtil.MaxInstructionBytes, (ulong)traceMemory.Length - i));
                            var progress = new BigInteger(i) * 100 / traceMemory.Length;
                            //Console.WriteLine($"progress: {progress}");

                            if (progress != oldProgress) {
                                Console.WriteLine($"decoding asm, progress: {progress}");
                            }
                            oldProgress = progress;

                            byte instructionLength = 0;
                            byte[] paddedCbytes = new byte[AsmUtil.MaxBranchBytes];

                            Instruction instruction = null;
                            try {
                                instruction = AsmUtil.Disassemble(subRange);
                            } catch (IndexOutOfRangeException) {
                                // ignore
                                sw2.WriteLine("SharpDisasm: failed with IndexOutOfRangeException");
                            } catch (DecodeException) {
                                // ignore
                                sw2.WriteLine("SharpDisasm: failed with DecodeException");
                            }

                            if (instruction != null) {
                                instructionLength = (byte)instruction.Length;
                                //var ops = string.Join(",", instruction.Operands.Select(x => x.Index));
                                //var ops2 = string.Join(",", instruction.Operands.Select(x => x.Base));
                                //sw2.WriteLine($"{i:X}: {instruction} OPS: {ops}, OPS2: {ops2}");
                                // sw2.WriteLine($"PREWRITE {i:X}: {instruction}");
                                var maybeJump = AsmUtil.IsBranch(instruction);
                                if (maybeJump.Present) {
                                    List<Instruction> asmSame = new List<Instruction>();

                                    WriteBranchData(maybeJump, instruction, paddedCbytes, asmSame, sw2);

                                    sw2.WriteLine($"{i:X}: {instruction}");
                                    foreach (var instr in asmSame) {
                                        var hex =
                                            AsmUtil.BytesToHex(
                                                paddedCbytes.Skip((int)instr.Offset)
                                                    .Take(instr.Length)
                                                    .ToArray());
                                        sw2.WriteLine($"{instr.Offset:X}: {hex} {instr}");
                                    }
                                    sw2.WriteLine("");
                                } else {
                                    for (var j = 0; j < paddedCbytes.Length; j++) {
                                        paddedCbytes[j] = 0;
                                    }
                                }
                            }
                            asmSizesBw.Write(instructionLength);
                            asmBranchesBw.Write(paddedCbytes);
                        }
                    }
                }
            }
        }

        [HandleProcessCorruptedStateExceptions]
        private static void WriteBranchData(MaybeJump maybeJump, Instruction instruction, byte[] paddedCbytes, List<Instruction> asmSame, StreamWriter sw2) {
            if (maybeJump.AddBranchOfSameType != null &&
                maybeJump.AddInstrToGetBranchTarget != null) {
                byte[] cbytes = null;

                // asmjit fails randomly with memory errors, so give it some tries
                // TODO: locate their bug and submit a patch
                var maxTryCount = 3;
                for (var tryCount = 0; tryCount < maxTryCount; tryCount++) {
                    var c = Assembler.CreateContext<Action>();
                    var label = c.Label();
                    var finishLabel = c.Label();
                    maybeJump.AddBranchOfSameType(c, label);
                    c.Jmp(finishLabel);
                    c.Bind(label);
                    maybeJump.AddInstrToGetBranchTarget(c, c.Rax);
                    c.Bind(finishLabel);

                    try {
                        cbytes = AsmUtil.GetAsmJitBytes(c);
                        break;
                    }
                    catch (Exception) {
                        if (tryCount + 1 == maxTryCount) {
                            throw new Exception($"failed to handle: {instruction}");
                        }
                        //error = $"failed to get bytes 1 on try {tryCount}";
                    }
                }

                if (cbytes != null) {
                    if (cbytes.Length > paddedCbytes.Length) {
                        throw new Exception(
                            $"miscalculated max size: {nameof(AsmUtil.MaxBranchBytes)}: {AsmUtil.MaxBranchBytes} < {cbytes.Length}");
                    }
                    Array.Copy(cbytes, paddedCbytes, cbytes.Length);
                    for (int j = cbytes.Length; j < paddedCbytes.Length; j++) {
                        paddedCbytes[j] = AsmUtil.Nop;
                    }

                    try {
                        foreach (var instr in AsmUtil.DisassembleMany(paddedCbytes, 100)
                            ) {
                            asmSame.Add(instr);
                        }
                    }
                    catch (DecodeException) {
                        sw2.WriteLine("decode failed: " + AsmUtil.BytesToHex(cbytes));
                        throw new Exception("decode failed: " +
                                            AsmUtil.BytesToHex(cbytes));
                    }
                }
                else {
                    throw new Exception("shouldn't happen");
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