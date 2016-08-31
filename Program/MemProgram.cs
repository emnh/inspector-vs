using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace Program {
    class MemProgram {

        public static void Main() {
            var process = DebugProcessUtils.GetFirstProcessByName(Specifics.ProcessName);

            // ReSharper disable once UnusedVariable
            using (var logger = new Logger(Specifics.LogName, Specifics.LogNameLatest)) {

                ImportResolver ir = new ImportResolver(process);

                ir.DumpDebug();

                var matches = MemScan.LookForByteArray(process, ir, Specifics.StartAddressBytes);
                foreach (var match in matches) {
                    Console.WriteLine($"byte array match at: 0x{match:X}");
                }
                if (matches.Count != 1) {
                    return;
                }

                MemScan.MemModuleScan(process, ir);

                // TraceMain(process, ir, matches, logger);
            }
        }

        public static void TraceMain(Process process, ImportResolver ir, List<ulong> matches, Logger logger) {
            MemScan.MemMain(process, ir, true);

            var patchSite = matches.First();

            var asmSizes = File.ReadAllBytes(Specifics.ReadAsmSizesDumpFileName);
            var branches = File.ReadAllBytes(Specifics.ReadAsmBranchDumpFileName);

            logger.WriteLine($"patch site: {patchSite:X}");
            EmulatedMemTracer.TraceState traceState = null;
            SimpleMemTracer.TraceIt(process, patchSite, logger, false,
                (x, y, z) => { traceState = EmulatedMemTracer.InstallTracer(x, y, z, ir, asmSizes, branches); });
            if (traceState != null) {
                // TODO: fix race
                var threadId = BitConverter.ToUInt32(DebugProcessUtils.ReadBytes(process, traceState.TraceLogAddress, 4), 0);
                Console.WriteLine($"thread id: {threadId:X}");
            }
        }
    }
}
