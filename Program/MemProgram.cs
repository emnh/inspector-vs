namespace Program {
    class MemProgram {

/*
        private static string PtrToStringUtf8(IntPtr ptr) // aPtr is nul-terminated
        {
            if (ptr == IntPtr.Zero)
                return "";
            int len = 0;
            while (System.Runtime.InteropServices.Marshal.ReadByte(ptr, len) != 0)
                len++;
            if (len == 0)
                return "";
            byte[] array = new byte[len];
            System.Runtime.InteropServices.Marshal.Copy(ptr, array, 0, len);
            return System.Text.Encoding.UTF8.GetString(array);
        }
*/

        public static void Main() {
            var process = DebugProcessUtils.GetFirstProcessByName(Specifics.ProcessName);

            using (var logger = new Logger(Specifics.LogName, Specifics.LogNameLatest)) {

                ImportResolver ir = new ImportResolver(process);

                MemScan.MemModuleScan(process, ir);
                //MemScan.MemMain(process, ir);
                //Analyze(process);

                var patchSite = Specifics.GetPatchSite(ir);

                logger.WriteLine($"patch site: {patchSite:X}");
                //SimpleMemTracer.TraceIt(process, patchSite, logger, false);
            }
        /*
        var code = (ulong) traceState.codeAddress;

        while (true) {
            foreach (var instr in ASMUtil.DisassembleMany(process, code, 20)) {
                logger.WriteLine($"{instr.Offset}: " + ASMUtil.FormatInstruction(instr));
            }

            logger.WriteLine($"code address: 0x{(ulong)traceState.codeAddress:X}");

            Console.ReadKey();
        }
        */
    }
        
    }
}
