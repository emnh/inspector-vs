namespace Program {
    class MemProgram {

        public static void Main() {
            var process = DebugProcessUtils.GetFirstProcessByName(Specifics.ProcessName);

            using (var logger = new Logger(Specifics.LogName, Specifics.LogNameLatest)) {

                ImportResolver ir = new ImportResolver(process);

                //MemScan.MemModuleScan(process, ir);
                MemScan.MemMain(process, ir, true);
                //Analyze(process);

                var patchSite = Specifics.GetPatchSite(ir);

                logger.WriteLine($"patch site: {patchSite:X}");
                SimpleMemTracer.TraceIt(process, patchSite, logger, false, AdvancedMemTracer.InstallTracer);
            }
        }
    }
}
