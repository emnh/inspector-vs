using System.IO;

namespace Program {
    public class Specifics {

#if DEBUG
        public const string ProcessName = "DebugTest";
        public const string TraceModuleName = "DebugTest.exe";
#else
        public const string ProcessName = "x64";
        public const string TraceModuleName = "x64.exe";
#endif

#if DEBUG
        public static ImportResolver.RelativeAddress StartAddress =
            new ImportResolver.RelativeAddress()
            {
                ModuleName = TraceModuleName,
                AddressOffset = (0x7FF6222D17C0 - 0x7FF6222C0000)
            };
#else
        // public const ulong startAddress = 0x7FF762EE437C;
        public static ImportResolver.RelativeAddress StartAddress =
             new ImportResolver.RelativeAddress() {
                ModuleName = TraceModuleName,
                //addressOffset = 0x61437C
                AddressOffset = 0x614FDC
            };
#endif

        public static ulong GetPatchSite(ImportResolver ir) {
#if DEBUG
                return 0x00007FF6222D17F6; // (ulong) process.MainModule.EntryPointAddress + Specifics.startAddress.addressOffset;
#else
            return ir.ResolveRelativeAddress(Specifics.StartAddress);
#endif 
        }
        public const int MainLoopDelay = 100;
        public const int LoopWaitInterval = 100;
        public const int TraceInterval = 100;
        public const int WaitInterval = 100;

        public static string BasePath = Path.Combine(@"C:\dev\probe-wars\data", ProcessName);

        public static string LogName = Path.Combine(BasePath, @"exec-log.txt");
        public static string LogNameLatest = Path.Combine(BasePath, @"exec-latest.txt");
        public static string AppStateFileName = Path.Combine(BasePath, @"app-state.xml");

        public static string RawRegionsDumpFileName = Path.Combine(BasePath, @"raw-regions.txt");
        public static string FunctionsRegionsDumpFileName = Path.Combine(BasePath, @"function-regions.txt");
        public static string ModuleRegionsDumpFileName = Path.Combine(BasePath, @"module-regions.txt");
        public static string AsmDumpFileName = Path.Combine(BasePath, TraceModuleName + @"-asm-dump.txt");
        public static string WriteAsmSizesDumpFileName = Path.Combine(BasePath, TraceModuleName + @"-asm-sizes-write.bin");
        public static string ReadAsmSizesDumpFileName = Path.Combine(BasePath, TraceModuleName + @"-asm-sizes-read.bin");
        public static string PatchAsmDumpFileName = Path.Combine(BasePath, @"patch-asm-dump-filename.txt");

        static Specifics() {
            Directory.CreateDirectory(BasePath);
        }
    }
}