using System.IO;

namespace Program {
    public class Specifics {

#if DEBUG
        public const string ProcessName = "DebugTest";
        public const string TraceModuleName = "DebugTest.exe";
#else
        public const string ProcessName = "SC2_x64";
        public const string TraceModuleName = "SC2_x64.exe";
#endif

#if DEBUG
        public static ImportResolver.RelativeAddress StartAddress =
            new ImportResolver.RelativeAddress()
            {
                ModuleName = TraceModuleName,
                //AddressOffset = (0x7FF6222D17C0 - 0x7FF6222C0000)
                AddressOffset =  0x00007FF783CE17F6 - 0x7FF6222C0000
            };
        public static byte[] StartAddressBytes = {
            0x8B, 0x45, 0x24, 0xFF, 0xC0
        };
#else
        // public const ulong startAddress = 0x7FF762EE437C;
        public static ImportResolver.RelativeAddress StartAddress =
             new ImportResolver.RelativeAddress() {
                ModuleName = TraceModuleName,
                //addressOffset = 0x61437C
                AddressOffset = 0x614FDC
            };
        public static byte[] StartAddressBytes = {
            0x89, 0x77, 0x60, 0x48, 0x8B, 0x74, 0x24, 0x40
        };
#endif

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
        public static string PatchAsmDumpFileName = Path.Combine(BasePath, @"patch-asm-dump.txt");
        public static string ImportsDump = Path.Combine(BasePath, @"imports.txt");
        public static string WriteAsmBranchDumpFileName = Path.Combine(BasePath, TraceModuleName + @"-asm-branches-write.bin");
        public static string ReadAsmBranchDumpFileName = Path.Combine(BasePath, TraceModuleName + @"-asm-branches-read.bin");
        public static string WriteAsmBranchNasmDumpFileName = Path.Combine(BasePath, TraceModuleName + @"-asm-branches-write.asm");

        static Specifics() {
            Directory.CreateDirectory(BasePath);
        }
    }
}