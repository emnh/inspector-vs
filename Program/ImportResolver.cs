using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace Program {
    public class ImportResolver {
        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymInitialize(IntPtr hProcess, string userSearchPath, [MarshalAs(UnmanagedType.Bool)]bool fInvadeProcess);

        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymCleanup(IntPtr hProcess);

        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern ulong SymLoadModuleEx(IntPtr hProcess, IntPtr hFile,
                string imageName, string moduleName, long baseOfDll, int dllSize, IntPtr data, int flags);

        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymEnumerateSymbols64(IntPtr hProcess,
            ulong baseOfDll, SymEnumerateSymbolsProc64 enumSymbolsCallback, IntPtr userContext);

        public delegate bool SymEnumerateSymbolsProc64(string symbolName,
                ulong symbolAddress, uint symbolSize, IntPtr userContext);

        public class RelativeAddress {
            public string ModuleName;
            public ulong AddressOffset;
        }

        public class ModuleAddressInfo {
            public ProcessModule Module;
            public string FunctionName;
            public ulong Address;
            public uint Size;
        }

        private readonly List<ulong> _addresses = new List<ulong>();
        private readonly Dictionary<ulong, string> _addressToFunction = new Dictionary<ulong, string>();
        private readonly Dictionary<string, ulong> _functionToAddress = new Dictionary<string, ulong>();
        private readonly string _currentModuleName = "";
        private readonly ProcessModule _currentModule;

        public List<ModuleAddressInfo> ModuleFunctions = new List<ModuleAddressInfo>();

        public bool EnumSyms(string name, ulong address, uint size, IntPtr context) {
            // XXX: note the inconsistency. different data structures for different purposes. should change the lookup function to filter out .EXE instead.
            if (!Regex.Match(_currentModuleName, "[Ee][Xx][Ee]$").Success) {
                _addresses.Add(address);
                var moduleAndFunction = _currentModuleName + ":" + name;
                _addressToFunction[address] = moduleAndFunction;
                _functionToAddress[moduleAndFunction] = address;
            }
            ModuleFunctions.Add(new ModuleAddressInfo {
                Module = _currentModule,
                FunctionName = name,
                Address = address,
                Size = size
            });
            return true;
        }

        public ulong ResolveRelativeAddress(RelativeAddress address) {
            return _functionToAddress[address.ModuleName] + address.AddressOffset;
        }

        public ImportResolver(Process process) {
            IntPtr hCurrentProcess = process.Handle; //Process.GetCurrentProcess().Handle;

            // Initialize sym.
            // Please read the remarks on MSDN for the hProcess
            // parameter.
            var status = SymInitialize(hCurrentProcess, null, false);

            if (status == false) {
                Console.Out.WriteLine("Failed to initialize sym.");
                return;
            }

            foreach (ProcessModule module in process.Modules) {
                _currentModule = module;
                _currentModuleName = module.ModuleName;
                var baseAddress = (ulong)module.BaseAddress.ToInt64();
                _addresses.Add(baseAddress);
                _addressToFunction[baseAddress] = module.ModuleName;
                _functionToAddress[module.ModuleName] = baseAddress;

                if (Regex.Match(_currentModuleName, "[Ee][Xx][Ee]$").Success) {
                    // don't resolve imports for EXE files, usually too incomplete
                    // continue;
                }

                // Load dll.
                var baseOfDll = SymLoadModuleEx(hCurrentProcess,
                    IntPtr.Zero,
                    //"c:\\windows\\system32\\user32.dll",
                    module.FileName,
                    module.ModuleName,
                    module.BaseAddress.ToInt64(),
                    module.ModuleMemorySize,
                    IntPtr.Zero,
                    0);

                if (baseOfDll == 0) {
                    Console.Out.WriteLine($"Failed to load module: {module.FileName}");
                    SymCleanup(hCurrentProcess);

                    status = SymInitialize(hCurrentProcess, null, false);

                    if (status == false) {
                        Console.Out.WriteLine("Failed to initialize sym.");
                        return;
                    }
                    //return;
                }

                // Enumerate symbols. For every symbol the 
                // callback method EnumSyms is called.
                if (SymEnumerateSymbols64(hCurrentProcess,
                    baseOfDll, EnumSyms, IntPtr.Zero) == false) {
                    Console.Out.WriteLine("Failed to enum symbols.");
                }
            }

            // Cleanup.
            SymCleanup(hCurrentProcess);

            _addresses.Sort();
        }

        public Tuple<string, ulong> LookupAddress(ulong address) {
            var apiAddressIndex = _addresses.BinarySearch(address);
            if (apiAddressIndex < 0) {
                apiAddressIndex = ~apiAddressIndex;
                while (apiAddressIndex >= 0 && apiAddressIndex < _addresses.Count && _addresses[apiAddressIndex] > address) {
                    apiAddressIndex--;
                }
            }
            if (apiAddressIndex < 0 || apiAddressIndex >= _addresses.Count) {
                return new Tuple<string, ulong>("N/A", address);
            }
            var baseAddress = _addresses[apiAddressIndex];
            /*if (addressToFunction[baseAddress].ToLower().Contains(".exe")) {

            } else {

            }*/
            return new Tuple<string, ulong>(_addressToFunction[baseAddress], baseAddress);
        }

        public ulong LookupFunction(string moduleAndFunction) {
            return _functionToAddress[moduleAndFunction];
        }

        public void DumpDebug() {
            using (System.IO.StreamWriter logFile = new System.IO.StreamWriter(Specifics.ImportsDump)) {
                foreach (var address in _addresses) {
                    logFile.WriteLine($"{address:X}: {_addressToFunction[address]}");
                }
            }
        }
    }
}