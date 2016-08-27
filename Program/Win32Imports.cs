using System;
using System.Runtime.InteropServices;

namespace Program {
    public class Win32Imports {

        public enum ExceptionCodeStatus : uint {
            ExceptionBreakpoint = 0x80000003,
            ExceptionSingleStep = 0x80000004,
            ExceptionInvalidHandle = 0xC0000008,
            ExceptionInvalidOperation = 0xC000001D,
            ExceptionAccessViolation = 0xC0000005
        }

        public const uint DbgContinue = 0x00010002;
        public const uint DbgExceptionNotHandled = 0x80010001;

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, AllocationProtectEnum flNewProtect, out AllocationProtectEnum lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int ResumeThread(IntPtr hThread);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int SuspendThread(IntPtr hThread);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(ThreadAccessFlags dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern bool DebugActiveProcess(int dwProcessId);
        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern bool DebugBreakProcess(int dwProcessId);
        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern bool DebugActiveProcessStop(int dwProcessId);
        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern bool DebugSetProcessKillOnExit(bool killOnExit);
        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern bool WaitForDebugEvent([Out] out DebugEvent lpDebugEvent, int dwMilliseconds);
        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern bool ContinueDebugEvent(int dwProcessId, int dwThreadId, uint dwContinueStatus);
        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern bool IsDebuggerPresent();
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetThreadContext(IntPtr hThread, ref ContextX64 lpContext);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetThreadContext(IntPtr hThread, ref ContextX64 lpContext);

        [Flags]
        public enum AllocationType {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum MemoryProtection {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        [StructLayout(LayoutKind.Sequential, Pack=8)]
        public unsafe struct DebugEvent {
            public readonly DebugEventType dwDebugEventCode;
            public readonly int dwProcessId;
            public readonly int dwThreadId;

            // Pack 8 and IntPtr puts this at offset 16, not 12, like in the C struct,
            // and length of struct is 176, not 172.
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20, ArraySubType = UnmanagedType.U8)]
            private readonly IntPtr[] debugInfo;

            public ExceptionDebugInfo Exception => GetDebugInfo<ExceptionDebugInfo>();

            /*
            public CREATE_THREAD_DEBUG_INFO CreateThread {
                get { return GetDebugInfo<CREATE_THREAD_DEBUG_INFO>(); }
            }

            public CREATE_PROCESS_DEBUG_INFO CreateProcessInfo {
                get { return GetDebugInfo<CREATE_PROCESS_DEBUG_INFO>(); }
            }

            public EXIT_THREAD_DEBUG_INFO ExitThread {
                get { return GetDebugInfo<EXIT_THREAD_DEBUG_INFO>(); }
            }

            public EXIT_PROCESS_DEBUG_INFO ExitProcess {
                get { return GetDebugInfo<EXIT_PROCESS_DEBUG_INFO>(); }
            }

            public LOAD_DLL_DEBUG_INFO LoadDll {
                get { return GetDebugInfo<LOAD_DLL_DEBUG_INFO>(); }
            }

            public UNLOAD_DLL_DEBUG_INFO UnloadDll {
                get { return GetDebugInfo<UNLOAD_DLL_DEBUG_INFO>(); }
            }

            public OUTPUT_DEBUG_STRING_INFO DebugString {
                get { return GetDebugInfo<OUTPUT_DEBUG_STRING_INFO>(); }
            }

            public RIP_INFO RipInfo {
                get { return GetDebugInfo<RIP_INFO>(); }
            }
            */

            private T GetDebugInfo<T>() where T : struct {
                var structSize = Marshal.SizeOf(typeof(T));
                var pointer = Marshal.AllocHGlobal(structSize);
                Marshal.Copy(debugInfo, 0, pointer, structSize / sizeof(IntPtr));

                var result = Marshal.PtrToStructure(pointer, typeof(T));
                Marshal.FreeHGlobal(pointer);
                return (T)result;
            }

            /*
            public EXCEPTION_DEBUG_INFO Exception {
                get {
                    if (debugInfo == null)
                        return new EXCEPTION_DEBUG_INFO();


                    fixed (byte* ptr = (byte*) debugInfo) {
                        return *(EXCEPTION_DEBUG_INFO*)ptr;
                    }
                }
            }

            public LOAD_DLL_DEBUG_INFO LoadDll {
                get {
                    if (debugInfo == null)
                        return new LOAD_DLL_DEBUG_INFO();


                    fixed (byte* ptr = (byte*) debugInfo) {
                        return *(LOAD_DLL_DEBUG_INFO*)ptr;
                    }
                }
            }
            */
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LoadDllDebugInfo {
            public readonly IntPtr hFile;
            public readonly IntPtr lpBaseOfDll;
            public readonly uint dwDebugInfoFileOffset;
            public readonly uint nDebugInfoSize;
            public readonly IntPtr lpImageName;
            public readonly ushort fUnicode;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct ExceptionDebugInfo {
            public ExceptionRecord ExceptionRecord;
            public readonly uint dwFirstChance;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct ExceptionRecord {
            public readonly ExceptionCodeStatus ExceptionCode;
            public readonly uint ExceptionFlags;
            public readonly IntPtr ExceptionRecordInstance;
            public readonly IntPtr ExceptionAddress;
            public readonly uint NumberParameters;

            //[MarshalAs(UnmanagedType.ByValArray, SizeConst = 15, ArraySubType = UnmanagedType.U4)]
            //public readonly uint[] ExceptionInformation;


            public unsafe fixed ulong ExceptionInformation[15];
        }


        public enum DebugEventType : uint {
            CreateProcessDebugEvent = 3, //Reports a create-process debugging event. The value of u.CreateProcessInfo specifies a CREATE_PROCESS_DEBUG_INFO structure.
            CreateThreadDebugEvent = 2, //Reports a create-thread debugging event. The value of u.CreateThread specifies a CREATE_THREAD_DEBUG_INFO structure.
            ExceptionDebugEvent = 1, //Reports an exception debugging event. The value of u.Exception specifies an EXCEPTION_DEBUG_INFO structure.
            ExitProcessDebugEvent = 5, //Reports an exit-process debugging event. The value of u.ExitProcess specifies an EXIT_PROCESS_DEBUG_INFO structure.
            ExitThreadDebugEvent = 4, //Reports an exit-thread debugging event. The value of u.ExitThread specifies an EXIT_THREAD_DEBUG_INFO structure.
            LoadDllDebugEvent = 6, //Reports a load-dynamic-link-library (DLL) debugging event. The value of u.LoadDll specifies a LOAD_DLL_DEBUG_INFO structure.
            OutputDebugStringEvent = 8, //Reports an output-debugging-string debugging event. The value of u.DebugString specifies an OUTPUT_DEBUG_STRING_INFO structure.
            RipEvent = 9, //Reports a RIP-debugging event (system debugging error). The value of u.RipInfo specifies a RIP_INFO structure.
            UnloadDllDebugEvent = 7, //Reports an unload-DLL debugging event. The value of u.UnloadDll specifies an UNLOAD_DLL_DEBUG_INFO structure.
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct Context {
            public uint ContextFlagsField;
            public uint Dr0;
            public uint Dr1;
            public uint Dr2;
            public uint Dr3;
            public uint Dr6;
            public uint Dr7;
            public FloatingSaveArea FloatSave;
            public uint SegGs;
            public uint SegFs;
            public uint SegEs;
            public uint SegDs;
            public uint Edi;
            public uint Esi;
            public uint Ebx;
            public uint Edx;
            public uint Ecx;
            public uint Eax;
            public uint Ebp;
            public uint Eip;
            public uint SegCs;
            public EflagsEnum EFlags;
            public uint Esp;
            public uint SegSs;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] ExtendedRegisters;
        }

        public enum ContextFlags : uint {
            ContextI386 = 0x10000,
            ContextI486 = 0x10000,
            ContextControl = ContextI386 | 0x01,
            ContextInteger = ContextI386 | 0x02,
            ContextSegments = ContextI386 | 0x04,
            ContextFloatingPoint = ContextI386 | 0x08,
            ContextDebugRegisters = ContextI386 | 0x10,
            ContextExtendedRegisters = ContextI386 | 0x20,
            ContextFull = ContextControl | ContextInteger | ContextSegments,
            ContextAll = ContextControl | ContextInteger | ContextSegments | ContextFloatingPoint | ContextDebugRegisters | ContextExtendedRegisters
        }

        public enum ContextFlagsX64 : uint {
            ContextFx64 = 0x00100000,
            ContextControl = (ContextFx64 | 0x0001),
            ContextInteger = (ContextFx64 | 0x0002),
            ContextSegments = (ContextFx64 | 0x0004),
            ContextFloatingPoint = (ContextFx64 | 0x0008),
            ContextDebugRegisters = (ContextFx64 | 0x0010),
            ContextFull = (ContextControl | ContextInteger | ContextFloatingPoint),
            ContextAll = (ContextControl | ContextInteger | ContextSegments | ContextFloatingPoint | ContextDebugRegisters)
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct XmmSaveArea32 {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2 * 2)]
            public ulong[] Header;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8 * 2)]
            public ulong[] Legacy;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16 * 2)]
            public ulong[] Xmm;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 12)]
            public ulong[] Alignment;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct ContextX64 {

            // Register parameter home addresses.
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            // Control flags.
            public uint ContextFlagsField;
            public uint MxCsr;

            // Segment Registers and processor flags.
            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public EflagsEnum EFlags;

            // Debug registers
            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            // Integer registers.
            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;

            // Program counter.
            public ulong Rip;

            // Floating point state.
            public XmmSaveArea32 FltSave;

            // Vector registers.
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26 * 2)]
            public ulong[] VectorRegister;
            public ulong VectorControl;

            // Special debug control registers.
            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }

        [Flags]
        public enum ThreadAccessFlags : uint {
            Terminate = 0x0001,
            SuspendResume = 0x0002,
            GetContext = 0x0008,
            SetContext = 0x0010,
            SetInformation = 0x0020,
            QueryInformation = 0x0040,
            SetThreadToken = 0x0080,
            Impersonate = 0x0100,
            DirectImpersonation = 0x0200
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct FloatingSaveArea {
            public uint ControlWord;
            public uint StatusWord;
            public uint TagWord;
            public uint ErrorOffset;
            public uint ErrorSelector;
            public uint DataOffset;
            public uint DataSelector;

            // missing some stuff
            public uint Cr0NpxState;
        }

        [Flags]
        public enum AllocationProtectEnum : uint {
            PageExecute = 0x00000010,
            PageExecuteRead = 0x00000020,
            PageExecuteReadwrite = 0x00000040,
            PageExecuteWritecopy = 0x00000080,
            PageNoaccess = 0x00000001,
            PageReadonly = 0x00000002,
            PageReadwrite = 0x00000004,
            PageWritecopy = 0x00000008,
            PageGuard = 0x00000100,
            PageNocache = 0x00000200,
            PageWritecombine = 0x00000400
        }

        public enum StateEnum : uint {
            MemCommit = 0x1000,
            MemFree = 0x10000,
            MemReserve = 0x2000
        }

        public enum TypeEnum : uint {
            MemImage = 0x1000000,
            MemMapped = 0x40000,
            MemPrivate = 0x20000
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        public struct MemoryBasicInformation {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public AllocationProtectEnum AllocationProtect;
            public IntPtr RegionSize;
            public StateEnum State;
            public AllocationProtectEnum Protect;
            public TypeEnum Type;
        }

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MemoryBasicInformation lpBuffer, IntPtr dwLength);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, IntPtr size, ref IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [Flags]
        public enum ProcessAccessFlags : uint {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [DllImport("kernel32.dll")]
        public static extern void GetSystemInfo(out SystemInfo lpSystemInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MemoryBasicInformation lpBuffer, uint dwLength);

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        public struct SystemInfo {
            public ushort processorArchitecture;
            readonly ushort reserved;
            public uint pageSize;
            public IntPtr minimumApplicationAddress;
            public IntPtr maximumApplicationAddress;
            public IntPtr activeProcessorMask;
            public uint numberOfProcessors;
            public uint processorType;
            public uint allocationGranularity;
            public ushort processorLevel;
            public ushort processorRevision;
        }



    }

    [Flags]
    public enum EflagsEnum : uint {
        /*
http://www.eecg.toronto.edu/~amza/www.mindsec.com/files/x86regs.html
Bit   Label    Desciption
---------------------------
0      CF      Carry flag
2      PF      Parity flag
4      AF      Auxiliary carry flag
6      ZF      Zero flag
7      SF      Sign flag
8      TF      Trap flag
9      IF      Interrupt enable flag
10     DF      Direction flag
11     OF      Overflow flag
12-13  IOPL    I/O Priviledge level
14     NT      Nested task flag
16     RF      Resume flag
17     VM      Virtual 8086 mode flag
18     AC      Alignment check flag (486+)
19     VIF     Virtual interrupt flag
20     VIP     Virtual interrupt pending flag
21     ID      ID flag
         */
        Carry = 1 << 0,
        R1 = 1 << 1,
        Parity = 1 << 2,
        R2 = 1 << 3,
        AuxiliaryCarry = 1 << 4,
        R3 = 1 << 5,
        Zero = 1 << 6,
        Sign = 1 << 7,
        Trap = 1 << 8,
        InterruptEnable = 1 << 9,
        Direction = 1 << 10,
        Overflow = 1 << 11,
        IoPrivilegeLevel1 = 1 << 12,
        IoPrivilegeLevel2 = 1 << 13,
        NestedTask = 1 << 14,
        R4 = 1 << 15,
        Resume = 1 << 16,
        Virtual8086Mode = 1 << 17,
        AlignmentCheck = 1 << 18,
        VirtualInterrupt = 1 << 19,
        VirtualInterruptPending = 1 << 20,
        Id = 1 << 21
    }
}
