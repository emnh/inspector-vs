using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Runtime.ExceptionServices;
using System.Collections.Generic;
using System.Linq;

namespace Program {
    public class DebugProcessUtils {
        private const int ProcessVmRead = 0x0010;
        private const int ProcessVmWrite = 0x0020;
        private const int ProcessVmOperation = 0x0008;

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(int hProcess, ulong lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(int hProcess, ulong lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        public static Process GetFirstProcessByName(String name) {
            Process[] processes = Process.GetProcessesByName(name);

            Process process;

            if (processes.Length > 0) {
                process = processes[0];
            }
            else {
                throw new Exception($"Program '{name}' not found!");
            }

            return process;
        }

        /*
        public static ProcessModule GetModuleByAddress(Process process, ulong address) {
            foreach (ProcessModule module in process.Modules) {
                var start = (ulong)module.BaseAddress.ToInt64();
                var end = start + (ulong)module.ModuleMemorySize;
                if (address >= start && address <= end) {
                    return module;
                }
            }
            return null;
        }
        */

        public static byte ReadByte(Process process, ulong address) {
            var processHandle = OpenProcess(ProcessVmRead, false, process.Id);

            int bytesRead = 0;
            byte[] buffer = new byte[1];

            if (!ReadProcessMemory((int)processHandle, address, buffer, buffer.Length, ref bytesRead)) {
                throw new Win32Exception();
            }

            CloseHandle(processHandle);

            return buffer[0];
        }

        [HandleProcessCorruptedStateExceptions]
        public static byte[] ReadBytes(Process process, ulong address, int length) {
            var processHandle = OpenProcess(ProcessVmRead, false, process.Id);

            int bytesRead = 0;
            byte[] buffer = new byte[length];

            try {
                if (!ReadProcessMemory((int)processHandle, address, buffer, buffer.Length, ref bytesRead)) {
                    var bufstr = String.Join(" ", buffer.Select((x) => x.ToString("X")));
                    Console.WriteLine($"ReadProcessMemory failed, buffer: {bufstr}");
                    throw new Win32Exception();
                }
            }
            catch (AccessViolationException e) {
                throw new InvalidOperationException($"could not read memory at {address}: {e}");
            }

            CloseHandle(processHandle);

            return buffer;
        }
        public static void WriteByte(Process process, ulong address, byte toWrite) {
            var processHandle = OpenProcess(ProcessVmWrite | ProcessVmOperation, false, process.Id);

            int bytesWritten = 0;
            byte[] buffer = { toWrite };

            if (!WriteProcessMemory((int)processHandle, address, buffer, buffer.Length, ref bytesWritten)) {
                throw new Win32Exception();
            }

            CloseHandle(processHandle);
        }

        public static void WriteBytes(Process process, ulong address, byte[] buffer) {
            var processHandle = OpenProcess(ProcessVmWrite | ProcessVmOperation, false, process.Id);

            int bytesWritten = 0;

            if (!WriteProcessMemory((int)processHandle, address, buffer, buffer.Length, ref bytesWritten)) {
                throw new Win32Exception();
            }

            CloseHandle(processHandle);
        }

        public static string BytesToHex(byte[] mem) {
            var hex = new List<String>();
            foreach (var b in mem) {
                hex.Add($"{b:X2}");
            }
            var s = String.Join(" ", hex);
            return s;
        }
    }
}