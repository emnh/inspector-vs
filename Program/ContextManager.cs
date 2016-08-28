using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Threading;
using System.Collections.Generic;
using System.Linq;
using SharpDisasm;
using SharpDisasm.Udis86;

namespace Program {
    public class ContextManager {

        [Flags]
        public enum GetRipAction {
            ActionSuspend = 1,
            ActionResume = 2,
            ActionGetContext = 4
        }

        public enum HwbrkType {
            HwbrkTypeCode,
            HwbrkTypeReadwrite,
            HwbrkTypeWrite,
        };

        public enum HwbrkSize {
            HwbrkSize1,
            HwbrkSize2,
            HwbrkSize4,
            HwbrkSize8,
        };


        [DllImport("hwbrk64.dll")]
        public static extern ulong SetHardwareBreakpoint(ulong tHandle, HwbrkType type, HwbrkSize size, ulong address);

        [DllImport("hwbrk64.dll")]
        public static extern bool RemoveHardwareBreakpoint(ulong handle);

        [DllImport("ContextLib.dll")]
        public static extern ulong getRip(uint tHandle, ref Win32Imports.ContextX64 context, GetRipAction actions);
        [DllImport("ContextLib.dll")]
        public static extern ulong setRip(uint tHandle, bool suspend, ulong rip);
        [DllImport("ContextLib.dll")]
        public static extern ulong setTrace(uint tHandle, bool suspend = true, bool clear = false);
        [DllImport("ContextLib.dll")]
        public static extern ulong setHardwareBreakPoint(uint tHandle, ulong address, bool suspend = true, bool clear = false);
        [DllImport("ContextLib.dll")]
        public static extern bool handleDebugEvent(out Win32Imports.DebugEvent evt, out uint continueStatus);
        [DllImport("ContextLib.dll")]
        public static extern void setDebugPrivilege();
        
        public class ThreadData {
            public uint ThreadId;
            public ulong Rip;
        }

        public class Info {
            public ulong EventCount;
            public ulong MinDistance = ulong.MaxValue;
            public ulong MinAddress = 0;
            public bool LastContextReady;
            public Win32Imports.ContextX64 LastContext;
        }

        public Process CurrentProcess;
        public Info CurrentInfo = new Info();
        public Logger LoggerInstance;
        public Specifics SpecificsInstance;
        public Func<ContextManager, int, Win32Imports.ContextX64, bool, ContextTracer.TraceReturn> BreakPointCallBack;

        public class BreakPointInfo {
            public bool ShouldEnable = true;
            public bool IsActive;
            public bool IsHardware;
            public ulong HardwareBreakPointHandle;
            public bool IsSoftware;
            public byte[] OriginalCode;
            public string Description = "";
            public bool DontDisableOnHit;
        }

        private ulong _lastBreakAddress;
        public ulong LastBreakAddress => _lastBreakAddress;

        public readonly Dictionary<ulong, BreakPointInfo> BreakPoints = new Dictionary<ulong, BreakPointInfo>();
        private readonly Dictionary<ulong, BreakPointInfo> _enabledBreakPoints = new Dictionary<ulong, BreakPointInfo>();

        private readonly ImportResolver _importResolver;
        private const string CloseHandleDescription = "CloseHandle";

        public ContextManager(String name, Logger loggerInstance, Specifics specificsInstance,
            Func<ContextManager, int, Win32Imports.ContextX64, bool, ContextTracer.TraceReturn> breakPointCallBack,
            ImportResolver importResolver) {

            LoggerInstance = loggerInstance;
            BreakPointCallBack = breakPointCallBack;
            _importResolver = importResolver;

            setDebugPrivilege();

            CurrentProcess = DebugProcessUtils.GetFirstProcessByName(name);

            foreach (ProcessThread thread in CurrentProcess.Threads) {
                loggerInstance.WriteLine($"main thread: {thread.Id}");
                break;
            }

            SpecificsInstance = specificsInstance;

            Console.WriteLine("debugger");

            Console.WriteLine("pid: " + CurrentProcess.Id);

#if RestartEachTime
            // Attach to the process we provided the thread as an argument
            if (!Win32Imports.DebugActiveProcess(CurrentProcess.Id)) {
                    throw new Win32Exception();
                }

                if (!Win32Imports.DebugSetProcessKillOnExit(false)) {
                    throw new Win32Exception();
                }

                ClearEvents();
            }
#endif

        public void Int3Check() {
            var addresses = new ulong[] { 0x7FF9C61653E0 };
            foreach (var address in addresses) {
                var b = DebugProcessUtils.ReadByte(CurrentProcess, address);
                var overwritten = false;
                if (b == AsmUtil.Int3) {
                    DebugProcessUtils.WriteByte(CurrentProcess, address, AsmUtil.Nop);
                    overwritten = true;
                }
                LoggerInstance.WriteLine($"checking int3 at: 0x{address:X}, overwritten: {overwritten}");
            }
        }

        public void CloseHandleCheck() {
            var closeHandleAddress = _importResolver.LookupFunction("KERNELBASE.dll:CloseHandle");
            //var closeHandleAddress = importResolver.LookupFunction("KERNEL32.DLL:CloseHandle");

            EnableBreakPoint(closeHandleAddress, new BreakPointInfo {
                ShouldEnable = true,
                Description = CloseHandleDescription,
                DontDisableOnHit = true
            });
        }

        public void AntiAntiDebug() {
            Int3Check();
            CloseHandleCheck();
        }

        public void InstallHardwareBreakPoint(uint threadId, ulong startAddress) {
            //const byte INT3Trap = 0xCC;
            /*if (CheckBreakPointActive()) {
                throw new Exception("only one breakpoint at a time supported");
            }*/
            //LoggerInstance.WriteLine($"installing hardware breakpoint at {startAddress:X}");

            if (BreakPoints[startAddress].IsActive && BreakPoints[startAddress].IsHardware) {
                //LoggerInstance.WriteLine($"first removing hardware breakpoint at {startAddress:X}");
                RemoveHardwareBreakpoint(BreakPoints[startAddress].HardwareBreakPointHandle);
            }

            ulong handle = SetHardwareBreakpoint(threadId, HwbrkType.HwbrkTypeCode, HwbrkSize.HwbrkSize1, startAddress);
            BreakPoints[startAddress].HardwareBreakPointHandle = handle;
            BreakPoints[startAddress].IsHardware = true;
            BreakPoints[startAddress].IsActive = true;
        }

        public void InstallBreakPoint(ulong startAddress) {
            //const byte INT3Trap = 0xCC;
            /*if (CheckBreakPointActive()) {
                throw new Exception("only one breakpoint at a time supported");
            }*/

            LoggerInstance.WriteLine($"installing breakpoint at {startAddress:X}");

            if (BreakPoints[startAddress].OriginalCode == null) {
                byte[] mem = DebugProcessUtils.ReadBytes(CurrentProcess, startAddress, AsmUtil.InfiniteLoop.Length);
                BreakPoints[startAddress].OriginalCode = mem;
            }
            DebugProcessUtils.WriteBytes(CurrentProcess, startAddress, AsmUtil.InfiniteLoop);

            BreakPoints[startAddress].IsSoftware = true;
            BreakPoints[startAddress].IsActive = true;
        }

        private void UninstallBreakPoint(ulong address) {
            if (BreakPoints[address].IsActive) {
                if (BreakPoints[address].IsSoftware) {
                    byte[] mem = DebugProcessUtils.ReadBytes(CurrentProcess, address, AsmUtil.InfiniteLoop.Length);
                    if (mem[0] == AsmUtil.InfiniteLoop[0] && mem[1] == AsmUtil.InfiniteLoop[1]) {
                        LoggerInstance.WriteLine($"{nameof(UninstallBreakPoint)}: restoring inf-jmp with original code at 0x{address:X}");
                        DebugProcessUtils.WriteBytes(CurrentProcess, address, BreakPoints[address].OriginalCode);
                    }
                    else if (mem[0] != BreakPoints[address].OriginalCode[0] && mem[1] != BreakPoints[address].OriginalCode[1]) {
                        LoggerInstance.WriteLine($"{nameof(UninstallBreakPoint)}: code changed (self-modifying?) at 0x{address:X}");
                    }
                    else {
                        LoggerInstance.WriteLine($"{nameof(UninstallBreakPoint)}: code was intact at 0x{address:X}");
                    }
                } else if (BreakPoints[address].IsHardware && BreakPoints[address].HardwareBreakPointHandle != 0) {
                    RemoveHardwareBreakpoint(BreakPoints[address].HardwareBreakPointHandle);
                    /*foreach (ProcessThread thread in CurrentProcess.Threads) {
                        setHardwareBreakPoint((uint)thread.Id, address, true, true);
                    }*/
                }
            }
            BreakPoints[address].IsActive = false;
        }

        // for deserialization
        public void AddBreakPoint(ulong address, BreakPointInfo info) {
            BreakPoints[address] = info;
            if (info.ShouldEnable) {
                _enabledBreakPoints[address] = info;
            }
        }

        public bool HasBreakPoint(ulong address)
        {
            return BreakPoints.ContainsKey(address);
        }

        public void EnableBreakPoint(ulong address, BreakPointInfo info) {
            if (BreakPoints.ContainsKey(address)) {
                // breakpoints should be enabled only once
                BreakPoints[address].Description = info.Description;
            } else {
                Console.WriteLine("enabling breakpoint: " + info.Description);
                info.ShouldEnable = true;
                BreakPoints[address] = info;
                _enabledBreakPoints[address] = info;
            }
        }

        public void DisableBreakPointOnHit(ulong address)
        {
            if (!HasBreakPoint(address) ||
                (HasBreakPoint(address) && !BreakPoints[address].DontDisableOnHit)) {
                DisableBreakPoint(address);
            }
        }

        public void DisableBreakPoint(ulong address) {
            if (BreakPoints.ContainsKey(address)) {
                BreakPoints[address].ShouldEnable = false;
                _enabledBreakPoints.Remove(address);
            } else {
                BreakPoints[address] = new BreakPointInfo() {
                    ShouldEnable = false
                };
            }
        }

        public void Stop() {
            LoggerInstance.WriteLine("stopping");

            foreach (var address in BreakPoints.Keys) {
                UninstallBreakPoint(address);
            }

#if RestartEachTime
            foreach (ProcessThread thread in CurrentProcess.Threads) {
                    uint iThreadId = (uint)thread.Id;
                    setTrace(iThreadId, true, true);
                }
                for (var i = 0; i < 10; i++) {
                    ClearEvents();
                    Thread.Sleep(100);
                }
                if (!Win32Imports.DebugActiveProcessStop(CurrentProcess.Id)) {
                    throw new Win32Exception();
                }
            }
#endif

        public void ClearEvents() {
            // const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
            // const uint EXCEPTION_SINGLE_STEP = 0x80000004;
            const int dbgContinue = 0x00010002; // Seems to work better than DBG_EXCEPTION_NOT_HANDLED

            while (true) {
                Win32Imports.DebugEvent evt;
                if (!Win32Imports.WaitForDebugEvent(out evt, 0)) {
                    break;
                }
                CurrentInfo.EventCount++;
                Win32Imports.ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, dbgContinue);//DBG_EXCEPTION_NOT_HANDLED);
            }
        }

        public List<ThreadData> GetContexts() {

            // Attach to the process we provided the thread as an argument
#if RestartEachTime
#if UseDebugger
            if (!Win32Imports.DebugActiveProcess(CurrentProcess.Id)) {
                throw new Win32Exception();
            }

            if (!Win32Imports.DebugSetProcessKillOnExit(false)) {
                throw new Win32Exception();
            }
#endif
#endif

            var retval = new List<ThreadData>();

            //CONTEXT_X64 context = new CONTEXT_X64();
            Win32Imports.ContextX64 context = new Win32Imports.ContextX64();

            foreach (ProcessThread thread in CurrentProcess.Threads) {
                uint iThreadId = (uint)thread.Id;

                getRip(iThreadId, ref context, GetRipAction.ActionGetContext);
                //Console.WriteLine($"Rip: {Rip}");
                retval.Add(new ThreadData() {
                    ThreadId = iThreadId,
                    Rip = context.Rip
                });

                //Console.WriteLine($"thread id: {iThreadId}");
                //Console.WriteLine($"RIP: {context.Rip}");
            }

#if RestartEachTime
#if UseDebugger
            if (!Win32Imports.DebugActiveProcessStop(CurrentProcess.Id))
            {
                throw new Win32Exception();
            }
#endif
#endif
            return retval;
        }

        public bool ResumeBreak(bool trace = true) {
            //Console.WriteLine("ResumeBreak");
            //for (var i = 0; i < 10000; i++) {
            var done = false;
            var goNextBreakPoint = false;
            var continueCode = Win32Imports.DbgContinue;
            while (!done)
            {
                Win32Imports.DebugEvent evt;
                if (!Win32Imports.WaitForDebugEvent(out evt, 0)) {
                //if (!handleDebugEvent(out evt, out continueCode)) {
                        //Console.WriteLine("WaitForDebugEvent failed");
                        //throw new Win32Exception();
                        done = true;
                }
                else {
                    CurrentInfo.EventCount++;

                    // Multiple if's for easier debugging at this moment
                    switch (evt.dwDebugEventCode) {
                        case Win32Imports.DebugEventType.LoadDllDebugEvent:
                            //Console.WriteLine($"resumed load dll event: {evt.dwThreadId}");
                            break;
                        case Win32Imports.DebugEventType.UnloadDllDebugEvent:
                            //Console.WriteLine($"resumed unload dll event: {evt.dwThreadId}");
                            break;
                        case Win32Imports.DebugEventType.ExceptionDebugEvent:
                            var exceptionAddress = (ulong) evt.Exception.ExceptionRecord.ExceptionAddress.ToInt64(); 

                            //Console.WriteLine($"first addr: {breakAddress:X} vs {address:X}");
                            var context = new Win32Imports.ContextX64();
                            var breakAddress = getRip((uint) evt.dwThreadId, ref context, GetRipAction.ActionGetContext);
                            var code = evt.Exception.ExceptionRecord.ExceptionCode;
                            //Console.WriteLine($"code: {code}, events: {eventCount}, thread: {evt.dwThreadId}, addr: {breakAddress2:X} vs {address:X}");

                            if (BreakPoints.ContainsKey(breakAddress) && BreakPoints[breakAddress].IsActive) {
                                LoggerInstance.WriteLine($"match at {breakAddress:X}, trace: {trace}");

                                setTrace((uint)evt.dwThreadId);
                                UninstallBreakPoint(breakAddress);
                                _lastBreakAddress = breakAddress;

                                CurrentInfo.LastContext = context;
                                CurrentInfo.LastContextReady = true;
                                // trace
                                //setTrace((uint) evt.dwThreadId, false);
                                if (BreakPoints[breakAddress].Description.Equals(CloseHandleDescription)) {
                                    LoggerInstance.WriteLine("CloseHandle hit");
                                    LoggerInstance.WriteLine("Registers:" + AsmUtil.FormatContext(context));
                                } else {
                                }
                                done = BreakPointCallBack(this, evt.dwThreadId, context, trace).StepOver;
                                goNextBreakPoint = done;
                                //} else if (!CheckBreakPointActive()) {
                            }
                            else {
                                // if we have seen it before
                                var shouldTrace = !BreakPoints.ContainsKey(breakAddress) ||
                                    !(BreakPoints.ContainsKey(breakAddress) && !BreakPoints[breakAddress].ShouldEnable) ||
                                    !(BreakPoints.ContainsKey(breakAddress) && !BreakPoints[breakAddress].IsActive);
                                // no breakpoint active, so we are tracing
                                if (trace && shouldTrace) {
                                    LoggerInstance.WriteLine($"tracing thread {evt.dwThreadId} at 0x{breakAddress:X}");
                                    var ret = BreakPointCallBack(this, evt.dwThreadId, context, true);
                                    done = ret.StepOver;
                                    goNextBreakPoint = done;
                                    if (ret.Ignore) {
                                        LoggerInstance.WriteLine("continuing with exception handlers");
                                        continueCode = Win32Imports.DbgExceptionNotHandled;
                                    }
                                }
                                else {
                                    LoggerInstance.WriteLine("continuing with exception handlers");
                                    continueCode = Win32Imports.DbgExceptionNotHandled;
                                }
                            }

                            Instruction instr = null;
                            string asm = "N/A";
                            string asm2 = "N/A";
                            try {
                                instr = AsmUtil.Disassemble(CurrentProcess, exceptionAddress);
                                asm = AsmUtil.FormatInstruction(AsmUtil.Disassemble(CurrentProcess, breakAddress));
                                asm2 = AsmUtil.FormatInstruction(AsmUtil.Disassemble(CurrentProcess, exceptionAddress));
                            }
                            catch (Exception)
                            {
                                // ignored
                            }

                            string msg;

                            switch (code) {
                                case Win32Imports.ExceptionCodeStatus.ExceptionSingleStep:
                                    asm = AsmUtil.FormatInstruction(AsmUtil.Disassemble(CurrentProcess, breakAddress));
                                    LoggerInstance.WriteLine($"single step at {breakAddress:X}, evtCount: {CurrentInfo.EventCount}, asm: {asm}");
                                    continueCode = HasBreakPoint(breakAddress) ? Win32Imports.DbgContinue : Win32Imports.DbgExceptionNotHandled;
                                    break;
                                case Win32Imports.ExceptionCodeStatus.ExceptionBreakpoint:        
                                    asm = AsmUtil.FormatInstruction(instr);
                                    //if (instr.Mnemonic.Equals("INT") && instr.Operands.Equals("3")) {
                                    if (instr != null && instr.Mnemonic == ud_mnemonic_code.UD_Iint3) {
                                        LoggerInstance.WriteLine($"int3 breakpoint at: {exceptionAddress:X}, evtCount: {CurrentInfo.EventCount}, asm: {asm}");
                                        LoggerInstance.WriteLine("overwriting with NOP");
                                        DebugProcessUtils.WriteByte(CurrentProcess, exceptionAddress, AsmUtil.Nop);
                                        continueCode = Win32Imports.DbgContinue;
                                    } else {
                                        msg = $"breakpoint, chance: { evt.Exception.dwFirstChance}";
                                        msg += $", at: 0x{breakAddress:X}, exc at: 0x{exceptionAddress:X}, asm: {asm}, exc asm: {asm2}";
                                        LoggerInstance.WriteLine(msg);
                                    }
                                    break;
                                case Win32Imports.ExceptionCodeStatus.ExceptionInvalidHandle:
                                    msg = $"invalid handle, chance: { evt.Exception.dwFirstChance}";
                                    msg += $", at: 0x{breakAddress:X}, exc at: 0x{exceptionAddress:X}, asm: {asm}, exc asm: {asm2}";
                                    LoggerInstance.WriteLine(msg);
                                    LoggerInstance.WriteLine(msg);
                                    AsmUtil.LogStackTrace(_importResolver, LoggerInstance, CurrentProcess, context.Rsp);
                                    continueCode = Win32Imports.DbgExceptionNotHandled;
                                    break;
                                case Win32Imports.ExceptionCodeStatus.ExceptionInvalidOperation:
                                    msg = $"invalid operation, chance: { evt.Exception.dwFirstChance}";
                                    msg += $", at: 0x{breakAddress:X}, exc at: 0x{exceptionAddress:X}, asm: {asm}, exc asm: {asm2}";
                                    // anti-anti-debug measure
                                    if (instr != null && instr.Mnemonic == ud_mnemonic_code.UD_Iud2) {
                                        LoggerInstance.WriteLine("overwriting UD2 with NOP");
                                        DebugProcessUtils.WriteBytes(CurrentProcess, exceptionAddress, new[] { AsmUtil.Nop, AsmUtil.Nop });
                                    }
                                    // anti-anti-debug measure
                                    var instr2 = AsmUtil.Disassemble(CurrentProcess, exceptionAddress - 1);
                                    if (instr2.Mnemonic == ud_mnemonic_code.UD_Iint && instr2.Operands[0].Value == 0x2D) {
                                        ulong rip = context.Rip - 1;
                                        setRip((uint) evt.dwThreadId, false, rip);
                                        LoggerInstance.WriteLine("INT2D encountered, subtracting 1 from Rip");
                                        continueCode = Win32Imports.DbgContinue;
                                    } else {
                                        continueCode = Win32Imports.DbgExceptionNotHandled;
                                    }
                                    LoggerInstance.WriteLine(msg);                                    
                                    break;
                                case Win32Imports.ExceptionCodeStatus.ExceptionAccessViolation:
                                    msg = $"access violation: {code:X}, chance: { evt.Exception.dwFirstChance}";
                                    msg += $", at: 0x{breakAddress:X}, exc at: 0x{exceptionAddress:X}, asm: {asm}, exc asm: {asm2}";
                                    LoggerInstance.WriteLine(msg);
                                    break;
                                case 0:
                                    LoggerInstance.WriteLine($"event 0 at: {breakAddress:X}");
                                    break;
                                default:
                                    msg = $"unknown code: {code:X}, chance: { evt.Exception.dwFirstChance}";
                                    msg += $", at: 0x{breakAddress:X}, exc at: 0x{exceptionAddress:X}, asm: {asm}, exc asm: {asm2}";
                                    LoggerInstance.WriteLine(msg);
                                    break;
                            }
                            break;
                        case Win32Imports.DebugEventType.CreateProcessDebugEvent:
                            //Console.WriteLine($"resumed create process event for thread {evt.dwThreadId}");
                            break;
                        case Win32Imports.DebugEventType.CreateThreadDebugEvent:
                            //Console.WriteLine($"resumed create thread event for thread {evt.dwThreadId}");
                            break;
                        case Win32Imports.DebugEventType.ExitThreadDebugEvent:
                            //Console.WriteLine($"resumed exit thread event for thread {evt.dwThreadId}");
                            break;
                        case Win32Imports.DebugEventType.ExitProcessDebugEvent:
                            Console.WriteLine($"resumed exit process event for thread {evt.dwThreadId}");
                            break;
                        default:
                            Console.WriteLine($"resumed debug event for thread: {evt.dwThreadId} {evt.dwDebugEventCode}");
                            break;
                    }

                    
                    //LoggerInstance.WriteLine($"debug event of type {evt.dwDebugEventCode}");

                    if (!Win32Imports.ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, continueCode)) {
                        throw new Win32Exception();
                    }
                    //ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
                    //setBreakPoint((uint) evt.dwThreadId, address, false);
                }
            }

            //Console.WriteLine("End ResumeBreak");
            //return events;
            return goNextBreakPoint;
        }

        // remember to set targetAddress before using this function
        public List<ThreadData> TestBreak() {

#if RestartEachTime
#if UseDebugger
            // Attach to the process we provided the thread as an argument
            if (!Win32Imports.DebugActiveProcess(CurrentProcess.Id)) {
                throw new Win32Exception();
            }

            if (!Win32Imports.DebugSetProcessKillOnExit(false)) {
                throw new Win32Exception();
            }
#endif
#endif

        var retval = new List<ThreadData>();
            var context = new Win32Imports.ContextX64();

            //Console.WriteLine("TestBreak");

            if (!CheckBreakPointActive()) {
                //Console.WriteLine("adding breakpoints: " + breakPoints.Keys.Count);

                foreach (var breakPoint in BreakPoints.Keys) {
                    var shouldEnable = BreakPoints[breakPoint].ShouldEnable;
                    //Console.WriteLine($"enumerating breakPoint: 0x{breakPoint}, shouldEnable: {shouldEnable}");
                    if (shouldEnable) {
                        var msg = BreakPoints[breakPoint].Description;
                        Console.WriteLine($"installing continuation breakpoint at {breakPoint:X}: {msg}");
                        LoggerInstance.WriteLine($"installing continuation breakpoint at {breakPoint:X}: {msg}");
                        /*
                        if (!Specifics.useDebugger) {
                            LoggerInstance.WriteLine("Suspending all threads");
                            foreach (ProcessThread thread2 in process.Threads) {
                                getRip((uint)thread2.Id, ref context, ACTION_SUSPEND);
                            }
                        }*/

                        try {
#if UseHardwareBreakPoints
                            foreach (ProcessThread thread in CurrentProcess.Threads) {
                                InstallHardwareBreakPoint((uint) thread.Id, breakPoint);
                            }
#else
                            InstallBreakPoint(breakPoint);
      
#endif
                        }
                        catch (Exception e) {
                            Console.WriteLine($"Exception: {e.Message}");
                            Console.WriteLine(e.StackTrace);
                            LoggerInstance.WriteLine($"Exception: {e.Message}");
                            LoggerInstance.WriteLine(e.StackTrace);
                        }
                    } else {
                        Console.WriteLine("stale breakpoint" + BreakPoints[breakPoint].Description);
                    }
                }
            }

            foreach (ProcessThread thread in CurrentProcess.Threads) {
                uint iThreadId = (uint)thread.Id;

#if UseDebugger
                var traceInterval = Specifics.TraceInterval;
                var waitInterval = Specifics.WaitInterval;

                var sw = new Stopwatch();
                sw.Start();
                // trace program. slows down program a lot
                var done = false;
                foreach (ProcessThread thread2 in CurrentProcess.Threads) {
                    //Console.WriteLine("reinstalling CloseHandle breakpoint");
                    InstallHardwareBreakPoint((uint)thread2.Id,
                        BreakPoints.First(kv => kv.Value.Description.Equals(CloseHandleDescription)).Key);
                }
                while (sw.ElapsedMilliseconds <= traceInterval) {
                    getRip(iThreadId, ref context, GetRipAction.ActionGetContext);
                    var breakAddress = context.Rip;
                    if (BreakPoints.ContainsKey(breakAddress) && BreakPoints[breakAddress].IsActive) {
                        LoggerInstance.WriteLine("setting initial trace");
                        setTrace(iThreadId);
                    }
                    if (ResumeBreak()) {
                        done = true;
                        break;
                    }
                }
                sw.Stop();
                if (!done) {
                    sw = new Stopwatch();
                    sw.Start();
                    // give program time to run without debugging
                    while (sw.ElapsedMilliseconds <= waitInterval) {
                        ResumeBreak(false);
                    }
                    sw.Stop();
                }
#else
                    var sw = new Stopwatch();
                    sw.Start();

                    //getRip(iThreadId, ref context, ACTION_RESUME);

                    while (sw.ElapsedMilliseconds <= Specifics.loopWaitInterval) {
                        foreach (ProcessThread thread2 in CurrentProcess.Threads) {
                            uint iThreadId2 = (uint)thread2.Id;

                            getRip(iThreadId2, ref context, ActionGetContext);

                            var breakAddress = context.Rip;

                            if (BreakPoints.ContainsKey(breakAddress) && BreakPoints[breakAddress].IsActive) {
                                LoggerInstance.WriteLine($"match at {breakAddress:X} for thread {iThreadId2}");

                                setTrace((uint)iThreadId2, true);
                                UninstallBreakPoint(breakAddress);
                                _lastBreakAddress = breakAddress;

                                CurrentInfo.LastContext = context;
                                CurrentInfo.LastContextReady = true;
                                // trace
                                BreakPointCallBack(this, (int)iThreadId2, context, true);
                            }
                        }
                    }

                    //getRip(iThreadId, ref context, ACTION_SUSPEND);

                    sw.Stop();
#endif

            // XXX: ONLY FIRST THREAD
            /*if (Specifics.useDebugger) {
                break;
            }*/
            break;
            }

            /*
            if (!Specifics.useDebugger) {
                foreach (var address in originalCode.Keys) {
                    if (activeBreakPoints[address]) {
                        RemoveBreakPoint(address);
                    }
                }

                if (!Specifics.useDebugger) {
                    LoggerInstance.WriteLine("Resuming all threads");
                    foreach (ProcessThread thread2 in process.Threads) {
                        getRip((uint)thread2.Id, ref context, ACTION_RESUME);
                    }
                }
            }*/

            //ResumeBreak(address);
            //Thread.Sleep(5000);

#if RestartEachTime
#if UseDebugger
            if (!Win32Imports.DebugActiveProcessStop(CurrentProcess.Id)) {
                throw new Win32Exception();
            }
#endif
#endif
            return retval;
        }

        private bool CheckBreakPointActive() {
            var breakPointActive = false;
            foreach (var address in BreakPoints.Keys) {
                if (BreakPoints[address].IsActive) {
                    breakPointActive = true;
                    break;
                }
            }
            return breakPointActive;
        }
    }
}