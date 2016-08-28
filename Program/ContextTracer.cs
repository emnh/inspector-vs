using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Numerics;
using SharpDisasm;
using SharpDisasm.Udis86;

namespace Program {

    public class ContextTracer {

        public class State {
            public Win32Imports.ContextX64 Context;
            public Instruction Instruction;
            public string Line;
            public Dictionary<ulong, ulong> HitCounts = new Dictionary<ulong, ulong>();
            public int StackDepth;
            public ulong LastCallAddressInTraceModule;
            public Instruction SdInstruction;
        }

        public class TraceReturn {
            public bool Ignore;
            public bool StepOver;
        }

        private readonly Dictionary<int, State> _oldState = new Dictionary<int, State>();
        private readonly Dictionary<string, FieldInfo> _fieldMap = new Dictionary<string, FieldInfo>();
        private readonly ImportResolver _importResolver;

        public ContextTracer(ImportResolver importResolver) {
            _importResolver = importResolver;

            foreach (var field in typeof(Win32Imports.ContextX64).GetFields(BindingFlags.Instance |
                                BindingFlags.NonPublic |
                                BindingFlags.Public)) {
                _fieldMap[field.Name.ToUpper()] = field;
            }
        }

        // returns true if new breakpoint was set
        public TraceReturn Log(ContextManager cm, Logger logFile, Process process, int threadId, Win32Imports.ContextX64 context, bool trace) {
            if (!trace) {
                // end trace
                return new TraceReturn {
                    StepOver = false
                };
            }
            // http://stackoverflow.com/questions/14698350/x86-64-asm-maximum-bytes-for-an-instruction

            var breakAddress = context.Rip;

            var mem = DebugProcessUtils.ReadBytes(process, breakAddress, AsmUtil.MaxInstructionBytes);
            var distance = (long)(breakAddress - cm.LastBreakAddress);
            
            var decodedInstruction = AsmUtil.Disassemble(process, breakAddress);
            var hex = DebugProcessUtils.BytesToHex(mem.Take(decodedInstruction.Length).ToArray());

            var moduleAddressTuple = _importResolver.LookupAddress(breakAddress);
            var module = moduleAddressTuple.Item1;
            var relativeAddress = breakAddress - moduleAddressTuple.Item2;

            var hitCounts =
                _oldState.ContainsKey(threadId) ?
                _oldState[threadId].HitCounts :
                new Dictionary<ulong, ulong>();

            var stackDepth = 0;
            if (_oldState.ContainsKey(threadId)) {
                stackDepth = _oldState[threadId].StackDepth;
            }
            if (decodedInstruction.Mnemonic == ud_mnemonic_code.UD_Icall) {
                stackDepth++;
            } else if (decodedInstruction.Mnemonic == ud_mnemonic_code.UD_Iret) {
                stackDepth--;
            }

            if (breakAddress == _importResolver.ResolveRelativeAddress(Specifics.StartAddress)) {
                // reset trace state when we hit first breakpoint
                // except for oldHitCounts, which will be added back at end of function
                _oldState.Remove(threadId);
            } else if (breakAddress != cm.LastBreakAddress) {
#if UseDebugger
                // we're not interested in logging threads where breakpoint was not found
                if (!_oldState.ContainsKey(threadId)) {
                        logFile.WriteLine($"ignoring trace for thread {threadId}");
                        return new TraceReturn {
                            Ignore = true,
                            StepOver = false
                        };
                    }
#endif
            }

            // IMPORTANT: continues the trace
            var retVal = false;
            ulong lastCallAddressInTraceModule =
                _oldState.ContainsKey(threadId) ?
                _oldState[threadId].LastCallAddressInTraceModule :
                0;
            // clean up breakpoints as soon as they are hit
            cm.DisableBreakPointOnHit(breakAddress);
#if UseDebugger
            if (decodedInstruction.Mnemonic == ud_mnemonic_code.UD_Icall && !module.Equals(Specifics.TraceModuleName)) {
                    // step over call
                    var returnAddress = breakAddress + (ulong) decodedInstruction.Length;
                    logFile.WriteLine($"installing return breakpoint at {returnAddress:X}");
                    cm.EnableBreakPoint(returnAddress, new ContextManager.BreakPointInfo {
                        Description = "return breakpoint"
                    });
                    stackDepth--; // since the RET will not be executed
                    retVal = true;
                }
                else {
                    if (module.Equals(Specifics.TraceModuleName)) {
                        if (decodedInstruction.Mnemonic == ud_mnemonic_code.UD_Iret) {

                        }
                        else if (decodedInstruction.Mnemonic == ud_mnemonic_code.UD_Ijmp) {

                        }
                        else {
                            var cAddress = breakAddress + (ulong) decodedInstruction.Length;
                            logFile.WriteLine($"setting continuation at 0x{cAddress:X} for {decodedInstruction.Mnemonic} of size {decodedInstruction.Length}");
                            cm.EnableBreakPoint(cAddress, new ContextManager.BreakPointInfo {
                                Description = $"for {decodedInstruction.Mnemonic} of size {(ulong) decodedInstruction.Length}"
                            });
                        }
                        /*foreach (var condJump in new string[] {
                            "JE", "JZ", "JNE", "JNZ", "JG", "JNLE", "JGE", "JNL", "JL", "JNGE",
                            "JLE", "JNG", "JA", "JNBE", "JAE", "JNB", "JB", "JNAE", "JBE", "JNA" }) {
                            if (decodedInstruction.Mnemonic.Equals(condJump)) {
                                var nextTarget = breakAddress + decodedInstruction.Size;
                                var jumpMatch = Regex.Match("0x([a-z0-9]+)", decodedInstruction.Operands);
                                if (jumpMatch.Success) {
                                    var offset = ulong.Parse(jumpMatch.Groups[0].Value, System.Globalization.NumberStyles.AllowHexSpecifier);
                                    var jumpTarget = (ulong) (new BigInteger(breakAddress) + (long) offset);
                                    //logFile.WriteLine($"jump calc: offset: {(long) offset}, target: 0x{jumpTarget:X}");
                                }

                                //cm.continuationBreakAddress += 
                                break;
                            }
                        }*/
                        if (decodedInstruction.Mnemonic == ud_mnemonic_code.UD_Icall) {
                            // step over instruction
                            lastCallAddressInTraceModule = breakAddress;
                            lastCallAddressInTraceModule += (ulong) decodedInstruction.Length;
                        }
                        logFile.WriteLine($"setting next trace for {threadId}");
                        ContextManager.setTrace((uint)threadId);
                    }
                    else {
                        if (lastCallAddressInTraceModule == 0) {
                            logFile.WriteLine("In external module, but no call to get back to.");
                        }
                        else if (!cm.BreakPoints.ContainsKey(lastCallAddressInTraceModule)) {
                            logFile.WriteLine($"In external module, returning to {lastCallAddressInTraceModule:X}");
                            cm.EnableBreakPoint(lastCallAddressInTraceModule, new ContextManager.BreakPointInfo {
                                Description = $"return from external module: {module}+{relativeAddress}"
                            });
                        }
                    }
                }
#else
                throw new NotImplementedException();
                /*
                cm.continuationBreakAddress = breakAddress;
                //cm.continuationBreakAddress += decodedInstruction.Size;
                if (decodedInstruction.Mnemonic.Equals("RET")) {
                    var stackPointer = context.Rsp;
                    if (!decodedInstruction.Operands.Equals("")) {
                        var offset = ulong.Parse(decodedInstruction.Operands);
                        stackPointer += offset;
                    }
                    ulong returnAddress = BitConverter.ToUInt64(DebugProcessUtils.ReadBytes(process, stackPointer, 8), 0);
                    cm.continuationBreakAddress = returnAddress;
                }*/
#endif

            if (hitCounts.ContainsKey(breakAddress)) {
                hitCounts[breakAddress]++;
            }
            else {
                hitCounts[breakAddress] = 1;
            }

            var registers = _oldState.ContainsKey(threadId) ? 
                AsmUtil.FormatContextDiff(context, _oldState[threadId].Context, _oldState[threadId].SdInstruction) : 
                AsmUtil.FormatContext(context);
            //logFile.WriteLine(registers);
            var previous = "";
            var lineBreak = false;
            if (_oldState.ContainsKey(threadId)) {
                previous = _oldState[threadId].Line;
                if (_oldState[threadId].Instruction.Mnemonic == ud_mnemonic_code.UD_Iret ||
                    _oldState[threadId].Instruction.Mnemonic == ud_mnemonic_code.UD_Icall) {
                    lineBreak = true;
                }
            }
            var asm = $"{ decodedInstruction.Mnemonic } { decodedInstruction.Operands}";
            double logdist =
                distance == 0 ?
                    0.0 :
                    distance < 0 ?
                        -Math.Log(-distance, 2) :
                        Math.Log(distance, 2);

            var pattern = "";
            pattern += Regex.Escape("[");
            pattern += "(?<reg1>[A-Z0-9]{3})";
            pattern += "((?<sign1>[" + Regex.Escape("+") + Regex.Escape("-") + "])(?<reg2>[A-Z0-9]{3})(" + Regex.Escape("*") + "(?<multiplier>[0-9]+))?)?";
            pattern += "((?<sign2>[" + Regex.Escape("+") + Regex.Escape("-") + "])0x(?<offset>[0-9a-f]+))?";
            pattern += Regex.Escape("]");
            var rex = new Regex(pattern);
            // TODO: rewrite offset code to use SharpDisasm structure instead of string parsing
            var operands = decodedInstruction.Operands.ToString();
            var match = rex.Matches(operands);
            BigInteger memAddress = 0;
            if (match.Count > 0) {
                var reg1 = match[0].Groups[rex.GroupNumberFromName("reg1")].Value;
                var reg2 = match[0].Groups[rex.GroupNumberFromName("reg2")].Value;
                long sign1 = match[0].Groups[rex.GroupNumberFromName("sign1")].Value.Equals("+") ? 1 : -1;
                long sign2 = match[0].Groups[rex.GroupNumberFromName("sign2")].Value.Equals("+") ? 1 : -1;
                var multiplierString = match[0].Groups[rex.GroupNumberFromName("multiplier")].Value;
                var multiplier = multiplierString.Equals("") ? 1 : long.Parse(multiplierString);

                var offsetHex = match[0].Groups[rex.GroupNumberFromName("offset")].Value;
                var reg1Value = (ulong)_fieldMap[reg1].GetValue(context);
                ulong reg2Value = 0;
                if (!reg2.Equals("")) {
                    reg2Value = (ulong)_fieldMap[reg2].GetValue(context);
                }
                var offset = offsetHex.Equals("") ? 0 : long.Parse(offsetHex, System.Globalization.NumberStyles.AllowHexSpecifier);
                memAddress = new BigInteger(reg1Value) + sign1 * new BigInteger(reg2Value) * multiplier + sign2 * new BigInteger(offset);
            } else if (decodedInstruction.Mnemonic == ud_mnemonic_code.UD_Ipop || decodedInstruction.Mnemonic == ud_mnemonic_code.UD_Ipush) {
                memAddress = context.Rsp;
            }

            //var module = DebugProcessUtils.GetModuleByAddress(process, breakAddress);
            var oldLine = $"d: {logdist,8:#.##}, thread: {threadId,6:D}, mem: {memAddress,16:X} ";
            var moduleAndAddress = $"{module}+0x{relativeAddress:X}:{breakAddress:X}";
            oldLine += $"instr: {hex,30},";
            var hits = hitCounts[breakAddress];
            oldLine += $" {moduleAndAddress,64}(h{hits,2})(s{stackDepth,2}): {asm,-40} ";
            logFile.WriteLine(previous + registers);
            if (lineBreak) {
                logFile.WriteLine("");
            }

            _oldState[threadId] = new State {
                Context = context,
                Instruction = decodedInstruction,
                Line = oldLine,
                HitCounts = hitCounts,
                StackDepth = stackDepth,
                LastCallAddressInTraceModule = lastCallAddressInTraceModule
            };

            return new TraceReturn {
                StepOver = retVal
            };
        }
    }
}