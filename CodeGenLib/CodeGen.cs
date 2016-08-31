using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using AsmJit.AssemblerContext;
using SharpDisasm.Udis86;

namespace CodeGenLib
{
    public class CodeGen
    {
        private const string Newline = "\r\n";
        private const string Indent = "    ";

        public static string Repeat(string s, int n) {
            return new String(Enumerable.Range(0, n).SelectMany(x => s).ToArray());
        }

        public static Dictionary<string, string> GenerateAsmJitAssemblerMethod() {
            var mnemonics = Enum.GetValues(typeof(ud_mnemonic_code)).Cast<ud_mnemonic_code>().ToArray();
            var mnemonicNameToMethodName = new Dictionary<string, string>();
            var mnemonicNameToMethodInfoList = new Dictionary<string, List<MethodInfo>>();
            var mnemonicToBody = new Dictionary<string, string>();

            var indent5 = Repeat(Indent, 5);
            var indent6 = Repeat(Indent, 6);
            var indent7 = Repeat(Indent, 7);

            foreach (var method in typeof(CodeContext).GetMethods(BindingFlags.Instance |
                                                                  BindingFlags.Public)) {
                var transformed = "UD_I" + method.Name.ToLower();
                mnemonicNameToMethodName[transformed] = method.Name;
                var methodInfoList = new List<MethodInfo>();
                if (!mnemonicNameToMethodInfoList.ContainsKey(transformed)) {
                    mnemonicNameToMethodInfoList[transformed] = methodInfoList;
                }
                else {
                    methodInfoList = mnemonicNameToMethodInfoList[transformed];
                }
                methodInfoList.Add(method);
            }

            foreach (var mnemonic in mnemonics) {
                if (mnemonicNameToMethodName.ContainsKey(mnemonic.ToString())) {
                    var varDecls = new List<string>();
                    var varNames = new Dictionary<string, bool>();
                    var parts = new List<string>();
                    foreach (var method in mnemonicNameToMethodInfoList[mnemonic.ToString()]) {
                        var methodChecks = new List<string>();
                        var methodArguments = new List<string>();
                        var operandIndex = 0;
                        var length = method.GetParameters().Length;
                        methodChecks.Add($"instruction.Operands.Length == {length}");
                        foreach (var parameter in method.GetParameters()) {
                            var varName = $"var{parameter.ParameterType.Name}{operandIndex}";
                            if (!varNames.ContainsKey(varName)) {
                                string defaultValue =
                                    parameter.ParameterType.Name.Equals("Int64") || parameter.ParameterType.Name.Equals("UInt64")
                                    ? "0"
                                    : "null";
                                varDecls.Add(
                                    $"{indent7}var {varName} = " +
                                    $"new Lazy<MaybeOption<{parameter.ParameterType.Name}>>(() =>" +
                                    $"OperandToAsmJit.GetOperand(context, instruction, instruction.Operands[{operandIndex}], ({parameter.ParameterType.Name}) {defaultValue}));");
                                varNames[varName] = true;
                            }
                            methodChecks.Add($"{varName}.Value.Present");
                            methodArguments.Add($"{varName}.Value.Value");
                            operandIndex++;
                        }
                        var checks = String.Join(" && ", methodChecks);
                        var arguments = String.Join(", ", methodArguments);
                        var methodCall = $"context.{method.Name}({arguments})";
                        var methodBody = $"{indent6}if ({checks}) {{{Newline}{indent7}{methodCall};\r\n";
                        methodBody += $"{indent7}return;{Newline}{indent6}}}{indent6}{Newline}";
                        parts.Add(methodBody);
                    }
                    var decls = String.Join(Newline, varDecls);
                    var joinParts = String.Join(Newline, parts);
                    mnemonicToBody[mnemonic.ToString()] = $"{indent6}{{ {decls}{Newline}{joinParts} {indent6}}}";
                }
            }

            var casesList = new List<string>();
            foreach (var mnemonic in mnemonics) {
                var caseHead = $"{indent5}case ud_mnemonic_code.{mnemonic}:";
                string caseBody;
                if (mnemonicToBody.ContainsKey(mnemonic.ToString())) {
                    caseBody = mnemonicToBody[mnemonic.ToString()];
                    caseBody += $"{indent7}throw new AssembleException($\"unsupported operands to instruction: {{instruction}}\");";
                    //caseBody += $"{indent7}break;{newline}";
                } else {
                    caseBody = $"{indent6}throw new AssembleException($\"unsupported instruction: {{instruction}}\");";
                }
                casesList.Add(caseHead);
                casesList.Add(caseBody);
            }
            
            var cases = String.Join(Newline, casesList);
            var body = $"switch (instruction.Mnemonic) {{ {cases} }}";
            var methodDecl = $"public static void AsmJitAssemble(CodeContext context, SharpDisasm.Instruction instruction) {{ {body} }}";
            var classed = $"public class AsmJitAssemblerTemp {{ {methodDecl} }}";
            var namespaced = $"namespace AsmJitAssembleLib {{ {classed} }}";
            var usings = @"
// This file was auto-generated by CodeGen.GenerateAsmJitAssemblerMethod

using AsmJit.AssemblerContext;
using AsmJit.Common.Operands;
using SharpDisasm.Udis86;
using System;
";
            var all = usings + namespaced;

            string path = Path.GetFullPath(@"..\..\..\AsmJitAssemblerTemp.cs");
            Console.WriteLine($"writing {path}");
            File.WriteAllText(path, all);

            return mnemonicToBody;
        }

        public static void Main() {
            GenerateAsmJitAssemblerMethod();
        }
    }
}
