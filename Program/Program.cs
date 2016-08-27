using System;
using System.Data;
using System.Windows.Forms;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Reflection;

namespace Program {
    public class Program {
        
        public static void AddContexts(BindingSource source, List<ContextManager.ThreadData> contexts) {
            var table = new DataTable();

            var column = new DataColumn
            {
                DataType = Type.GetType("System.Int32"),
                ColumnName = "threadId",
                ReadOnly = true,
                Unique = true
            };
            table.Columns.Add(column);

            column = new DataColumn
            {
                DataType = Type.GetType("System.String"),
                ColumnName = "Rip",
                ReadOnly = true,
                Unique = false
            };
            table.Columns.Add(column);

            DataColumn[] primaryKeyColumns = new DataColumn[1];
            primaryKeyColumns[0] = table.Columns["threadId"];
            table.PrimaryKey = primaryKeyColumns;

            foreach (var c in contexts) {
                var row = table.NewRow();
                row["threadId"] = c.ThreadId;
                row["Rip"] = $"{c.Rip:X}";
                table.Rows.Add(row);
            }

            source.DataSource = table;

            //Console.WriteLine("updated table");
        }

        public static void UpdateInfo(BindingSource source, ContextManager.Info info) {
            var table = new DataTable();

            var column = new DataColumn
            {
                DataType = Type.GetType("System.String"),
                ColumnName = "title",
                ReadOnly = true,
                Unique = true
            };
            table.Columns.Add(column);

            column = new DataColumn
            {
                DataType = Type.GetType("System.String"),
                ColumnName = "data",
                ReadOnly = true,
                Unique = false
            };
            table.Columns.Add(column);

            DataColumn[] primaryKeyColumns = new DataColumn[1];
            primaryKeyColumns[0] = table.Columns["title"];
            table.PrimaryKey = primaryKeyColumns;

            var row = table.NewRow();
            row["title"] = "Event Count";
            row["data"] = $"{info.EventCount}";
            table.Rows.Add(row);

            row = table.NewRow();
            row["title"] = "Min Distance";
            row["data"] = $"{info.MinDistance}";
            table.Rows.Add(row);

            row = table.NewRow();
            row["title"] = "Min Address";
            row["data"] = $"{info.MinAddress:X}";
            table.Rows.Add(row);

            if (info.LastContextReady) {
                foreach (var field in typeof(Win32Imports.ContextX64).GetFields(BindingFlags.Instance |
                                                        BindingFlags.NonPublic |
                                                        BindingFlags.Public)) {
                    row = table.NewRow();
                    row["title"] = field.Name;
                    try {
                        row["data"] = field.GetValue(info.LastContext).ToString();
                    }
                    catch {
                        row["data"] = "Exception";
                    }
                    table.Rows.Add(row);
                }
            }

            source.DataSource = table;
        }

        public static void Update(ContextManager cg, IProgress<List<ContextManager.ThreadData>> progress) {
            var contexts = cg.GetContexts();
            progress.Report(contexts);
        }

        public void UpdateLabel(IProgress<String> progress, String s) {
            progress.Report(s);
        }

        public static void DoIt() {
            var name = Specifics.ProcessName;
            var address = Specifics.StartAddress;
            var process = DebugProcessUtils.GetFirstProcessByName(name);

            using (Form form = new Form()) {
                form.Text = "Inspector";
                form.Size = new Size(600, 1080);

                var table = new DataGridView();
                var bindingSource = new BindingSource();
                table.DataSource = bindingSource;

                var infoTable = new DataGridView();
                var infoSource = new BindingSource();
                infoTable.DataSource = infoSource;

                var formClosed = false;
                var cleanupFinished = false;

                var splitter = new Splitter();

                infoTable.Dock = DockStyle.Left;
                splitter.Dock = DockStyle.Left;
                table.Dock = DockStyle.Fill;
                form.Controls.AddRange(new Control[] { table, splitter, infoTable });

                Console.CancelKeyPress += delegate (object sender, ConsoleCancelEventArgs e) {
                    e.Cancel = true;
                    //form.Close();
                };

                var progress = new Progress<List<ContextManager.ThreadData>>(
                    (contexts) => {
                        AddContexts(bindingSource, contexts);
                    }
                );

                IProgress<ContextManager.Info> infoProgress = new Progress<ContextManager.Info>(
                    (info) => {
                        UpdateInfo(infoSource, info);
                    }
                );

                var specifics = new Specifics();

                Task.Factory.StartNew(
                    () => {
                        var logName = Specifics.LogName;
                        var logName2 = Specifics.LogNameLatest;
                        using (var logFile = new Logger(logName, logName2)) {
                            ContextManager cg = null;
                            logFile.WriteLine("");
                            logFile.WriteLine("STARTING INSPECTOR");
                            try {
                                var importResolver = new ImportResolver(process);
                                importResolver.DumpDebug();
                                var logContext = new ContextTracer(importResolver);
                                var logFile2 = logFile;
                                cg = new ContextManager(name, logFile, specifics, (cm, threadId, context, trace) => {
                                    Debug.Assert(logFile2 != null, "logFile2 != null");
                                    return logContext.Log(cm, logFile2, process, threadId, context, trace);
                                }, importResolver);

                                //if (File.Exists(Specifics.appStateFileName)) {
                                //SaveAndRestore.Restore(Specifics.appStateFileName, cg);
                                //} else {
                                cg.EnableBreakPoint(importResolver.ResolveRelativeAddress(address), new ContextManager.BreakPointInfo {
                                    Description = "starting breakpoint"
                                });
                                //}
                                cg.AntiAntiDebug();

                                /*try {
                                    cg.InstallBreakPoint(address);
                                } catch (InvalidOperationException e) {
                                    Console.WriteLine($"Failed to install break points: {e.ToString()}");
                                }*/

                                while (!formClosed) {
                                    logFile.WriteLine("main debugger loop");
                                    cg.CurrentProcess = DebugProcessUtils.GetFirstProcessByName(cg.CurrentProcess.ProcessName);
                                    cg.TestBreak();
                                    Update(cg, progress);
                                    infoProgress.Report(cg.CurrentInfo);
                                    SaveAndRestore.Save(Specifics.AppStateFileName, cg);
                                    Task.Delay(Specifics.MainLoopDelay).Wait();
                                }
                            }
                            catch (Exception e) {
                                Console.WriteLine($"Exception: {e.Message}");
                                Console.WriteLine(e.StackTrace);
                                logFile.WriteLine($"Exception: {e.Message}");
                                logFile.WriteLine(e.StackTrace);
                            }
                            // cleanup
                            Console.WriteLine("cleaning up");
                            SaveAndRestore.Save(Specifics.AppStateFileName, cg);
                            cg?.Stop();
                            cleanupFinished = true;
                        }
                    },
                    TaskCreationOptions.LongRunning
                );

                /*Task.Factory.StartNew(
                    () => {
                        while (true) {
                            cg.ResumeEvents();
                        }
                    },
                    TaskCreationOptions.LongRunning
                );*/

                form.FormClosing += (sender, e) => {
                                                    Console.WriteLine("form closing");
                                                    formClosed = true;
                                                    while (!cleanupFinished) {
                                                        Console.WriteLine("waiting for cleanup");
                                                        Task.Delay(1000).Wait();
                                                    }
                };

                form.ShowDialog();
            }
        }
        public static void Main2() {
            try {
                DoIt();
            }
            catch (Exception e) {
                Console.WriteLine($"Exception: {e.Message}");
                Console.WriteLine(e.StackTrace);
            }
        }
    }
}