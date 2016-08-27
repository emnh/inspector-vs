using System;
using System.IO;

namespace Program {
    public class Logger : IDisposable {

        // Flag: Has Dispose already been called?
        private bool _disposed;
        private readonly string _logName;
        private readonly StreamWriter _logFile;
        private readonly StreamWriter _logFileLatest;
        private string _lastLine;
        private int _lastLineCount;

        // Instantiate a SafeHandle instance.

        public Logger() {

        }

        public Logger(string logName, string latest) {
            _logName = logName;
            _logFile = new StreamWriter(logName, true);
            _logFileLatest = new StreamWriter(latest);
        }

        // Public implementation of Dispose pattern callable by consumers.
        public void Dispose() {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        // Protected implementation of Dispose pattern.
        protected virtual void Dispose(bool disposing) {
            if (_disposed)
                return;

            if (disposing) {
                _logFile.Dispose();
                _logFileLatest.Dispose();
                // Free any other managed objects here.
                //
            }

            // Free any unmanaged objects here.
            //
            _disposed = true;
        }

        private void WriteLineBoth(string v) {
            _logFile.WriteLine(v);
            _logFileLatest.WriteLine(v);
            using (var current = new StreamWriter(_logName + "-current.txt", true)) {
                current.WriteLine(v);
            }
        }

        internal void WriteLine(string v) {
            if (!v.Equals(_lastLine)) {
                if (_lastLineCount > 0) {
                    WriteLineBoth($"Last message repeated {_lastLineCount} times.");
                }
                WriteLineBoth(v);
                _lastLineCount = 0;
            }
            else {
                _lastLineCount++;
            }
            _lastLine = v;
        }
    }
}