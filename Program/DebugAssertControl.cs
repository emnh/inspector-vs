using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Program {

    public class MyTraceListener : TraceListener {
        private readonly Action<string> _log;

        public MyTraceListener(Action<string> log) {
            _log = log;
        }

        public override void Fail(string msg, string detailedMsg) {
            // log the message (don't display a MessageBox)
            _log(msg);
        }

        public override void Write(string message) {
            throw new NotImplementedException();
        }

        public override void WriteLine(string message) {
            throw new NotImplementedException();
        }
    }

    public class DebugAssertControl : IDisposable {

        private readonly List<TraceListener> _oldListeners = new List<TraceListener>();

        public DebugAssertControl(Action<string> log) {
            foreach (TraceListener listener in Debug.Listeners) {
                _oldListeners.Add(listener);
            }
            Debug.Listeners.Clear();
            Debug.Listeners.Add(new MyTraceListener(log));
        }

        public void Dispose() {
            _oldListeners.AddRange(_oldListeners);
        }
    }
}
