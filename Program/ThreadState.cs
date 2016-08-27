using System.Collections.Generic;

namespace Program {
    public class ThreadState {
        public Dictionary<int, Win32Imports.ContextX64> OldState;
    }
}