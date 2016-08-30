﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AsmJitAssembleLib {
    public enum RegisterType {
        RipRegister,
        GpRegister,
        FpRegister,
        XmmRegister,
        YmmRegister,
        SegRegister,
        MmRegister
    }

    public class MaybeRegister {
        public bool Present;
        public RegisterType Type;
        public object Register;
    }
}
