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
