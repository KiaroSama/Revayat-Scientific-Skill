using System;
using System.Runtime.InteropServices;

namespace ScientificSecurity
{
    // x64 SDK context marshalling and stage-specific trap attribution. Callers prove stopped-thread lifetime.
    internal static class DebugContext
    {
        internal const int Size = 1232, Flags = 48;
        internal static byte[] Read(IntPtr thread)
        {
            IntPtr allocation = Marshal.AllocHGlobal(Size + 15);
            try {
                IntPtr context = new IntPtr((allocation.ToInt64() + 15) & ~15L);
                Marshal.Copy(new byte[Size], 0, context, Size);
                Marshal.WriteInt32(context, Flags, 0x100013);
                Native.Check(GetThreadContext(thread, context), "read stopped creator context for hardware diagnostic");
                byte[] bytes = new byte[Size]; Marshal.Copy(context, bytes, 0, Size); return bytes;
            }
            finally { Release(allocation); }
        }
        internal static void Write(IntPtr thread, byte[] bytes)
        {
            if (bytes == null || bytes.Length != Size || BitConverter.ToUInt32(bytes, Flags) != 0x100010)
                throw new InvalidOperationException("hardware context write must select DEBUG_REGISTERS only");
            IntPtr allocation = Marshal.AllocHGlobal(Size + 15);
            try {
                IntPtr context = new IntPtr((allocation.ToInt64() + 15) & ~15L);
                Marshal.Copy(bytes, 0, context, Size);
                Native.Check(SetThreadContext(thread, context), "set only stopped creator debug-register context");
            }
            finally { Release(allocation); }
        }
        static void Release(IntPtr allocation)
        {
            try { for (int offset = 0; offset < Size + 15; offset++) Marshal.WriteByte(allocation, offset, 0); }
            finally { Marshal.FreeHGlobal(allocation); }
        }
        internal static bool UnchangedControlInteger(byte[] before, byte[] after)
        {
            foreach (int offset in new [] { 56, 66 })
                if (BitConverter.ToUInt16(before, offset) != BitConverter.ToUInt16(after, offset)) return false;
            if (BitConverter.ToUInt32(before, 68) != BitConverter.ToUInt32(after, 68)) return false;
            for (int offset = 120; offset <= 248; offset += 8)
                if (BitConverter.ToUInt64(before, offset) != BitConverter.ToUInt64(after, offset)) return false;
            return true;
        }
        // Regression model: event payload differs from idle; it is not a setter readback.
        internal static void CheckTrapValidation()
        {
            foreach (int slot in new [] { 0, 1 })
                foreach (ulong rtm in new ulong[] { 0, 0x10000 })
                    foreach (ulong fixedBit in new ulong[] { 0, 0x400 }) {
                        ulong control = 1UL << (slot * 2), cause = 1UL << slot;
                        ulong status = 0xFFFE0FF0UL | rtm | cause;
                        bool oldIdleComparison = (status & ~3UL) == 0 && (control | fixedBit) == control;
                        if (oldIdleComparison || !OwnedTrapStatus(status, control | fixedBit, control, slot))
                            throw new InvalidOperationException("owned trap regression model did not separate event and setter stages");
                        foreach (ulong foreign in new ulong[] { 4, 8, 0x2000, 0x4000, 0x8000, 0x100000000 })
                            if (OwnedTrapStatus(status | foreign, control, control, slot))
                                throw new InvalidOperationException("owned trap accepted a foreign cause/status shape");
                        foreach (ulong foreign in new ulong[] { 2, 0x100, 0x200, 0x800, 0x2000, 0x10000, 0x40000, 0x100000000 })
                            if (OwnedTrapStatus(status, control | foreign, control, slot))
                                throw new InvalidOperationException("owned trap accepted an unowned debug control");
                        if (OwnedTrapStatus(status ^ 0x800, control, control, slot) ||
                            OwnedTrapStatus(status ^ 0x10, control, control, slot) ||
                            OwnedTrapStatus(status | 0x1000, control, control, slot) ||
                            OwnedTrapStatus(status, control, control, 1 - slot) ||
                            OwnedTrapStatus(status | (1UL << (1 - slot)), control, control, slot) ||
                            OwnedTrapStatus(status, control | 0x800, control | 0x800, slot) ||
                            OwnedTrapStatus(status, 0, 0, slot))
                            throw new InvalidOperationException("owned trap accepted inactive, bus-lock or unsupported controls");
                    }
            if (!OwnedTrapSite(7, 7, true, true, 100, 100) || OwnedTrapSite(8, 7, true, true, 100, 100) ||
                OwnedTrapSite(7, 7, false, true, 100, 100) || OwnedTrapSite(7, 7, true, false, 100, 100) ||
                OwnedTrapSite(7, 7, true, true, 101, 100) || OwnedTrapSite(7, 7, true, true, 0, 0))
                throw new InvalidOperationException("owned trap lost creator/chance/active-site attribution");
            byte[] idle = new byte[Size], trap = (byte[])idle.Clone();
            BitConverter.GetBytes(0xFFFE0FF1UL).CopyTo(trap, 104);
            BitConverter.GetBytes(0x401UL).CopyTo(trap, 112);
            if (RawDebugEqual(idle, trap) || !UnchangedControlInteger(idle, trap))
                throw new InvalidOperationException("event status was accepted as exact setter readback");
            foreach (int offset in new [] { 72, 80, 88, 96, 104, 112 }) {
                byte[] changed = (byte[])idle.Clone(); changed[offset] = 1;
                if (RawDebugEqual(idle, changed)) throw new InvalidOperationException("setter readback lost raw debug equality");
            }
            foreach (int offset in new [] { 56, 66, 68, 120, 128, 136, 152, 248 }) {
                byte[] changed = (byte[])idle.Clone(); changed[offset] = 1;
                if (UnchangedControlInteger(idle, changed))
                    throw new InvalidOperationException("setter context immutability accepted an unexpected CONTROL/INTEGER change");
            }
            string clear = TrapQualifiers(0xFFFE0FF1), set = TrapQualifiers(0xFFFF0FF1);
            if (!clear.Contains("rtm_bit_set=False") || !set.Contains("rtm_bit_set=True") ||
                !clear.Contains("bld_bit_set=True") || !clear.Contains("transaction_context=unknown"))
                throw new InvalidOperationException("owned trap qualifiers lost meaningful raw RTM/BLD state");
        }
        internal static bool OwnedTrapStatus(ulong status, ulong control, ulong expectedControl, int slot)
        {
            if (slot < 0 || slot > 1 || (expectedControl & ~0x405UL) != 0) return false;
            ulong enabled = 1UL << (slot * 2);
            return (expectedControl & enabled) != 0 && ((control ^ expectedControl) & ~0x400UL) == 0 &&
                (status & 0xE00FUL) == (1UL << slot) &&
                (status & ~(0x10000UL | 3UL)) == 0xFFFE0FF0UL;
        }
        internal static bool OwnedTrapSite(uint eventThread, uint creatorThread, bool firstChance, bool enabled,
            ulong instruction, ulong configured)
        { return eventThread == creatorThread && firstChance && enabled && configured != 0 && instruction == configured; }
        internal static string TrapQualifiers(ulong status)
        {
            return "raw_dr6=0x" + status.ToString("X16") + " rtm_bit_set=" + ((status & 0x10000) != 0)
                + " bld_bit_set=" + ((status & 0x800) != 0) + " transaction_context=unknown";
        }
        internal static bool RawDebugEqual(byte[] expected, byte[] actual)
        {
            for (int offset = 72; offset <= 112; offset += 8)
                if (BitConverter.ToUInt64(expected, offset) != BitConverter.ToUInt64(actual, offset)) return false;
            return true;
        }
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetThreadContext(IntPtr thread, IntPtr context);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetThreadContext(IntPtr thread, IntPtr context);
    }
}
