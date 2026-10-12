using System;
using System.Runtime.InteropServices;

namespace ScientificSecurity
{
    // x64 SDK context marshalling only. Callers own and prove stopped-thread lifetime.
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
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetThreadContext(IntPtr thread, IntPtr context);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetThreadContext(IntPtr thread, IntPtr context);
    }
}
