using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace ScientificSecurity
{
    // Qualifies only the exact primary/duplicate/effective contexts of profile access controls.
    internal sealed class RegistryContext
    {
        [StructLayout(LayoutKind.Sequential)] struct SidAttributes { internal IntPtr sid; internal uint attributes; }
        [StructLayout(LayoutKind.Sequential)] struct GroupHeader { internal uint count; internal SidAttributes first; }
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenThreadToken(IntPtr thread, uint access, bool asSelf, out IntPtr token);
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
        readonly Snapshot expected;
        internal RegistryContext(IntPtr primary, IntPtr duplicate, string assignedPackage)
        {
            expected = Read(primary, false);
            if (expected.package != assignedPackage)
                throw new InvalidOperationException("registry control primary token is not the assigned package");
            RequireEqual(expected, Read(duplicate, true));
        }
        internal void RequireThread()
        {
            IntPtr token = IntPtr.Zero;
            try {
                Native.Check(OpenThreadToken(GetCurrentThread(), 8, true, out token), "open actual effective registry control token");
                RequireEqual(expected, Read(token, true));
            }
            finally { if (token != IntPtr.Zero) Native.Check(Native.CloseHandle(token), "close effective registry control token"); }
        }
        sealed class Snapshot
        {
            internal string user, package;
            internal string[] restricted;
        }
        sealed class Buffer : IDisposable
        {
            internal IntPtr pointer;
            internal uint size;
            internal Buffer(IntPtr token, int kind)
            {
                uint capacity;
                bool initial = Native.GetTokenInformation(token, kind, IntPtr.Zero, 0, out capacity);
                int error = Marshal.GetLastWin32Error();
                if (initial || error != 122 || capacity < 4 || capacity > 65536)
                    throw new InvalidOperationException("registry context query size is invalid kind=" + kind + " initial_success=" + initial + " native_error=" + error + " bytes=" + capacity);
                pointer = Marshal.AllocHGlobal((int)capacity);
                try {
                    Native.Check(Native.GetTokenInformation(token, kind, pointer, capacity, out size), "query bounded registry token context kind=" + kind);
                    if (size < 4 || size > capacity) throw new InvalidOperationException("registry context returned length is invalid");
                }
                catch { Dispose(); throw; }
            }
            internal void Range(IntPtr value, uint bytes)
            {
                ulong start = unchecked((ulong)pointer.ToInt64()), address = unchecked((ulong)value.ToInt64());
                if (!Within(start, size, address, bytes))
                    throw new InvalidOperationException("registry token SID points outside returned allocation");
            }
            internal string Sid(IntPtr value)
            {
                Range(value, 8);
                byte revision = Marshal.ReadByte(value), count = Marshal.ReadByte(value, 1);
                if (revision != 1 || count > 15) throw new InvalidOperationException("registry token SID header is invalid");
                uint bytes = 8U + 4U * count; Range(value, bytes);
                byte[] binary = new byte[bytes]; Marshal.Copy(value, binary, 0, binary.Length);
                return new SecurityIdentifier(binary, 0).Value;
            }
            public void Dispose() { if (pointer != IntPtr.Zero) { Marshal.FreeHGlobal(pointer); pointer = IntPtr.Zero; } }
        }
        static uint Scalar(IntPtr token, int kind)
        {
            using (var data = new Buffer(token, kind)) {
                if (data.size != 4) throw new InvalidOperationException("registry context scalar ABI is invalid");
                return unchecked((uint)Marshal.ReadInt32(data.pointer));
            }
        }
        static string TokenSid(IntPtr token, int kind)
        {
            using (var data = new Buffer(token, kind)) {
                uint minimum = kind == 1 ? (uint)Marshal.SizeOf(typeof(SidAttributes)) : (uint)IntPtr.Size;
                if (data.size < minimum) throw new InvalidOperationException("registry context SID pointer ABI is invalid");
                return data.Sid(Marshal.ReadIntPtr(data.pointer));
            }
        }
        static string[] Groups(IntPtr token, int kind)
        {
            using (var data = new Buffer(token, kind)) {
                uint count = unchecked((uint)Marshal.ReadInt32(data.pointer));
                int offset = Marshal.OffsetOf(typeof(GroupHeader), "first").ToInt32();
                int stride = Marshal.SizeOf(typeof(SidAttributes));
                if (count > 256 || (count != 0 && (ulong)offset + (ulong)stride * count > data.size))
                    throw new InvalidOperationException("registry context group set exceeds returned allocation");
                var result = new string[count];
                for (int index = 0; index < count; index++) {
                    var entry = (SidAttributes)Marshal.PtrToStructure(IntPtr.Add(data.pointer, offset + index * stride), typeof(SidAttributes));
                    result[index] = data.Sid(entry.sid) + "|" + entry.attributes.ToString("X8");
                }
                Array.Sort(result, StringComparer.Ordinal); return result; // sorted multiset retains duplicates.
            }
        }
        static Snapshot Read(IntPtr token, bool impersonation)
        {
            uint type = Scalar(token, 8), level = impersonation ? Scalar(token, 9) : 0,
                appContainer = Scalar(token, 29), lpac = LpacQuery.Read(token);
            int capabilities = Groups(token, 30).Length;
            if (type != (impersonation ? 2U : 1U) || (impersonation && level != 2) ||
                appContainer != 1 || lpac != 1 || capabilities != 0)
                throw new InvalidOperationException("registry control lost exact zero-capability LPAC token context type=" + type
                    + " level=" + level + " app_container=" + appContainer + " lpac=" + lpac + " capability_count=" + capabilities);
            return new Snapshot { user = TokenSid(token, 1), package = TokenSid(token, 31), restricted = Groups(token, 11) };
        }
        static bool Within(ulong start, uint size, ulong address, uint bytes)
        {
            return address >= start && address - start <= size && bytes <= size - (address - start);
        }
        internal static void CheckValidation()
        {
            LpacQuery.CheckValidation();
            if (!Within(100, 16, 100, 16) || !Within(100, 16, 108, 8) || Within(100, 16, 99, 1) ||
                Within(100, 16, 108, 9) || Within(UInt64.MaxValue - 8, 8, 1, 1))
                throw new InvalidOperationException("registry context buffer range self-check failed");
            var expected = new Snapshot { user = "user", package = "package", restricted = new [] { "a|01", "a|01", "b|02" } };
            RequireEqual(expected, new Snapshot { user = "user", package = "package", restricted = new [] { "a|01", "a|01", "b|02" } });
            bool rejected = false;
            try { RequireEqual(expected, new Snapshot { user = "user", package = "package", restricted = new [] { "a|01", "b|02", "b|02" } }); }
            catch (InvalidOperationException) { rejected = true; }
            if (!rejected) throw new InvalidOperationException("registry context multiset multiplicity self-check failed");
        }
        static void RequireEqual(Snapshot expected, Snapshot actual)
        {
            bool user = expected.user == actual.user, package = expected.package == actual.package,
                restricted = expected.restricted.SequenceEqual(actual.restricted, StringComparer.Ordinal);
            if (!user || !package || !restricted)
                throw new InvalidOperationException("registry control token identity changed user_equal=" + user
                    + " package_equal=" + package + " restricted_multiset_equal=" + restricted);
        }
    }
}
