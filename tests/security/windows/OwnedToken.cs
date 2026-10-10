using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace ScientificSecurity
{
    // Owned restricted primary token; never mutates the privileged preparation/cleanup token.
    internal sealed class OwnedToken : IDisposable
    {
        [StructLayout(LayoutKind.Sequential)] struct SidAttributes { internal IntPtr sid; internal uint attributes; }
        [StructLayout(LayoutKind.Sequential)] struct GroupHeader { internal uint count; internal SidAttributes first; }
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CreateRestrictedToken(IntPtr existing, uint flags, uint disableCount, IntPtr disableSids,
            uint deleteCount, IntPtr deletePrivileges, uint restrictCount, IntPtr restrictingSids, out IntPtr token);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CreateProcessAsUserW(IntPtr token, string application, StringBuilder command,
            IntPtr processAttributes, IntPtr threadAttributes, bool inherit, uint flags,
            IntPtr environment, string cwd, ref Native.StartupEx startup, out Native.ProcessInfo info);
        internal IntPtr Handle { get; private set; }
        private OwnedToken(IntPtr token) { Handle = token; }
        internal static OwnedToken Create()
        {
            IntPtr original = IntPtr.Zero, restricted = IntPtr.Zero, sid = IntPtr.Zero, disabled = IntPtr.Zero;
            try {
                // QUERY | DUPLICATE | ASSIGN_PRIMARY; returned restricted handle retains these rights.
                Native.Check(Native.OpenProcessToken(Native.GetCurrentProcess(), 0xB, out original), "open original primary token for restricted copy");
                var admin = new SecurityIdentifier("S-1-5-32-544");
                byte[] bytes = new byte[admin.BinaryLength]; admin.GetBinaryForm(bytes, 0);
                sid = Marshal.AllocHGlobal(bytes.Length); Marshal.Copy(bytes, 0, sid, bytes.Length);
                disabled = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SidAttributes)));
                Marshal.StructureToPtr(new SidAttributes { sid = sid, attributes = 0 }, disabled, false);
                // LUA_TOKEN | DISABLE_MAX_PRIVILEGE. Do not use SANDBOX_INERT or an unrestricted fallback.
                Native.Check(CreateRestrictedToken(original, 0x4 | 0x1, 1, disabled,
                    0, IntPtr.Zero, 0, IntPtr.Zero, out restricted), "create owned LUA primary with Administrators deny-only");
                RequireNoAdminOwner(restricted);
                Console.Out.WriteLine("WINDOWS_RESTRICTED_BASE admin_owner_absent=true admin_enabled_absent=true");
                Console.Out.Flush();
                var result = new OwnedToken(restricted); restricted = IntPtr.Zero;
                return result;
            }
            finally {
                if (restricted != IntPtr.Zero) Native.CloseHandle(restricted);
                if (disabled != IntPtr.Zero) Marshal.FreeHGlobal(disabled);
                if (sid != IntPtr.Zero) Marshal.FreeHGlobal(sid);
                if (original != IntPtr.Zero) Native.CloseHandle(original);
            }
        }
        internal static void RequireNoAdminOwner(IntPtr token)
        {
            uint size;
            bool initial = Native.GetTokenInformation(token, 2, IntPtr.Zero, 0, out size);
            int initialError = Marshal.GetLastWin32Error();
            if (initial || initialError != 122 || size < 4 || size > 65536)
                throw new InvalidOperationException("restricted token groups size query is invalid");
            IntPtr data = Marshal.AllocHGlobal((int)size);
            try {
                uint capacity = size;
                Native.Check(Native.GetTokenInformation(token, 2, data, capacity, out size), "read exact restricted Administrators attributes");
                if (size < 4 || size > capacity) throw new InvalidOperationException("restricted token group buffer is invalid");
                uint count = unchecked((uint)Marshal.ReadInt32(data));
                int offset = Marshal.OffsetOf(typeof(GroupHeader), "first").ToInt32();
                int stride = Marshal.SizeOf(typeof(SidAttributes));
                if (count > 256 || (count != 0 && (ulong)offset + (ulong)stride * count > size))
                    throw new InvalidOperationException("restricted token group count exceeds buffer bounds");
                for (int index = 0; index < count; index++) {
                    var group = (SidAttributes)Marshal.PtrToStructure(IntPtr.Add(data, offset + index * stride), typeof(SidAttributes));
                    if (new SecurityIdentifier(group.sid).Value != "S-1-5-32-544") continue;
                    if ((group.attributes & (8 | 4 | 2)) != 0 || (group.attributes & 16) == 0)
                        throw new InvalidOperationException("Administrators retains owner/enabled authority in restricted token");
                }
            }
            finally { Marshal.FreeHGlobal(data); }
        }
        public void Dispose()
        {
            IntPtr token = Handle; Handle = IntPtr.Zero;
            if (token != IntPtr.Zero) Native.Check(Native.CloseHandle(token), "close owned restricted primary token");
        }
    }
}
