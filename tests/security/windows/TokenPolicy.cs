using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace ScientificSecurity
{
    // Apply to the exact suspended LPAC token, then close the finite quota-owner set before resume.
    internal static class TokenPolicy
    {
        [StructLayout(LayoutKind.Sequential)] struct SidAttributes { internal IntPtr sid; internal uint attributes; }
        [StructLayout(LayoutKind.Sequential)] struct GroupHeader { internal uint count; internal SidAttributes first; }
        [StructLayout(LayoutKind.Sequential)] struct Luid { internal uint low; internal int high; }
        [StructLayout(LayoutKind.Sequential)] struct LuidAttributes { internal Luid luid; internal uint attributes; }
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, IntPtr state, uint bytes,
                                                IntPtr previous, IntPtr returned);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool LookupPrivilegeValueW(string system, string name, out Luid luid);

        static IntPtr Query(IntPtr token, int kind)
        {
            uint bytes;
            Native.GetTokenInformation(token, kind, IntPtr.Zero, 0, out bytes);
            if (bytes < 4 || bytes > 65536) throw new InvalidOperationException("unexpected token information size");
            IntPtr data = Marshal.AllocHGlobal((int)bytes);
            try {
                uint capacity = bytes;
                Native.Check(Native.GetTokenInformation(token, kind, data, capacity, out bytes), "query effective token policy");
                if (bytes > capacity) throw new InvalidOperationException("token data grew beyond allocated buffer");
                int offset = kind == 2 ? Marshal.OffsetOf(typeof(GroupHeader), "first").ToInt32() : 4;
                int stride = kind == 2 ? Marshal.SizeOf(typeof(SidAttributes)) : Marshal.SizeOf(typeof(LuidAttributes));
                if (kind == 2 || kind == 3) {
                    uint count = unchecked((uint)Marshal.ReadInt32(data));
                    if ((ulong)offset + (ulong)stride * count > bytes) throw new InvalidOperationException("token count exceeds native buffer");
                }
                else if (bytes < IntPtr.Size) throw new InvalidOperationException("token SID pointer buffer is truncated");
            }
            catch { Marshal.FreeHGlobal(data); throw; }
            return data;
        }
        internal static void Prepare(IntPtr process, string volume, string packageSid)
        {
            IntPtr token = IntPtr.Zero, data = IntPtr.Zero, owner = IntPtr.Zero;
            try
            {
                Native.Check(Native.OpenProcessToken(process, 0xA8, out token), "open suspended LPAC policy token");
                Luid traverse;
                Native.Check(LookupPrivilegeValueW(null, "SeChangeNotifyPrivilege", out traverse), "resolve allowed traversal privilege");
                data = Query(token, 3);
                uint count = unchecked((uint)Marshal.ReadInt32(data));
                if (count > 128) throw new InvalidOperationException("token privilege count exceeds finite bound");
                var removals = new List<Luid>();
                int stride = Marshal.SizeOf(typeof(LuidAttributes));
                for (int index = 0; index < count; index++) {
                    var privilege = (LuidAttributes)Marshal.PtrToStructure(IntPtr.Add(data, 4 + index * stride), typeof(LuidAttributes));
                    if (privilege.luid.low != traverse.low || privilege.luid.high != traverse.high) removals.Add(privilege.luid);
                }
                Marshal.FreeHGlobal(data); data = IntPtr.Zero;
                if (removals.Count != 0) {
                    IntPtr state = Marshal.AllocHGlobal(4 + stride * removals.Count);
                    try {
                        Marshal.WriteInt32(state, removals.Count);
                        for (int index = 0; index < removals.Count; index++)
                            Marshal.StructureToPtr(new LuidAttributes { luid = removals[index], attributes = 4 },
                                IntPtr.Add(state, 4 + index * stride), false);
                        Native.Check(AdjustTokenPrivileges(token, false, state, 0, IntPtr.Zero, IntPtr.Zero), "remove dangerous child privileges irreversibly");
                        int error = Marshal.GetLastWin32Error();
                        if (error != 0) throw new System.ComponentModel.Win32Exception(error, "privilege removal was not fully assigned");
                    }
                    finally { Marshal.FreeHGlobal(state); }
                }
                data = Query(token, 3);
                count = unchecked((uint)Marshal.ReadInt32(data));
                if (count > 128) throw new InvalidOperationException("post-removal privilege count exceeds finite bound");
                for (int index = 0; index < count; index++) {
                    var privilege = (LuidAttributes)Marshal.PtrToStructure(IntPtr.Add(data, 4 + index * stride), typeof(LuidAttributes));
                    if (privilege.luid.low != traverse.low || privilege.luid.high != traverse.high)
                        throw new InvalidOperationException("dangerous privilege remains in actual child token");
                }
                Marshal.FreeHGlobal(data); data = Query(token, 1);
                string userSid = new SecurityIdentifier(Marshal.ReadIntPtr(data)).Value;
                owner = Marshal.AllocHGlobal(IntPtr.Size); Marshal.WriteIntPtr(owner, Marshal.ReadIntPtr(data));
                Native.Check(Native.SetTokenInformation(token, 4, owner, (uint)IntPtr.Size), "set finite quota user as default file owner");
                Marshal.FreeHGlobal(owner); owner = IntPtr.Zero;
                Marshal.FreeHGlobal(data); data = IntPtr.Zero;
                var owners = new HashSet<string>(StringComparer.Ordinal) { userSid, packageSid };
                data = Query(token, 2); count = unchecked((uint)Marshal.ReadInt32(data));
                if (count > 256) throw new InvalidOperationException("token group count exceeds finite bound");
                int offset = Marshal.OffsetOf(typeof(GroupHeader), "first").ToInt32();
                stride = Marshal.SizeOf(typeof(SidAttributes));
                for (int index = 0; index < count; index++) {
                    var group = (SidAttributes)Marshal.PtrToStructure(IntPtr.Add(data, offset + index * stride), typeof(SidAttributes));
                    if ((group.attributes & 8) != 0) owners.Add(new SecurityIdentifier(group.sid).Value);
                }
                Marshal.FreeHGlobal(data); data = IntPtr.Zero;
                if (owners.Count > 16) throw new InvalidOperationException("assignable quota owners exceed finite bound");
                foreach (string sid in owners.OrderBy(value => value, StringComparer.Ordinal)) QuotaSid.SetOwnerEntry(volume, sid);
                // The trusted child independently enumerates this token and its descendants;
                // every resulting owner is exercised against the kernel quota boundary.
                Console.Out.WriteLine("WINDOWS_TOKEN_POLICY privileges=traversal-only quota_owners=[" +
                    String.Join(",", owners.OrderBy(value => value, StringComparer.Ordinal)) + "]");
                Console.Out.Flush();
            }
            finally
            {
                if (owner != IntPtr.Zero) Marshal.FreeHGlobal(owner);
                if (data != IntPtr.Zero) Marshal.FreeHGlobal(data);
                if (token != IntPtr.Zero) Native.CloseHandle(token);
            }
        }
    }
}
