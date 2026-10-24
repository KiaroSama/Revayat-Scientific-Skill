using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace ScientificSecurity
{
    // Only the two retained handles of the controller's own suspended child are accepted.
    internal static class OwnProcessAccess
    {
        [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(IntPtr handle, int kind, uint information,
            out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
        [DllImport("advapi32.dll")] static extern uint SetSecurityInfo(IntPtr handle, int kind, uint information,
            IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
        [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetSecurityDescriptorDacl(IntPtr descriptor,
            out bool present, out IntPtr dacl, out bool defaulted);

        internal static void Repair(Native.ProcessInfo child)
        {
            IntPtr token = IntPtr.Zero;
            try {
                Native.Check(Native.OpenProcessToken(child.process, 8, out token), "query exact child identity for own-object DACL");
                SecurityIdentifier user = TokenSid(token, 1), package = TokenSid(token, 31);
                if (!package.Value.StartsWith("S-1-15-2-", StringComparison.Ordinal))
                    throw new InvalidOperationException("own-object repair requires actual AppContainer identity");
                RepairObject(child.process, user, package);
                RepairObject(child.thread, user, package);
            }
            finally { if (token != IntPtr.Zero) Native.Check(Native.CloseHandle(token), "close own-object identity token"); }
        }
        static SecurityIdentifier TokenSid(IntPtr token, int kind)
        {
            uint bytes;
            bool initial = Native.GetTokenInformation(token, kind, IntPtr.Zero, 0, out bytes);
            if (initial || Marshal.GetLastWin32Error() != 122 || bytes < IntPtr.Size || bytes > 65536)
                throw new InvalidOperationException("own-object token SID query size is invalid");
            IntPtr buffer = Marshal.AllocHGlobal((int)bytes);
            try {
                uint capacity = bytes;
                Native.Check(Native.GetTokenInformation(token, kind, buffer, capacity, out bytes), "read actual own-object principal");
                if (bytes < IntPtr.Size || bytes > capacity || Marshal.ReadIntPtr(buffer) == IntPtr.Zero)
                    throw new InvalidOperationException("own-object token SID buffer is invalid");
                return new SecurityIdentifier(Marshal.ReadIntPtr(buffer));
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        static RawSecurityDescriptor Read(IntPtr handle)
        {
            IntPtr descriptor = IntPtr.Zero, owner, group, dacl, label;
            try {
                // LABEL_SECURITY_INFORMATION requires READ_CONTROL, not full audit-SACL access.
                uint result = GetSecurityInfo(handle, 6, 1 | 2 | 4 | 16, out owner, out group, out dacl, out label, out descriptor);
                if (result != 0) throw new System.ComponentModel.Win32Exception((int)result, "read own-object DACL/owner/mandatory label");
                if (descriptor == IntPtr.Zero || dacl == IntPtr.Zero)
                    throw new InvalidOperationException("own-object security descriptor or DACL is absent");
                uint bytes = GetSecurityDescriptorLength(descriptor);
                if (bytes < 20 || bytes > 65536) throw new InvalidOperationException("own-object security descriptor size is invalid");
                var binary = new byte[bytes]; Marshal.Copy(descriptor, binary, 0, binary.Length);
                return new RawSecurityDescriptor(binary, 0);
            }
            finally { if (descriptor != IntPtr.Zero) Native.LocalFree(descriptor); }
        }
        static void RepairObject(IntPtr handle, SecurityIdentifier user, SecurityIdentifier package)
        {
            RawSecurityDescriptor before = Read(handle);
            SecurityIdentifier[] identities = { new SecurityIdentifier("S-1-5-18"), new SecurityIdentifier("S-1-5-32-544"), package };
            if (before.DiscretionaryAcl == null || before.DiscretionaryAcl.Count != 3)
                throw new InvalidOperationException("old own-object DACL is not the exact three-entry policy");
            var firstAce = before.DiscretionaryAcl[0] as CommonAce;
            if (firstAce == null) throw new InvalidOperationException("old own-object first ACE is not a simple allow");
            int access = firstAce.AccessMask;
            // GENERIC_ALL may already be mapped to PROCESS_ALL_ACCESS/THREAD_ALL_ACCESS.
            if (access != 0x10000000 && access != 0x1FFFFF)
                throw new InvalidOperationException("old own-object policy is not generic/full same-object access");
            for (int index = 0; index < identities.Length; index++) {
                var ace = before.DiscretionaryAcl[index] as CommonAce;
                if (ace == null || ace.AceQualifier != AceQualifier.AccessAllowed || ace.IsCallback ||
                    ace.AceFlags != AceFlags.None || ace.AccessMask != access || !ace.SecurityIdentifier.Equals(identities[index]))
                    throw new InvalidOperationException("old own-object ACE differs from assigned policy");
            }
            byte[] source = new byte[before.BinaryLength]; before.GetBinaryForm(source, 0);
            var expected = new RawSecurityDescriptor(source, 0);
            expected.DiscretionaryAcl.InsertAce(2, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed,
                access, user, false, null));
            var bytes = new byte[expected.BinaryLength]; expected.GetBinaryForm(bytes, 0);
            IntPtr data = Marshal.AllocHGlobal(bytes.Length);
            try {
                Marshal.Copy(bytes, 0, data, bytes.Length);
                bool present, defaulted; IntPtr dacl;
                Native.Check(GetSecurityDescriptorDacl(data, out present, out dacl, out defaulted), "obtain exact own-object DACL pointer");
                if (!present || dacl == IntPtr.Zero) throw new InvalidOperationException("own-object replacement DACL is absent");
                uint result = SetSecurityInfo(handle, 6, 4, IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
                if (result != 0) throw new System.ComponentModel.Win32Exception((int)result, "persist only own-object user DACL entry");
            }
            finally { Marshal.FreeHGlobal(data); }
            RawSecurityDescriptor actual = Read(handle);
            if (actual.ControlFlags != expected.ControlFlags || !Equals(actual.Owner, before.Owner) || !Equals(actual.Group, before.Group) ||
                !AclBytes(actual.DiscretionaryAcl).SequenceEqual(AclBytes(expected.DiscretionaryAcl)) ||
                !AclBytes(actual.SystemAcl).SequenceEqual(AclBytes(before.SystemAcl)))
                throw new InvalidOperationException("own-object four-entry DACL/owner/mandatory label readback differs");
        }
        static byte[] AclBytes(RawAcl acl)
        {
            if (acl == null) return new byte[0];
            var bytes = new byte[acl.BinaryLength]; acl.GetBinaryForm(bytes, 0); return bytes;
        }
    }
}
