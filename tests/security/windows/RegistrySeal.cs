using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using Microsoft.Win32.SafeHandles;
using System.Security.Principal;

namespace ScientificSecurity
{
    // Corrected-profile DACL persistence only; no reopen, privileges or alternate setter fallback.
    internal static class RegistrySeal
    {
        [DllImport("advapi32.dll")] static extern int RegSetKeySecurity(IntPtr key, uint information, IntPtr descriptor);
        [DllImport("ntdll.dll")] static extern int NtQueryObject(IntPtr key, int kind, IntPtr buffer, uint bytes, out uint returned);
        [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(IntPtr key, int kind, uint information,
            out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr label, out IntPtr descriptor);
        [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr pointer);

        internal static void Persist(SafeRegistryHandle handle, RegistrySecurity acl)
        {
            if (!acl.AreAccessRulesCanonical || !acl.AreAccessRulesProtected)
                throw new InvalidOperationException("registry seal source policy is not protected and canonical");
            byte[] bytes = acl.GetSecurityDescriptorBinaryForm();
            Validate(bytes);
            bool retained = false;
            IntPtr descriptor = IntPtr.Zero, basic = IntPtr.Zero;
            try {
                handle.DangerousAddRef(ref retained);
                IntPtr key = handle.DangerousGetHandle();
                if (handle.IsInvalid || key.ToInt64() <= 0 ||
                    (key.ToInt64() >= 0x80000000L && key.ToInt64() <= 0x800000FFL))
                    throw new InvalidOperationException("registry seal requires a retained non-predefined native key");
                basic = Marshal.AllocHGlobal(56);
                uint returned;
                int status = NtQueryObject(key, 0, basic, 56, out returned);
                if (status != 0 || returned != 56)
                    throw new InvalidOperationException("registry seal held-rights query failed status=0x"
                        + unchecked((uint)status).ToString("X8") + " returned_bytes=" + returned);
                uint granted = unchecked((uint)Marshal.ReadInt32(basic, 4));
                if ((granted & 0x60000U) != 0x60000U)
                    throw new InvalidOperationException("registry seal retained key lacks READ_CONTROL/WRITE_DAC granted=0x" + granted.ToString("X8"));
                RawSecurityDescriptor before = ReadIdentityLabel(key);
                descriptor = Marshal.AllocHGlobal(bytes.Length);
                Marshal.Copy(bytes, 0, descriptor, bytes.Length);
                int result = RegSetKeySecurity(key, 0x80000004, descriptor); // DACL | PROTECTED_DACL only.
                if (result != 0)
                    throw new System.ComponentModel.Win32Exception(result, "persist corrected protected registry DACL");
                RequirePreserved(before, ReadIdentityLabel(key));
            }
            finally {
                try { if (descriptor != IntPtr.Zero) Marshal.FreeHGlobal(descriptor); }
                finally {
                    try { if (basic != IntPtr.Zero) Marshal.FreeHGlobal(basic); }
                    finally { if (retained) handle.DangerousRelease(); }
                }
            }
        }
        static void Validate(byte[] bytes)
        {
            if (bytes == null || bytes.Length < 20 || bytes.Length > 65536)
                throw new InvalidOperationException("registry seal descriptor exceeds fixed bounds");
            var descriptor = new RawSecurityDescriptor(bytes, 0);
            const ControlFlags required = ControlFlags.SelfRelative | ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclProtected;
            if ((descriptor.ControlFlags & required) != required || descriptor.DiscretionaryAcl == null ||
                descriptor.DiscretionaryAcl.Count != 6 || descriptor.Owner != null || descriptor.Group != null || descriptor.SystemAcl != null)
                throw new InvalidOperationException("registry seal requires a protected non-null six-ACE access-only descriptor");
            bool allowedSeen = false;
            // Inspect the original bytes: CommonAcl canonicalization sorts/compacts even valid input.
            foreach (GenericAce item in descriptor.DiscretionaryAcl) {
                var ace = item as CommonAce;
                if (ace == null || ace.IsCallback || ace.AceFlags != AceFlags.ContainerInherit || ace.AccessMask == 0 ||
                    (ace.AceQualifier != AceQualifier.AccessAllowed && ace.AceQualifier != AceQualifier.AccessDenied))
                    throw new InvalidOperationException("registry seal requires explicit container-inheritable allow/deny ACEs");
                if (ace.AceQualifier == AceQualifier.AccessAllowed) allowedSeen = true;
                else if (allowedSeen) throw new InvalidOperationException("registry seal deny follows an explicit allow");
            }
        }
        static RawSecurityDescriptor ReadIdentityLabel(IntPtr key)
        {
            IntPtr descriptor = IntPtr.Zero, owner, group, dacl, label;
            try {
                // LABEL_SECURITY_INFORMATION is queryable with READ_CONTROL; no full audit-SACL access.
                uint result = GetSecurityInfo(key, 4, 0x13, out owner, out group, out dacl, out label, out descriptor);
                if (result != 0) throw new System.ComponentModel.Win32Exception((int)result, "read retained registry owner/group/integrity label");
                if (descriptor == IntPtr.Zero || owner == IntPtr.Zero || group == IntPtr.Zero)
                    throw new InvalidOperationException("registry identity/label descriptor is incomplete");
                uint length = GetSecurityDescriptorLength(descriptor);
                if (length < 20 || length > 65536)
                    throw new InvalidOperationException("registry identity/label descriptor exceeds fixed bounds");
                byte[] bytes = new byte[length]; Marshal.Copy(descriptor, bytes, 0, bytes.Length);
                var parsed = new RawSecurityDescriptor(bytes, 0);
                if (parsed.Owner == null || parsed.Group == null)
                    throw new InvalidOperationException("registry identity descriptor omitted owner/group");
                return parsed;
            }
            finally {
                if (descriptor != IntPtr.Zero && LocalFree(descriptor) != IntPtr.Zero)
                    throw new InvalidOperationException("registry identity/label allocation cleanup failed");
            }
        }
        static byte[] AclBytes(GenericAcl acl)
        {
            if (acl == null) return null;
            byte[] bytes = new byte[acl.BinaryLength]; acl.GetBinaryForm(bytes, 0); return bytes;
        }
        static void RequireRejected(byte[] bytes, int fixture)
        {
            bool rejected = false;
            try { Validate(bytes); } catch (InvalidOperationException) { rejected = true; }
            if (!rejected) throw new InvalidOperationException("malformed registry seal descriptor was accepted fixture=" + fixture);
        }
        static void RequirePreserved(RawSecurityDescriptor before, RawSecurityDescriptor after)
        {
            byte[] original = AclBytes(before.SystemAcl), current = AclBytes(after.SystemAcl);
            if (!before.Owner.Equals(after.Owner) || !before.Group.Equals(after.Group) ||
                (before.ControlFlags & ~(ControlFlags)0x150C) != (after.ControlFlags & ~(ControlFlags)0x150C) ||
                (original == null) != (current == null) ||
                (original != null && !original.SequenceEqual(current)))
                throw new InvalidOperationException("registry DACL persistence changed owner/group/integrity label or control flags");
        }
        internal static void CheckValidation()
        {
            var valid = new RawSecurityDescriptor("D:P(A;CI;KR;;;SY)(A;CI;KR;;;BA)(A;CI;KR;;;BU)(A;CI;KR;;;WD)(A;CI;KR;;;RC)(A;CI;KR;;;S-1-15-2-1)");
            byte[] bytes = new byte[valid.BinaryLength]; valid.GetBinaryForm(bytes, 0);
            byte[] originalBytes = (byte[])bytes.Clone(); Validate(bytes);
            if (!bytes.SequenceEqual(originalBytes)) throw new InvalidOperationException("registry validation altered source bytes");
            var reordered = new RawSecurityDescriptor(bytes, 0);
            reordered.DiscretionaryAcl.RemoveAce(5);
            reordered.DiscretionaryAcl.InsertAce(5, new CommonAce(AceFlags.ContainerInherit, AceQualifier.AccessDenied,
                2, new System.Security.Principal.SecurityIdentifier("S-1-15-2-1"), false, null));
            byte[] noncanonical = new byte[reordered.BinaryLength]; reordered.GetBinaryForm(noncanonical, 0);
            bool orderRejected = false;
            try { Validate(noncanonical); } catch (InvalidOperationException) { orderRejected = true; }
            if (!orderRejected) throw new InvalidOperationException("noncanonical registry DACL was accepted");
            int fixture = 0;
            foreach (Action<RawSecurityDescriptor> change in new Action<RawSecurityDescriptor>[] {
                descriptor => descriptor.SetFlags(descriptor.ControlFlags & ~ControlFlags.DiscretionaryAclProtected),
                descriptor => descriptor.SetFlags(descriptor.ControlFlags & ~ControlFlags.DiscretionaryAclPresent),
                descriptor => descriptor.DiscretionaryAcl = null,
                descriptor => descriptor.DiscretionaryAcl = new RawAcl(2, 0),
                descriptor => descriptor.Owner = new System.Security.Principal.SecurityIdentifier("S-1-5-18"),
                descriptor => descriptor.Group = new System.Security.Principal.SecurityIdentifier("S-1-5-32-544"),
                descriptor => {
                    descriptor.SystemAcl = new RawSecurityDescriptor("S:(ML;;NW;;;LW)").SystemAcl;
                    descriptor.SetFlags(descriptor.ControlFlags | ControlFlags.SystemAclPresent);
                },
                descriptor => descriptor.DiscretionaryAcl[0].AceFlags |= AceFlags.Inherited,
                descriptor => descriptor.DiscretionaryAcl[0].AceFlags |= AceFlags.InheritOnly,
                descriptor => descriptor.DiscretionaryAcl[0] = new CommonAce(AceFlags.ContainerInherit, AceQualifier.AccessAllowed,
                    0x20019, new System.Security.Principal.SecurityIdentifier("S-1-5-18"), true, new byte[4])
            }) {
                var invalid = new RawSecurityDescriptor(bytes, 0); change(invalid);
                byte[] invalidBytes = new byte[invalid.BinaryLength]; invalid.GetBinaryForm(invalidBytes, 0);
                if (fixture == 6 && ((BitConverter.ToUInt16(invalidBytes, 2) & (ushort)ControlFlags.SystemAclPresent) == 0 ||
                    BitConverter.ToUInt32(invalidBytes, 12) == 0))
                    throw new InvalidOperationException("registry SACL negative fixture was not serialized as intended fixture=6");
                RequireRejected(invalidBytes, fixture++);
            }
            foreach (ControlFlags missing in new [] { ControlFlags.DiscretionaryAclPresent, ControlFlags.DiscretionaryAclProtected }) {
                byte[] invalid = (byte[])bytes.Clone();
                ushort flags = (ushort)(BitConverter.ToUInt16(invalid, 2) & ~(ushort)missing);
                BitConverter.GetBytes(flags).CopyTo(invalid, 2);
                RequireRejected(invalid, fixture++);
            }
            var policy = new RegistrySecurity(); policy.SetAccessRuleProtection(true, false);
            foreach (var identity in new [] { "S-1-3-4", "S-1-15-2-3" })
                policy.AddAccessRule(new RegistryAccessRule(new System.Security.Principal.SecurityIdentifier(identity),
                    RegistryRights.ChangePermissions | RegistryRights.TakeOwnership, InheritanceFlags.ContainerInherit,
                    PropagationFlags.None, AccessControlType.Deny));
            foreach (var identity in new [] { "S-1-15-2-3", "S-1-5-21-1-2-3-500", "S-1-5-18", "S-1-5-32-544" })
                policy.AddAccessRule(new RegistryAccessRule(new System.Security.Principal.SecurityIdentifier(identity),
                    RegistryRights.ReadKey, InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
            if (!policy.AreAccessRulesCanonical || !policy.AreAccessRulesProtected)
                throw new InvalidOperationException("registry source-policy fixture is not canonical/protected");
            Validate(policy.GetSecurityDescriptorBinaryForm());
            foreach (string invalid in new [] { "D:", "D:P", "D:(A;CI;KR;;;SY)", "O:SYD:P(A;CI;KR;;;SY)" }) {
                bool rejected = false;
                var descriptor = new RawSecurityDescriptor(invalid);
                byte[] bad = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(bad, 0);
                try { Validate(bad); } catch (InvalidOperationException) { rejected = true; }
                if (!rejected) throw new InvalidOperationException("malformed registry seal descriptor was accepted");
            }
            var before = new RawSecurityDescriptor("O:SYG:BAD:P(A;;KR;;;SY)S:(ML;;NW;;;LW)");
            var equal = new RawSecurityDescriptor("O:SYG:BAD:P(A;;KR;;;SY)S:(ML;;NW;;;LW)");
            RequirePreserved(before, equal);
            foreach (string changed in new [] { "O:BAG:BAD:P(A;;KR;;;SY)S:(ML;;NW;;;LW)",
                "O:SYG:SYD:P(A;;KR;;;SY)S:(ML;;NW;;;LW)", "O:SYG:BAD:P(A;;KR;;;SY)S:(ML;;NW;;;ME)" }) {
                bool rejected = false;
                try { RequirePreserved(before, new RawSecurityDescriptor(changed)); }
                catch (InvalidOperationException) { rejected = true; }
                if (!rejected) throw new InvalidOperationException("registry identity/label mutation was accepted");
            }
        }
    }
}
