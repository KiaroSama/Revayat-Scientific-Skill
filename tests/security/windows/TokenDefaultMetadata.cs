using System;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace ScientificSecurity
{
    // Structural diagnostic for the fixed native fixture, not effective-access or admission evidence.
    public static class TokenDefaultMetadata
    {
        const int Capacity = 65536;
        static bool Within(ulong start, uint length, ulong address, uint bytes)
        { return address >= start && address - start <= length && bytes <= length - (address - start); }
        static bool AlignedSpan(ulong start, uint length, ulong address, uint bytes)
        { return (address & 3) == 0 && Within(start, length, address, bytes); }
        static string NullSummary()
        { return "WINDOWS_DEFAULT_DACL status=summary default_dacl_null=True effective_access_proved=False"; }

        internal static string Observe(IntPtr process)
        {
            if (IntPtr.Size != 8) return Unknown("unsupported-abi", 0);
            IntPtr token = IntPtr.Zero, buffer = IntPtr.Zero;
            byte[] binary = null;
            try {
                if (!Native.OpenProcessToken(process, 8, out token))
                    return Unknown("open-token", Marshal.GetLastWin32Error());
                buffer = Marshal.AllocHGlobal(Capacity);
                uint returned;
                if (!Native.GetTokenInformation(token, 6, buffer, Capacity, out returned))
                    return Unknown("query-default", Marshal.GetLastWin32Error());
                if (returned < IntPtr.Size || returned > Capacity)
                    return Unknown("default-length", 0);
                IntPtr acl = Marshal.ReadIntPtr(buffer);
                if (acl == IntPtr.Zero)
                    return NullSummary();
                ulong start = unchecked((ulong)buffer.ToInt64()), address = unchecked((ulong)acl.ToInt64());
                if (!AlignedSpan(start, returned, address, 8))
                    return Unknown("default-pointer", 0);
                uint length = unchecked((ushort)Marshal.ReadInt16(acl, 2));
                if (length < 8 || (length & 3) != 0 || !Within(start, returned, address, length))
                    return Unknown("acl-length", 0);
                if (!NativeSpans(acl, length)) return Unknown("ace-spans", 0);
                binary = new byte[length]; Marshal.Copy(acl, binary, 0, binary.Length);
                if (!ValidSpans(binary)) return Unknown("ace-spans", 0);
                // Same exact token, fixed bounded SID queries; identity values are never emitted.
                SecurityIdentifier user = QuerySid(token, 1, buffer), package = QuerySid(token, 31, buffer);
                if (user == null || package == null) return Unknown("identity-query", 0);
                return Summarize(binary, user, package);
            }
            catch (ArgumentException) { return Unknown("managed-structure", 0); }
            catch (InvalidOperationException) { return Unknown("managed-structure", 0); }
            finally {
                try { if (binary != null) Array.Clear(binary, 0, binary.Length); }
                finally {
                    try {
                        if (buffer != IntPtr.Zero) {
                            try { for (int offset = 0; offset < Capacity; offset += 8) Marshal.WriteInt64(buffer, offset, 0); }
                            finally { Marshal.FreeHGlobal(buffer); }
                        }
                    }
                    finally { if (token != IntPtr.Zero) Native.Check(Native.CloseHandle(token), "close default-DACL diagnostic token"); }
                }
            }
        }
        static string Unknown(string stage, int error)
        { return "WINDOWS_DEFAULT_DACL status=unknown stage=" + stage + " native_error=" + error + " effective_access_proved=False"; }
        static SecurityIdentifier QuerySid(IntPtr token, int kind, IntPtr buffer)
        {
            uint returned;
            if (!Native.GetTokenInformation(token, kind, buffer, Capacity, out returned) ||
                returned < (kind == 1 ? 16 : IntPtr.Size) || returned > Capacity) return null;
            IntPtr sid = Marshal.ReadIntPtr(buffer);
            ulong start = unchecked((ulong)buffer.ToInt64()), address = unchecked((ulong)sid.ToInt64());
            if (!AlignedSpan(start, returned, address, 8)) return null;
            byte revision = Marshal.ReadByte(sid), count = Marshal.ReadByte(sid, 1);
            uint length = 8U + 4U * count;
            if (revision != 1 || count > 15 || !Within(start, returned, address, length)) return null;
            byte[] bytes = new byte[length];
            try { Marshal.Copy(sid, bytes, 0, bytes.Length); return new SecurityIdentifier(bytes, 0); }
            finally { Array.Clear(bytes, 0, bytes.Length); }
        }
        static bool NativeSpans(IntPtr acl, uint bytes)
        {
            byte revision = Marshal.ReadByte(acl);
            int count = unchecked((ushort)Marshal.ReadInt16(acl, 4)), offset = 8;
            if ((revision != 2 && revision != 4) || Marshal.ReadByte(acl, 1) != 0 ||
                Marshal.ReadInt16(acl, 6) != 0 || count > 64) return false;
            for (int index = 0; index < count; index++) {
                if ((offset & 3) != 0 || (uint)offset > bytes - 4) return false;
                int length = unchecked((ushort)Marshal.ReadInt16(acl, offset + 2));
                if (length < 4 || (length & 3) != 0 || (uint)length > bytes - (uint)offset) return false;
                offset += length;
            }
            return true;
        }
        static bool ValidSpans(byte[] bytes)
        {
            if (bytes == null || bytes.Length < 8 || bytes.Length > 65535 || (bytes.Length & 3) != 0 ||
                (bytes[0] != 2 && bytes[0] != 4) || bytes[1] != 0 || BitConverter.ToUInt16(bytes, 6) != 0 ||
                BitConverter.ToUInt16(bytes, 2) != bytes.Length) return false;
            int count = BitConverter.ToUInt16(bytes, 4), offset = 8;
            if (count > 64) return false;
            for (int index = 0; index < count; index++) {
                if (offset > bytes.Length - 4 || (offset & 3) != 0) return false;
                int length = BitConverter.ToUInt16(bytes, offset + 2);
                if (length < 4 || (length & 3) != 0 || length > bytes.Length - offset) return false;
                // Plain allow/deny SID spans must fit the ACE before any managed SID decode.
                if (bytes[offset] == 0 || bytes[offset] == 1) {
                    if (length < 16 || bytes[offset + 8] != 1 || bytes[offset + 9] > 15 ||
                        16 + 4 * bytes[offset + 9] > length) return false;
                }
                offset += length;
            }
            return true; // AclSize may include legitimate unused padding after the final ACE.
        }
        static string Summarize(byte[] bytes, SecurityIdentifier user, SecurityIdentifier package)
        {
            if (!ValidSpans(bytes)) return Unknown("ace-spans", 0);
            var acl = new RawAcl(bytes, 0);
            uint userAllow = 0, userDeny = 0, packageAllow = 0, packageDeny = 0;
            int unknown = 0, other = 0, inheritOnly = 0, stage = 0;
            bool canonical = true;
            for (int index = 0; index < acl.Count; index++) {
                var ace = acl[index] as CommonAce;
                if (ace == null || ace.IsCallback ||
                    (ace.AceQualifier != AceQualifier.AccessAllowed && ace.AceQualifier != AceQualifier.AccessDenied)) {
                    unknown++; canonical = false; continue;
                }
                int current = (ace.AceFlags & AceFlags.Inherited) != 0 ? 2 :
                    (ace.AceQualifier == AceQualifier.AccessDenied ? 0 : 1);
                if (current < stage) canonical = false; stage = Math.Max(stage, current);
                if ((ace.AceFlags & AceFlags.InheritOnly) != 0) { inheritOnly++; continue; }
                uint mask = unchecked((uint)ace.AccessMask);
                bool allow = ace.AceQualifier == AceQualifier.AccessAllowed;
                if (ace.SecurityIdentifier.Equals(user)) { if (allow) userAllow |= mask; else userDeny |= mask; }
                else if (ace.SecurityIdentifier.Equals(package)) { if (allow) packageAllow |= mask; else packageDeny |= mask; }
                else other++;
            }
            return "WINDOWS_DEFAULT_DACL status=summary default_dacl_null=False acl_bytes=" + bytes.Length
                + " ace_count=" + acl.Count + " canonical_order=" + canonical + " recognized_all=" + (unknown == 0)
                + " unknown_ace_count=" + unknown + " other_ace_count=" + other + " inherit_only_count=" + inheritOnly
                + " user_allow_mask=0x" + userAllow.ToString("X8") + " user_deny_mask=0x" + userDeny.ToString("X8")
                + " package_allow_mask=0x" + packageAllow.ToString("X8") + " package_deny_mask=0x" + packageDeny.ToString("X8")
                + " effective_access_proved=False";
        }
        static byte[] Binary(RawAcl acl)
        { byte[] bytes = new byte[acl.BinaryLength]; acl.GetBinaryForm(bytes, 0); return bytes; }
        // Shared parser check only. Does not query/mutate a token or create native objects.
        public static void CheckValidation()
        {
            var user = new SecurityIdentifier("S-1-5-21-1-2-3-500");
            var package = new SecurityIdentifier("S-1-15-2-3");
            var acl = new RawAcl(2, 4);
            acl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessDenied, 2, user, false, null));
            acl.InsertAce(1, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 8, user, false, null));
            acl.InsertAce(2, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x20019, package, false, null));
            acl.InsertAce(3, new CommonAce(AceFlags.InheritOnly | AceFlags.ContainerInherit, AceQualifier.AccessAllowed,
                0x10000000, user, false, null));
            byte[] valid = Binary(acl);
            string summary = Summarize(valid, user, package);
            if (!summary.Contains("user_allow_mask=0x00000008") || !summary.Contains("user_deny_mask=0x00000002") ||
                !summary.Contains("package_allow_mask=0x00020019") || !summary.Contains("inherit_only_count=1") ||
                !summary.Contains("effective_access_proved=False") || summary.Contains(user.Value) || summary.Contains(package.Value))
                throw new InvalidOperationException("default-DACL summary parser lost bounds or privacy");
            byte[] empty = Binary(new RawAcl(2, 0));
            if (!Summarize(empty, user, package).Contains("ace_count=0"))
                throw new InvalidOperationException("empty default-DACL fixture was not distinguished");
            byte[] padded = new byte[valid.Length + 4]; valid.CopyTo(padded, 0);
            BitConverter.GetBytes((ushort)padded.Length).CopyTo(padded, 2);
            if (!Summarize(padded, user, package).Contains("user_allow_mask=0x00000008"))
                throw new InvalidOperationException("legitimate ACL padding changed the parser summary");
            if (!NullSummary().Contains("default_dacl_null=True") ||
                Summarize(empty, user, package).Contains("default_dacl_null=True"))
                throw new InvalidOperationException("null and empty default-DACL summaries were conflated");
            var reversed = new RawAcl(2, 2);
            reversed.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 8, user, false, null));
            reversed.InsertAce(1, new CommonAce(AceFlags.None, AceQualifier.AccessDenied, 2, user, false, null));
            if (!Summarize(Binary(reversed), user, package).Contains("canonical_order=False"))
                throw new InvalidOperationException("misordered default-DACL ACEs were reported canonical");
            foreach (Action<byte[]> change in new Action<byte[]>[] {
                p => p[0] = 1, p => p[1] = 1, p => p[2] = 0,
                p => BitConverter.GetBytes((ushort)65).CopyTo(p, 4),
                p => BitConverter.GetBytes((ushort)3).CopyTo(p, 10),
                p => BitConverter.GetBytes((ushort)65532).CopyTo(p, 10),
                p => p[16] = 2, p => p[17] = 16
            }) {
                byte[] bad = (byte[])valid.Clone(); change(bad);
                if (ValidSpans(bad)) throw new InvalidOperationException("malformed default-DACL ACL span was accepted");
            }
            acl[1] = new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 8, user, true, new byte[4]);
            if (!Summarize(Binary(acl), user, package).Contains("recognized_all=False"))
                throw new InvalidOperationException("callback default-DACL ACE was treated as an unconditional grant");
            if (!AlignedSpan(100, 16, 100, 16) || AlignedSpan(100, 16, 101, 4) ||
                AlignedSpan(100, 16, 108, 9) || Within(100, 16, 99, 1) ||
                Within(UInt64.MaxValue - 8, 8, 1, 1))
                throw new InvalidOperationException("default-DACL native range fixture failed");
        }
    }
}
