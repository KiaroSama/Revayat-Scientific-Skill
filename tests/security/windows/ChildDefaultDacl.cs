using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace ScientificSecurity
{
    // Child-only default security, never the token object's descriptor or an existing resource ACL.
    public static class ChildDefaultDacl
    {
        const int Capacity = 65536;
        const int GenericAll = 0x10000000;
        internal static void Need(bool value, [System.Runtime.CompilerServices.CallerLineNumber] int source = 0)
        { if (!value) throw new InvalidOperationException("child default-DACL contract failed component=policy source_check=" + source); }
        public static void CheckValidation()
        {
            string first = null, second = null;
            try { Need(false); } catch (InvalidOperationException error) { first = error.Message; }
            try { Need(false); } catch (InvalidOperationException error) { second = error.Message; }
            Need(first != second && System.Text.RegularExpressions.Regex.IsMatch(first,
                @"^child default-DACL contract failed component=policy source_check=[1-9][0-9]{0,3}$"));
            string malformed = null;
            try { Parse(new byte[7]); } catch (InvalidOperationException error) { malformed = error.Message; }
            Need(System.Text.RegularExpressions.Regex.IsMatch(malformed,
                @"^child default-DACL contract failed component=policy source_check=[1-9][0-9]{0,3}$"));
            var unsupported = new RawAcl(2, 1);
            unsupported.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, unchecked((int)0x80000000U),
                new SecurityIdentifier("S-1-5-21-1-2-3-500"), false, null));
            string maskFailure = null;
            try { Parse(Binary(unsupported)); } catch (InvalidOperationException error) { maskFailure = error.Message; }
            Need(maskFailure != null && maskFailure.EndsWith(
                " ace_index=0 ace_type=0 mask=0x80000000 rejected_bits=0x80000000", StringComparison.Ordinal) &&
                !maskFailure.Contains("S-1-") && maskFailure.Length < 220);
            var user = new SecurityIdentifier("S-1-5-21-1-2-3-500");
            var original = new RawAcl(2, 2);
            original.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessDenied, 2,
                new SecurityIdentifier("S-1-5-32-546"), false, null));
            original.InsertAce(1, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, GenericAll,
                new SecurityIdentifier("S-1-15-2-3"), false, null));
            byte[] before = Binary(original), copy = (byte[])before.Clone();
            RawAcl changed = Parse(WithUser(before, user));
            Need(before.SequenceEqual(copy) && changed.Count == 3 &&
                Binary(changed[0]).SequenceEqual(Binary(original[0])) && Binary(changed[2]).SequenceEqual(Binary(original[1])));
            var inserted = (CommonAce)changed[1];
            Need(inserted.SecurityIdentifier.Equals(user) && inserted.AccessMask == 0x10000000 &&
                inserted.AceFlags == AceFlags.None && inserted.AceQualifier == AceQualifier.AccessAllowed);
            RawAcl eventAcl = Parse(EventPolicy(Binary(changed)));
            Need(((CommonAce)eventAcl[1]).AccessMask == 0x1F0003 && ((CommonAce)eventAcl[0]).AccessMask == 2);
            byte[] padded = new byte[before.Length + 4]; before.CopyTo(padded, 0);
            BitConverter.GetBytes((ushort)padded.Length).CopyTo(padded, 2); RequireEqual(before, padded);
            foreach (Action invalid in new Action[] {
                () => Parse(null), () => Parse(new byte[7]), () => WithUser(Binary(changed), user),
                () => RequireEqual(before, Binary(changed)),
                () => { byte[] bad = (byte[])before.Clone(); bad[1] = 1; Parse(bad); },
                () => { byte[] bad = (byte[])before.Clone(); bad[9] = 2; Parse(bad); },
                () => { byte[] bad = (byte[])before.Clone(); bad[15] = 0x80; Parse(bad); },
                () => { byte[] bad = (byte[])before.Clone(); bad[17] = 16; Parse(bad); },
                () => { var bad = new RawAcl(2, 2); bad.InsertAce(0, original[1]); bad.InsertAce(1, original[0]); Parse(Binary(bad)); }
            }) {
                bool refused = false; try { invalid(); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            Need(Within(100, 16, 100, 16) && !Within(100, 16, 99, 1) && !Within(100, 16, 108, 9) &&
                !Within(UInt64.MaxValue - 8, 8, 1, 1));
        }
        static bool Within(ulong start, uint length, ulong address, uint bytes)
        { return address >= start && address - start <= length && bytes <= length - (address - start); }
        static void Range(IntPtr buffer, uint size, IntPtr pointer, uint bytes, uint alignment)
        {
            ulong address = unchecked((ulong)pointer.ToInt64());
            Need(address % alignment == 0 && Within(unchecked((ulong)buffer.ToInt64()), size, address, bytes));
        }
        internal static byte[] Binary(GenericAcl acl)
        { var bytes = new byte[acl.BinaryLength]; acl.GetBinaryForm(bytes, 0); return bytes; }
        static byte[] Binary(GenericAce ace)
        { var bytes = new byte[ace.BinaryLength]; ace.GetBinaryForm(bytes, 0); return bytes; }
        static void Mask(uint mask, int index, byte type, [System.Runtime.CompilerServices.CallerLineNumber] int source = 0)
        {
            uint rejected = mask & ~(0x10000000U | 0x1F0003U);
            if (rejected != 0) throw new InvalidOperationException("child default-DACL contract failed component=policy source_check=" + source +
                " ace_index=" + index + " ace_type=" + type + " mask=0x" + mask.ToString("X8") + " rejected_bits=0x" + rejected.ToString("X8"));
        }
        internal static RawAcl Parse(byte[] bytes)
        {
            Need(bytes != null && bytes.Length >= 8 && bytes.Length <= 65535 && (bytes.Length & 3) == 0 &&
                (bytes[0] == 2 || bytes[0] == 4) && bytes[1] == 0 && BitConverter.ToUInt16(bytes, 2) == bytes.Length &&
                BitConverter.ToUInt16(bytes, 6) == 0);
            int count = BitConverter.ToUInt16(bytes, 4), offset = 8;
            Need(count <= 64);
            for (int index = 0; index < count; index++) {
                Need(offset <= bytes.Length - 16 && (bytes[offset] == 0 || bytes[offset] == 1) && bytes[offset + 1] == 0);
                int length = BitConverter.ToUInt16(bytes, offset + 2), subAuthorities = bytes[offset + 9];
                Need(length >= 16 && (length & 3) == 0 && length <= bytes.Length - offset &&
                    bytes[offset + 8] == 1 && subAuthorities <= 15 && length == 16 + 4 * subAuthorities);
                uint mask = BitConverter.ToUInt32(bytes, offset + 4);
                Mask(mask, index, bytes[offset]);
                offset += length;
            }
            var acl = new RawAcl(bytes, 0); bool allowSeen = false;
            foreach (GenericAce entry in acl) {
                var ace = entry as CommonAce;
                Need(ace != null && !ace.IsCallback && ace.AceFlags == AceFlags.None &&
                    (ace.AceQualifier == AceQualifier.AccessAllowed || ace.AceQualifier == AceQualifier.AccessDenied));
                if (ace.AceQualifier == AceQualifier.AccessAllowed) allowSeen = true;
                else Need(!allowSeen);
            }
            return acl;
        }
        internal static byte[] WithUser(byte[] original, SecurityIdentifier user)
        {
            RawAcl acl = Parse(original); Need(user != null && acl.Count < 64);
            int position = 0;
            for (int index = 0; index < acl.Count; index++) {
                var ace = (CommonAce)acl[index]; Need(!ace.SecurityIdentifier.Equals(user));
                if (ace.AceQualifier == AceQualifier.AccessDenied) position++;
            }
            var result = new RawAcl(acl.Revision, acl.Count + 1);
            for (int index = 0; index <= acl.Count; index++) {
                if (index == position) result.InsertAce(result.Count,
                    new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, GenericAll, user, false, null));
                if (index < acl.Count) result.InsertAce(result.Count, GenericAce.CreateFromBinaryForm(Binary(acl[index]), 0));
            }
            byte[] bytes = Binary(result); Parse(bytes); return bytes;
        }
        internal static byte[] EventPolicy(byte[] prepared)
        {
            RawAcl acl = Parse(prepared), mapped = new RawAcl(acl.Revision, acl.Count);
            foreach (CommonAce ace in acl) {
                int mask = ace.AccessMask;
                if ((mask & GenericAll) != 0) mask = (mask & ~GenericAll) | 0x1F0003;
                mapped.InsertAce(mapped.Count, new CommonAce(AceFlags.None, ace.AceQualifier, mask,
                    ace.SecurityIdentifier, false, null));
            }
            return Binary(mapped);
        }
        internal static void RequireEqual(byte[] expected, byte[] actual)
        {
            RawAcl first = Parse(expected), second = Parse(actual);
            Need(first.Revision == second.Revision && first.Count == second.Count);
            for (int index = 0; index < first.Count; index++) Need(Binary(first[index]).SequenceEqual(Binary(second[index])));
        }
        static byte[] Query(IntPtr token, int kind)
        {
            IntPtr buffer = Marshal.AllocHGlobal(Capacity);
            try {
                uint returned;
                Native.Check(Native.GetTokenInformation(token, kind, buffer, Capacity, out returned), "query bounded child default security");
                Need(returned >= (kind == 1 ? 16 : 8) && returned <= Capacity);
                IntPtr pointer = Marshal.ReadIntPtr(buffer); Need(pointer != IntPtr.Zero);
                Range(buffer, returned, pointer, 8, 4);
                uint length;
                if (kind == 1) {
                    Need(Marshal.ReadByte(pointer) == 1 && Marshal.ReadByte(pointer, 1) <= 15);
                    length = 8U + 4U * Marshal.ReadByte(pointer, 1);
                } else { length = unchecked((ushort)Marshal.ReadInt16(pointer, 2)); Need(length >= 8); }
                Range(buffer, returned, pointer, length, 4);
                byte[] bytes = new byte[length]; Marshal.Copy(pointer, bytes, 0, bytes.Length);
                return bytes;
            }
            finally {
                try { for (int index = 0; index < Capacity; index += 8) Marshal.WriteInt64(buffer, index, 0); }
                finally { Marshal.FreeHGlobal(buffer); }
            }
        }
        internal static SecurityIdentifier User(IntPtr token)
        {
            byte[] bytes = Query(token, 1);
            try { return new SecurityIdentifier(bytes, 0); }
            finally { Array.Clear(bytes, 0, bytes.Length); }
        }
        internal static byte[] Read(IntPtr token)
        {
            byte[] bytes = Query(token, 6);
            try { Parse(bytes); return bytes; }
            catch { Array.Clear(bytes, 0, bytes.Length); throw; }
        }
        internal static void Set(IntPtr token, byte[] expected)
        {
            Parse(expected); IntPtr acl = IntPtr.Zero, data = IntPtr.Zero;
            try {
                acl = Marshal.AllocHGlobal(expected.Length); Marshal.Copy(expected, 0, acl, expected.Length);
                data = Marshal.AllocHGlobal(8); Marshal.WriteIntPtr(data, acl);
                Native.Check(Native.SetTokenInformation(token, 6, data, 8), "set exact suspended child default DACL");
            }
            finally {
                try { if (data != IntPtr.Zero) Marshal.FreeHGlobal(data); }
                finally { if (acl != IntPtr.Zero) { for (int index = 0; index < expected.Length; index++) Marshal.WriteByte(acl, index, 0); Marshal.FreeHGlobal(acl); } }
            }
        }
    }
}
