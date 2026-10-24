using System;
using System.Runtime.InteropServices;
using System.Text;

namespace ScientificSecurity
{
    // Native named-attribute LPAC proof; SDK enum existence is not query support.
    internal static class LpacQuery
    {
        const string Name = "WIN://NOALLAPPPKG";
        const uint Capacity = 512;
        [StructLayout(LayoutKind.Sequential)] struct UnicodeString {
            internal ushort length, maximum; internal IntPtr buffer;
        }
        [StructLayout(LayoutKind.Sequential)] struct Attributes {
            internal ushort version, reserved; internal uint count; internal IntPtr entries;
        }
        [StructLayout(LayoutKind.Sequential)] struct Attribute {
            internal UnicodeString name;
            internal ushort type, reserved;
            internal uint flags, count;
            internal IntPtr values;
        }
        [DllImport("ntdll.dll")]
        static extern int NtQuerySecurityAttributesToken(IntPtr token, ref UnicodeString names, uint count,
            IntPtr output, uint bytes, out uint returned);

        static void RequireAbi()
        {
            if (IntPtr.Size != 8 || Marshal.SizeOf(typeof(UnicodeString)) != 16 ||
                Marshal.SizeOf(typeof(Attributes)) != 16 || Marshal.SizeOf(typeof(Attribute)) != 40 ||
                Marshal.OffsetOf(typeof(Attribute), "values").ToInt32() != 32)
                throw new PlatformNotSupportedException("LPAC named-attribute query requires the verified Windows x64 ABI");
        }
        internal static uint Read(IntPtr token)
        {
            RequireAbi();
            IntPtr name = IntPtr.Zero, output = IntPtr.Zero;
            try {
                name = Marshal.StringToHGlobalUni(Name);
                ushort length = checked((ushort)(Name.Length * 2));
                var query = new UnicodeString { length = length, maximum = length, buffer = name };
                output = Marshal.AllocHGlobal((int)Capacity);
                uint returned;
                int status = NtQuerySecurityAttributesToken(token, ref query, 1, output, Capacity, out returned);
                if (status != 0 || returned < 16 || returned > Capacity)
                    throw new InvalidOperationException("LPAC named-attribute query failed status=0x"
                        + unchecked((uint)status).ToString("X8") + " returned_bytes=" + returned);
                Validate(output, returned);
                return 1;
            }
            finally {
                try { if (output != IntPtr.Zero) Marshal.FreeHGlobal(output); }
                finally { if (name != IntPtr.Zero) Marshal.FreeHGlobal(name); }
            }
        }
        static void Span(IntPtr buffer, uint length, IntPtr pointer, uint bytes, uint alignment)
        {
            ulong start = unchecked((ulong)buffer.ToInt64()), value = unchecked((ulong)pointer.ToInt64());
            if (value % alignment != 0 || value < start || value - start > length || bytes > length - (value - start))
                throw new InvalidOperationException("LPAC attribute pointer violates returned-buffer bounds or alignment");
        }
        static void Validate(IntPtr buffer, uint length)
        {
            if (length < 16 || length > Capacity)
                throw new InvalidOperationException("LPAC attribute returned length violates fixed bounds");
            Span(buffer, length, buffer, 16, 8);
            var header = (Attributes)Marshal.PtrToStructure(buffer, typeof(Attributes));
            if (header.version != 1 || header.reserved != 0 || header.count != 1)
                throw new InvalidOperationException("LPAC attribute header is not exact version-one/single-attribute");
            Span(buffer, length, header.entries, 40, 8);
            var attribute = (Attribute)Marshal.PtrToStructure(header.entries, typeof(Attribute));
            if (attribute.type != 2 || attribute.reserved != 0 || attribute.count != 1 || (attribute.flags & 0x10) != 0)
                throw new InvalidOperationException("LPAC attribute is not an active single UInt64 value");
            uint expected = checked((uint)Name.Length * 2);
            if (attribute.name.length != expected || attribute.name.maximum < expected || (attribute.name.maximum & 1) != 0)
                throw new InvalidOperationException("LPAC attribute name length does not match the fixed query");
            Span(buffer, length, attribute.name.buffer, attribute.name.maximum, 2);
            byte[] name = new byte[expected]; Marshal.Copy(attribute.name.buffer, name, 0, name.Length);
            if (!String.Equals(new UnicodeEncoding(false, false, true).GetString(name), Name, StringComparison.Ordinal))
                throw new InvalidOperationException("LPAC attribute name differs from the fixed query");
            Span(buffer, length, attribute.values, 8, 8);
            if (unchecked((ulong)Marshal.ReadInt64(attribute.values)) != 1)
                throw new InvalidOperationException("LPAC attribute value is not exactly enabled");
        }
        // Pure managed/native-buffer parsing fixtures; never invokes a token/native security API.
        internal static void CheckValidation()
        {
            RequireAbi();
            IntPtr buffer = Marshal.AllocHGlobal((int)Capacity);
            try {
                PrepareFixture(buffer); Validate(buffer, 128);
                var changes = new Action<IntPtr>[] {
                    p => Marshal.WriteInt64(IntPtr.Add(p, 112), 0),
                    p => Marshal.WriteInt64(IntPtr.Add(p, 112), 2),
                    p => Marshal.WriteInt16(p, 0, 2),
                    p => Marshal.WriteInt16(p, 2, 1),
                    p => Marshal.WriteInt32(p, 4, 0),
                    p => Marshal.WriteInt32(p, 4, 2),
                    p => Marshal.WriteIntPtr(p, 8, IntPtr.Add(p, 17)),
                    p => Marshal.WriteIntPtr(p, 8, IntPtr.Add(p, 496)),
                    p => Marshal.WriteInt16(p, 32, 3),
                    p => Marshal.WriteInt16(p, 34, 1),
                    p => Marshal.WriteInt32(p, 36, 0x10),
                    p => Marshal.WriteInt32(p, 40, 0),
                    p => Marshal.WriteInt32(p, 40, 2),
                    p => Marshal.WriteInt16(p, 16, 1),
                    p => Marshal.WriteInt16(p, 18, 1),
                    p => Marshal.WriteIntPtr(p, 24, IntPtr.Add(p, 65)),
                    p => Marshal.WriteIntPtr(p, 24, IntPtr.Add(p, 120)),
                    p => Marshal.WriteInt16(p, 64, (short)'X'),
                    p => Marshal.WriteIntPtr(p, 48, IntPtr.Add(p, 113)),
                    p => Marshal.WriteIntPtr(p, 48, IntPtr.Add(p, 128)),
                    p => Marshal.WriteIntPtr(p, 48, IntPtr.Subtract(p, 8))
                };
                foreach (var change in changes) {
                    PrepareFixture(buffer); change(buffer); RequireRejected(buffer, 128);
                }
                PrepareFixture(buffer); RequireRejected(buffer, 15); RequireRejected(buffer, Capacity + 1);
                PrepareFixture(buffer); RequireRejected(buffer, 119);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        static void PrepareFixture(IntPtr buffer)
        {
            Marshal.Copy(new byte[Capacity], 0, buffer, (int)Capacity);
            byte[] name = Encoding.Unicode.GetBytes(Name);
            Marshal.Copy(name, 0, IntPtr.Add(buffer, 64), name.Length);
            Marshal.StructureToPtr(new Attributes { version = 1, count = 1, entries = IntPtr.Add(buffer, 16) }, buffer, false);
            Marshal.StructureToPtr(new Attribute {
                name = new UnicodeString { length = checked((ushort)name.Length), maximum = checked((ushort)name.Length), buffer = IntPtr.Add(buffer, 64) },
                type = 2, count = 1, values = IntPtr.Add(buffer, 112)
            }, IntPtr.Add(buffer, 16), false);
            Marshal.WriteInt64(IntPtr.Add(buffer, 112), 1);
        }
        static void RequireRejected(IntPtr buffer, uint length)
        {
            bool rejected = false;
            try { Validate(buffer, length); } catch (InvalidOperationException) { rejected = true; }
            if (!rejected) throw new InvalidOperationException("malformed LPAC attribute fixture was accepted");
        }
    }
}
