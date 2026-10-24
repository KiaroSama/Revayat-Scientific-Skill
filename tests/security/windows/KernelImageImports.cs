using System;
using System.Collections.Generic;
using System.Linq;

namespace ScientificSecurity
{
    public sealed partial class KernelImage
    {
        // Direct import names only, not API-set, transitive, SxS or loader resolution.
        internal static int QualifyPythonImports(byte[] bytes, string label)
        {
            string[] expected;
            switch (label) {
                case "python-exe": expected = new [] { "kernel32.dll", "python311.dll", "vcruntime140.dll" }; break;
                case "python311": expected = new [] { "advapi32.dll", "bcrypt.dll", "kernel32.dll", "vcruntime140.dll", "version.dll", "ws2_32.dll" }; break;
                case "vcruntime140": expected = new [] { "kernel32.dll" }; break;
                default: throw new InvalidOperationException("unsupported fixed Python import profile");
            }
            var image = new KernelImage(bytes, 1, label);
            string[] names = image.DirectImportNames();
            string[] physical = names.Where(name => !name.StartsWith("api-ms-win-", StringComparison.Ordinal)).ToArray();
            if (!new HashSet<string>(physical, StringComparer.Ordinal).SetEquals(expected))
                throw new InvalidOperationException("prepared Python physical direct imports differ from reviewed profile label=" + label);
            return names.Length - physical.Length;
        }
        string[] DirectImportNames()
        {
            ulong optional = (ulong)U32(0x3C) + 24;
            Need(U32(optional + 112 + 13 * 8) == 0 && U32(optional + 116 + 13 * 8) == 0);
            uint rva = U32(optional + 120), size = U32(optional + 124);
            Need(rva != 0 && size >= 40 && size <= 2580 && size % 20 == 0);
            int table = Map(rva, size);
            var names = new HashSet<string>(StringComparer.Ordinal);
            for (uint offset = 0; offset < size; offset += 20) {
                ulong item = (ulong)table + offset;
                bool empty = true;
                for (uint field = 0; field < 20; field += 4) empty &= U32(item + field) == 0;
                if (empty) {
                    Need(names.Count != 0);
                    for (uint tail = offset + 20; tail < size; tail++) Need(data[table + tail] == 0);
                    return names.OrderBy(name => name, StringComparer.Ordinal).ToArray();
                }
                uint nameRva = U32(item + 12);
                Need(nameRva != 0 && U32(item + 16) != 0 && names.Count < 128);
                var name = new System.Text.StringBuilder(); bool terminated = false;
                for (uint index = 0; index < 128; index++) {
                    Need(nameRva <= UInt32.MaxValue - index);
                    byte value = data[Map(nameRva + index, 1)];
                    if (value == 0) { terminated = true; break; }
                    Need((value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') ||
                        (value >= '0' && value <= '9') || value == '-' || value == '_' || value == '.');
                    name.Append((char)value);
                }
                string normalized = name.ToString().ToLowerInvariant();
                Need(terminated && normalized.Length > 4 && normalized.EndsWith(".dll", StringComparison.Ordinal) && names.Add(normalized));
            }
            throw new InvalidOperationException("prepared Python import directory has no bounded terminator");
        }
        public static void CheckImportValidation()
        {
            byte[] bytes = Fixture();
            Put(bytes, 0x98 + 120, 0x1000); Put(bytes, 0x98 + 124, 40);
            Put(bytes, 0x200, 0x1080); Put(bytes, 0x20C, 0x1060); Put(bytes, 0x210, 0x1080);
            System.Text.Encoding.ASCII.GetBytes("KERNEL32.dll\0").CopyTo(bytes, 0x260);
            var image = new KernelImage(bytes, 1, "fixture");
            Need(image.DirectImportNames().SequenceEqual(new [] { "kernel32.dll" }));
            foreach (Action<byte[]> change in new Action<byte[]>[] {
                b => Put(b, 0x98 + 124, 39), b => Put(b, 0x98 + 124, 2600),
                b => Put(b, 0x20C, UInt32.MaxValue), b => b[0x260] = (byte)'\\',
                b => Put(b, 0x224, 1), b => Put(b, 0x98 + 112 + 13 * 8, 0x1000),
                b => Put(b, 0x210, 0), b => Array.Clear(b, 0x200, 20)
            }) {
                byte[] bad = (byte[])bytes.Clone(); change(bad); bool rejected = false;
                try { new KernelImage(bad, 1, "fixture").DirectImportNames(); }
                catch (InvalidOperationException) { rejected = true; }
                Need(rejected);
            }
            bool drift = false;
            try { QualifyPythonImports(bytes, "python-exe"); } catch (InvalidOperationException) { drift = true; }
            Need(drift);
            byte[] python = ImportFixture(new [] { "KERNEL32.dll", "python311.dll", "VCRUNTIME140.dll", "api-ms-win-crt-runtime-l1-1-0.dll" });
            Need(QualifyPythonImports(python, "python-exe") == 1);
            Need(QualifyPythonImports(ImportFixture(new [] { "KERNEL32.dll" }), "vcruntime140") == 0);
            Need(QualifyPythonImports(ImportFixture(new [] { "ADVAPI32.dll", "bcrypt.dll", "KERNEL32.dll", "VCRUNTIME140.dll", "VERSION.dll", "WS2_32.dll" }), "python311") == 0);
            foreach (string[] invalid in new [] {
                new [] { "KERNEL32.dll", "kernel32.dll" }, new [] { "C:\\private\\secret.dll" },
                new [] { "kernel32.dll", "unexpected.dll" }, new [] { new string('a', 128) + ".dll" }
            }) {
                bool rejected = false;
                try { QualifyPythonImports(ImportFixture(invalid), "vcruntime140"); }
                catch (InvalidOperationException) { rejected = true; }
                Need(rejected);
            }
        }
        static byte[] ImportFixture(string[] names)
        {
            byte[] bytes = Fixture();
            uint count = (uint)names.Length;
            Put(bytes, 0x98 + 120, 0x1000); Put(bytes, 0x98 + 124, (count + 1) * 20);
            int nameOffset = 0x300;
            for (uint index = 0; index < count; index++) {
                int descriptor = 0x200 + (int)index * 20;
                Put(bytes, descriptor, 0x11F0); Put(bytes, descriptor + 16, 0x11F0);
                Put(bytes, descriptor + 12, (uint)(0x1000 + nameOffset - 0x200));
                byte[] name = System.Text.Encoding.ASCII.GetBytes(names[index] + "\0");
                Need(nameOffset + name.Length <= bytes.Length);
                name.CopyTo(bytes, nameOffset); nameOffset += name.Length;
            }
            return bytes;
        }
    }
}
