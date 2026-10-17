using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ScientificSecurity
{
    public sealed partial class KernelImage
    {
        static readonly string[] ModuleHostImports = { "ExitProcess", "GetStdHandle", "WriteFile" };
        static readonly string[] ModuleDllImports = { "CompareStringOrdinal", "GetLastError", "GetModuleFileNameW", "QueryActCtxW" };
        internal static void QualifyModuleActivation(byte[] bytes, bool dll, bool manifest, ushort language, byte[] payload)
        {
            var image = new KernelImage(bytes, 1, "fixed-module-activation");
            image.ModuleActivation(dll, manifest);
            if (manifest) {
                var actual = ModuleManifest(bytes, true);
                try { Need(actual.Item1 == language && actual.Item2.SequenceEqual(payload)); }
                finally { Array.Clear(actual.Item2, 0, actual.Item2.Length); }
            }
        }
        void ModuleActivation(bool dll, bool manifest)
        {
            Need(data.Length <= 1048576 && (!manifest || dll));
            ulong nt = U32(0x3C), optional = nt + 24;
            Need((U16(nt + 22) & 0x2002) == (dll ? 0x2002 : 2) && Entry != 0 && U16(optional + 68) == 3);
            foreach (int directory in new [] { 0, 2, 9, 13, 14 }) {
                if (directory == 0 && dll || directory == 2 && manifest) continue;
                Need(U32(optional + 112 + (ulong)directory * 8) == 0 && U32(optional + 116 + (ulong)directory * 8) == 0);
            }
            uint rva = U32(optional + 120), size = U32(optional + 124);
            Need(rva != 0 && size >= (dll ? 40 : 60) && size <= 128);
            int table = Map(rva, size), descriptors = dll ? 1 : 2;
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int row = 0; row < descriptors; row++) {
                ulong descriptor = (ulong)table + (uint)row * 20;
                uint lookup = U32(descriptor), name = U32(descriptor + 12), address = U32(descriptor + 16);
                Need(lookup != 0 && name != 0 && address != 0 && U32(descriptor + 4) == 0 && U32(descriptor + 8) == 0);
                string module = ActivationText(name); Need(names.Add(module));
                string[] expected;
                if (String.Equals(module, "KERNEL32.dll", StringComparison.OrdinalIgnoreCase)) expected = dll ? ModuleDllImports : ModuleHostImports;
                else { Need(!dll && module == "startup-module.dll"); expected = new [] { "ObserveModuleActivation" }; }
                var imports = new HashSet<string>(StringComparer.Ordinal);
                for (uint index = 0; index <= expected.Length; index++) {
                    Need(lookup <= UInt32.MaxValue - index * 8 && address <= UInt32.MaxValue - index * 8);
                    ulong symbol = BitConverter.ToUInt64(data, Map(lookup + index * 8, 8));
                    Need(symbol == BitConverter.ToUInt64(data, Map(address + index * 8, 8)));
                    if (symbol == 0) { Need(index == expected.Length && imports.SetEquals(expected)); break; }
                    Need(index < expected.Length && symbol <= UInt32.MaxValue - 2); Map((uint)symbol, 2);
                    Need(imports.Add(ActivationText((uint)symbol + 2)));
                }
            }
            Need(names.Contains("KERNEL32.dll") && (dll || names.Contains("startup-module.dll")));
            for (uint tail = (uint)descriptors * 20; tail < size; tail++) Need(data[table + tail] == 0);
            if (dll) ModuleExport(optional);
        }
        void ModuleExport(ulong optional)
        {
            uint rva = U32(optional + 112), size = U32(optional + 116);
            Need(rva != 0 && size >= 40 && size <= 4096); int table = Map(rva, size);
            Need(ActivationText(U32((ulong)table + 12)) == "startup-module.dll" && U32((ulong)table + 20) == 1 && U32((ulong)table + 24) == 1);
            uint function = U32((ulong)Map(U32((ulong)table + 28), 4));
            uint name = U32((ulong)Map(U32((ulong)table + 32), 4));
            Need(U16((ulong)Map(U32((ulong)table + 36), 2)) == 0 && ActivationText(name) == "ObserveModuleActivation" && Executable(function));
            Need(function < rva || (ulong)function >= (ulong)rva + size);
        }
        public static void CheckModuleActivationValidation()
        {
            byte[] payload = { 1, 2, 3, 4 };
            foreach (int role in new [] { 0, 1, 2 }) {
                bool dll = role != 0, manifest = role == 2;
                byte[] bytes = ModuleActivationFixtureImage(dll, manifest);
                QualifyModuleActivation(bytes, dll, manifest, 1033, payload);
                foreach (Action<byte[]> change in new Action<byte[]>[] {
                    b => Put16(b, 0x96, (ushort)(dll ? 2 : 0x2002)), b => Put(b, 0x98 + 16, 0),
                    b => Put16(b, 0x98 + 68, 2), b => b[0x500] ^= 1, b => b[0x602] ^= 1,
                    b => b[0x300] ^= 1, b => Put(b, 0x98 + 124, 39),
                    b => Put(b, 0x98 + 112 + 9 * 8, 0x1000), b => Put(b, 0x98 + 112 + 13 * 8, 0x1000),
                    b => Put(b, 0x98 + 112 + 14 * 8, 0x1000), b => Put(b, 0x200 + (dll ? 20 : 40), 1)
                }) ModuleRefuse(() => { byte[] bad = (byte[])bytes.Clone(); change(bad); QualifyModuleActivation(bad, dll, manifest, 1033, payload); });
                if (dll) {
                    foreach (Action<byte[]> change in new Action<byte[]>[] {
                        b => Put(b, 0xA14, 2), b => Put(b, 0xA18, 2), b => Put(b, 0xA40, 0x1800),
                        b => b[0xA82] ^= 1, b => Put16(b, 0xA48, 1)
                    }) ModuleRefuse(() => { byte[] bad = (byte[])bytes.Clone(); change(bad); QualifyModuleActivation(bad, true, manifest, 1033, payload); });
                }
                if (manifest) {
                    foreach (Action<byte[]> change in new Action<byte[]>[] {
                        b => Put(b, 0xB30, 1), b => Put(b, 0xB10, 23), b => b[0xB80] ^= 1,
                        b => Put(b, 0xB50, 1034), b => Put16(b, 0xB4E, 2), b => Put(b, 0xB60, 0x1940)
                    }) ModuleRefuse(() => { byte[] bad = (byte[])bytes.Clone(); change(bad); QualifyModuleActivation(bad, true, true, 1033, payload); });
                }
                else ModuleRefuse(() => { byte[] bad = (byte[])bytes.Clone(); Put(bad, 0x98 + 132, 8); QualifyModuleActivation(bad, dll, false, 1033, payload); });
            }
        }
        static void ModuleRefuse(Action action)
        { bool refused = false; try { action(); } catch (InvalidOperationException) { refused = true; } Need(refused); }
        static byte[] ModuleActivationFixtureImage(bool dll, bool manifest)
        {
            byte[] b = Fixture(); Array.Resize(ref b, 4096);
            Put16(b, 0x96, (ushort)(dll ? 0x2002 : 2)); Put16(b, 0x98 + 68, 3);
            Put(b, 0x98 + 56, 0x3000); Put(b, 0x188 + 8, 0xE00); Put(b, 0x188 + 16, 0xE00);
            Put(b, 0x98 + 120, 0x1000); Put(b, 0x98 + 124, (uint)(dll ? 40 : 60));
            Put(b, 0x200, 0x1080); Put(b, 0x20C, 0x1300); Put(b, 0x210, 0x1100);
            Encoding.ASCII.GetBytes("KERNEL32.dll\0").CopyTo(b, 0x500);
            string[] imports = dll ? ModuleDllImports : ModuleHostImports; int text = 0x600;
            for (int index = 0; index < imports.Length; index++) {
                ulong symbol = (ulong)(text + 0xE00);
                BitConverter.GetBytes(symbol).CopyTo(b, 0x280 + index * 8); BitConverter.GetBytes(symbol).CopyTo(b, 0x300 + index * 8);
                byte[] name = Encoding.ASCII.GetBytes(imports[index] + "\0"); name.CopyTo(b, text + 2); text += name.Length + 2;
            }
            if (!dll) {
                Put(b, 0x214, 0x1180); Put(b, 0x220, 0x1340); Put(b, 0x224, 0x1200);
                Encoding.ASCII.GetBytes("startup-module.dll\0").CopyTo(b, 0x540);
                BitConverter.GetBytes(0x1580UL).CopyTo(b, 0x380); BitConverter.GetBytes(0x1580UL).CopyTo(b, 0x400);
                Encoding.ASCII.GetBytes("ObserveModuleActivation\0").CopyTo(b, 0x782);
            }
            else {
                Put(b, 0x98 + 112, 0x1800); Put(b, 0x98 + 116, 0x100);
                Put(b, 0xA0C, 0x184C); Put(b, 0xA14, 1); Put(b, 0xA18, 1);
                Put(b, 0xA1C, 0x1840); Put(b, 0xA20, 0x1844); Put(b, 0xA24, 0x1848);
                Put(b, 0xA40, 0x1010); Put(b, 0xA44, 0x1880);
                Encoding.ASCII.GetBytes("startup-module.dll\0").CopyTo(b, 0xA4C);
                Encoding.ASCII.GetBytes("ObserveModuleActivation\0").CopyTo(b, 0xA80);
            }
            if (manifest) {
                Put(b, 0x98 + 128, 0x1900); Put(b, 0x98 + 132, 0x100);
                Put16(b, 0xB0E, 1); Put(b, 0xB10, 24); Put(b, 0xB14, 0x80000020);
                Put16(b, 0xB2E, 1); Put(b, 0xB30, 2); Put(b, 0xB34, 0x80000040);
                Put16(b, 0xB4E, 1); Put(b, 0xB50, 1033); Put(b, 0xB54, 0x60);
                Put(b, 0xB60, 0x1980); Put(b, 0xB64, 4); new byte[] { 1, 2, 3, 4 }.CopyTo(b, 0xB80);
            }
            return b;
        }
    }
}
