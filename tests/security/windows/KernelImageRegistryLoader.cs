using System;
using System.Linq;
using System.Text;

namespace ScientificSecurity
{
    public sealed partial class KernelImage
    {
        internal static void QualifyRegistryLoader(byte[] bytes)
        {
            var image = new KernelImage(bytes, 1, "fixed-registry-loader");
            ulong nt = image.U32(0x3C), optional = nt + 24;
            Need((image.U16(nt + 22) & 0x2002) == 0x2002 && image.Entry == 0);
            foreach (int directory in new [] { 2, 9, 13, 14 })
                Need(image.U32(optional + 112 + (ulong)directory * 8) == 0 && image.U32(optional + 116 + (ulong)directory * 8) == 0);
            Need(image.DirectImportNames().SequenceEqual(new [] { "kernel32.dll", "python311.dll" }));
            uint rva = image.U32(optional + 112), size = image.U32(optional + 116);
            Need(rva != 0 && size >= 40 && size <= 4096);
            ulong table = (ulong)image.Map(rva, size);
            Need(image.ActivationText(image.U32(table + 12)) == "_registry_loader.pyd" && image.U32(table + 20) == 1 && image.U32(table + 24) == 1);
            uint function = image.U32((ulong)image.Map(image.U32(table + 28), 4));
            uint name = image.U32((ulong)image.Map(image.U32(table + 32), 4));
            Need(image.U16((ulong)image.Map(image.U32(table + 36), 2)) == 0 && image.ActivationText(name) == "PyInit__registry_loader" && image.Executable(function));
            Need(function < rva || (ulong)function >= (ulong)rva + size);
        }
        public static void CheckRegistryLoaderValidation()
        {
            byte[] bytes = ImportFixture(new [] { "KERNEL32.dll", "python311.dll" });
            Array.Resize(ref bytes, 4096);
            Put16(bytes, 0x96, 0x2002); Put(bytes, 0x98 + 16, 0);
            Put(bytes, 0x98 + 56, 0x3000); Put(bytes, 0x188 + 8, 0xE00); Put(bytes, 0x188 + 16, 0xE00);
            Put(bytes, 0x98 + 112, 0x1800); Put(bytes, 0x98 + 116, 0x100);
            Put(bytes, 0xA0C, 0x184C); Put(bytes, 0xA14, 1); Put(bytes, 0xA18, 1);
            Put(bytes, 0xA1C, 0x1840); Put(bytes, 0xA20, 0x1844); Put(bytes, 0xA24, 0x1848);
            Put(bytes, 0xA40, 0x1010); Put(bytes, 0xA44, 0x1880);
            Encoding.ASCII.GetBytes("_registry_loader.pyd\0").CopyTo(bytes, 0xA4C);
            Encoding.ASCII.GetBytes("PyInit__registry_loader\0").CopyTo(bytes, 0xA80);
            QualifyRegistryLoader(bytes);
            foreach (Action<byte[]> change in new Action<byte[]>[] {
                b => Put16(b, 0x84, 0x14C), b => Put16(b, 0x96, 2), b => Put(b, 0x98 + 16, 0x1010),
                b => Put(b, 0x98 + 112 + 9 * 8, 0x1000), b => Put(b, 0x98 + 116 + 9 * 8, 4),
                b => Put(b, 0x98 + 112 + 14 * 8, 0x1000), b => Put(b, 0x98 + 112 + 13 * 8, 0x1000),
                b => b[0x310] ^= 1, b => Put(b, 0xA14, 2), b => Put(b, 0xA18, 2),
                b => Put(b, 0xA40, 0x1800), b => b[0xA80] ^= 1, b => Put16(b, 0xA48, 1)
            }) {
                byte[] bad = (byte[])bytes.Clone(); change(bad); bool refused = false;
                try { QualifyRegistryLoader(bad); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
        }
    }
}
