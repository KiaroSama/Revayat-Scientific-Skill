using System;
using System.Linq;
using System.Text;

namespace ScientificSecurity
{
    public sealed partial class KernelImage
    {
        static readonly string[] DefaultImports = { "ExitProcess", "GetStdHandle", "WriteFile" };
        internal static void QualifyDefaultActivation(byte[] bytes, ushort language, byte[] expected)
        {
            var image = new KernelImage(bytes, 1, "fixed-default-activation");
            image.ChildActivation(DefaultImports, true);
            var manifest = DefaultManifest(bytes, true);
            try { Need(manifest.Item1 == language && manifest.Item2.SequenceEqual(expected)); }
            finally { Array.Clear(manifest.Item2, 0, manifest.Item2.Length); }
        }
        public static void CheckDefaultActivationValidation()
        {
            byte[] bytes = Fixture(); Array.Resize(ref bytes, 2048);
            Put16(bytes, 0x96, 2); Put16(bytes, 0x98 + 68, 3);
            Put(bytes, 0x188 + 8, 0x600); Put(bytes, 0x188 + 16, 0x600);
            Put(bytes, 0x98 + 120, 0x1000); Put(bytes, 0x98 + 124, 40);
            Array.Clear(bytes, 0x200, 0x600);
            Put(bytes, 0x200, 0x1040); Put(bytes, 0x20C, 0x10C0); Put(bytes, 0x210, 0x1080);
            Encoding.ASCII.GetBytes("KERNEL32.dll\0").CopyTo(bytes, 0x2C0);
            int text = 0x300;
            for (int index = 0; index < DefaultImports.Length; index++) {
                ulong rva = (ulong)(text - 0x200 + 0x1000);
                BitConverter.GetBytes(rva).CopyTo(bytes, 0x240 + index * 8);
                BitConverter.GetBytes(rva).CopyTo(bytes, 0x280 + index * 8);
                byte[] symbol = Encoding.ASCII.GetBytes(DefaultImports[index] + "\0");
                symbol.CopyTo(bytes, text + 2); text += symbol.Length + 2;
            }
            Put(bytes, 0x98 + 128, 0x1300); Put(bytes, 0x98 + 132, 0x100);
            Put16(bytes, 0x50E, 1); Put(bytes, 0x510, 24); Put(bytes, 0x514, 0x80000020);
            Put16(bytes, 0x52E, 1); Put(bytes, 0x530, 1); Put(bytes, 0x534, 0x80000040);
            Put16(bytes, 0x54E, 1); Put(bytes, 0x550, 1033); Put(bytes, 0x554, 0x60);
            Put(bytes, 0x560, 0x1380); Put(bytes, 0x564, 4);
            byte[] payload = { 1, 2, 3, 4 }; payload.CopyTo(bytes, 0x580);
            QualifyDefaultActivation(bytes, 1033, payload);
            foreach (Action<byte[]> change in new Action<byte[]>[] {
                b => b[0x580] ^= 1, b => Put(b, 0x550, 0), b => Put(b, 0x530, 2),
                b => Put16(b, 0x50E, 2), b => Put16(b, 0x54E, 2), b => Put(b, 0x560, 0x1340),
                b => Put(b, 0x564, 65537), b => Put(b, 0x98 + 16, 0), b => Put16(b, 0x96, 0x2002),
                b => Put(b, 0x98 + 112, 0x1000), b => Put(b, 0x98 + 112 + 9 * 8, 0x1000),
                b => Put(b, 0x98 + 112 + 13 * 8, 0x1000), b => Put(b, 0x98 + 112 + 14 * 8, 0x1000),
                b => b[0x280] ^= 1, b => b[0x302] = (byte)'X', b => Put(b, 0x218, 1)
            }) {
                byte[] bad = (byte[])bytes.Clone(); change(bad); bool refused = false;
                try { QualifyDefaultActivation(bad, 1033, payload); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
        }
    }
}
