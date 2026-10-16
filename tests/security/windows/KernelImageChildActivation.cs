using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ScientificSecurity
{
    public sealed partial class KernelImage
    {
        static readonly string[] ActivationImports = { "CreateActCtxW", "ExitProcess", "GetLastError", "GetStdHandle", "ReleaseActCtx", "WriteFile" };
        internal static void QualifyChildActivation(byte[] bytes)
        { new KernelImage(bytes, 1, "fixed-child-activation").ChildActivation(); }
        void ChildActivation()
        {
            Need(data.Length <= 1048576);
            ulong nt = U32(0x3C), optional = nt + 24;
            Need((U16(nt + 22) & 0x2002) == 2 && U16(optional + 68) == 3 && Entry != 0);
            foreach (int directory in new [] { 0, 2, 9, 13, 14 })
                Need(U32(optional + 112 + (ulong)directory * 8) == 0 && U32(optional + 116 + (ulong)directory * 8) == 0);
            uint rva = U32(optional + 120), size = U32(optional + 124);
            Need(rva != 0 && size >= 40 && size <= 128);
            int table = Map(rva, size);
            uint lookup = U32((ulong)table), name = U32((ulong)table + 12), address = U32((ulong)table + 16);
            Need(lookup != 0 && name != 0 && address != 0 && U32((ulong)table + 4) == 0 && U32((ulong)table + 8) == 0);
            for (uint tail = 20; tail < size; tail++) Need(data[table + tail] == 0);
            Need(String.Equals(ActivationText(name), "KERNEL32.dll", StringComparison.OrdinalIgnoreCase));
            var imports = new HashSet<string>(StringComparer.Ordinal);
            for (uint index = 0; index <= 6; index++) {
                Need(lookup <= UInt32.MaxValue - index * 8 && address <= UInt32.MaxValue - index * 8);
                ulong symbol = BitConverter.ToUInt64(data, Map(lookup + index * 8, 8));
                Need(symbol == BitConverter.ToUInt64(data, Map(address + index * 8, 8)));
                if (symbol == 0) { Need(index == 6 && imports.SetEquals(ActivationImports)); return; }
                Need(index < 6 && symbol <= UInt32.MaxValue - 2);
                Map((uint)symbol, 2);
                Need(imports.Add(ActivationText((uint)symbol + 2)));
            }
            throw new InvalidOperationException("fixed activation imports lack terminator");
        }
        string ActivationText(uint rva)
        {
            var text = new StringBuilder();
            for (uint index = 0; index < 64; index++) {
                Need(rva <= UInt32.MaxValue - index);
                byte value = data[Map(rva + index, 1)];
                if (value == 0) return text.ToString();
                Need(value >= 32 && value <= 126); text.Append((char)value);
            }
            throw new InvalidOperationException("fixed activation import text exceeds bound");
        }
        public static void CheckChildActivationValidation()
        {
            byte[] bytes = Fixture(); Array.Resize(ref bytes, 2048);
            Put16(bytes, 0x96, 2); Put16(bytes, 0x98 + 68, 3);
            Put(bytes, 0x188 + 8, 0x600); Put(bytes, 0x188 + 16, 0x600);
            Put(bytes, 0x98 + 120, 0x1000); Put(bytes, 0x98 + 124, 40);
            Array.Clear(bytes, 0x200, 0x600);
            Put(bytes, 0x200, 0x1040); Put(bytes, 0x20C, 0x10C0); Put(bytes, 0x210, 0x1080);
            Encoding.ASCII.GetBytes("KERNEL32.dll\0").CopyTo(bytes, 0x2C0);
            int text = 0x300;
            for (int index = 0; index < ActivationImports.Length; index++) {
                ulong rva = (ulong)(text - 0x200 + 0x1000);
                BitConverter.GetBytes(rva).CopyTo(bytes, 0x240 + index * 8);
                BitConverter.GetBytes(rva).CopyTo(bytes, 0x280 + index * 8);
                byte[] symbol = Encoding.ASCII.GetBytes(ActivationImports[index] + "\0");
                symbol.CopyTo(bytes, text + 2); text += symbol.Length + 2;
            }
            QualifyChildActivation(bytes);
            foreach (Action<byte[]> change in new Action<byte[]>[] {
                b => Put16(b, 0x96, 0x2002), b => Put16(b, 0x98 + 68, 2), b => Put(b, 0x98 + 16, 0),
                b => Put(b, 0x98 + 128, 0x1000), b => Put(b, 0x98 + 132, 8),
                b => Put(b, 0x98 + 112, 0x1000), b => Put(b, 0x98 + 112 + 9 * 8, 0x1000),
                b => Put(b, 0x98 + 112 + 13 * 8, 0x1000), b => Put(b, 0x98 + 112 + 14 * 8, 0x1000),
                b => Put(b, 0x98 + 124, 39), b => Put(b, 0x98 + 124, 129),
                b => Put(b, 0x214, 1), b => b[0x2C0] = (byte)'X', b => b[0x302] = (byte)'X',
                b => b[0x280] ^= 1, b => Array.Clear(b, 0x240, 8),
                b => { Array.Copy(b, 0x240, b, 0x248, 8); Array.Copy(b, 0x280, b, 0x288, 8); },
                b => { b[0x247] = 0x80; b[0x287] = 0x80; },
                b => { Put(b, 0x240, UInt32.MaxValue); Put(b, 0x280, UInt32.MaxValue); }
            }) {
                byte[] bad = (byte[])bytes.Clone(); change(bad); bool refused = false;
                try { QualifyChildActivation(bad); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
        }
    }
}
