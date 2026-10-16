using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace ScientificSecurity
{
    // Reads only the exact OS load-event image handle; no symbol server or remote image parsing.
    public sealed partial class KernelImage
    {
        struct Section { internal uint rva, size, raw, rawSize, flags; }
        readonly byte[] data;
        readonly List<Section> sections = new List<Section>();
        readonly uint headers, imageSize;
        internal readonly ulong Base;
        internal readonly string Name;
        internal readonly uint Entry;
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetFinalPathNameByHandleW(IntPtr file, StringBuilder path, uint size, uint flags);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetFileSizeEx(IntPtr file, out long size);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetFilePointerEx(IntPtr file, long distance, out long position, uint origin);

        static string EventPath(IntPtr file)
        {
            if (file == IntPtr.Zero || file == Native.InvalidHandle) return null;
            var path = new StringBuilder(512);
            uint length = GetFinalPathNameByHandleW(file, path, 512, 0);
            if (length == 0 || length >= 512) throw new InvalidOperationException("hardware image path provenance is unavailable");
            string actual = path.ToString();
            if (actual.StartsWith(@"\\?\", StringComparison.Ordinal)) actual = actual.Substring(4);
            return actual;
        }
        internal static KernelImage FromLoad(IntPtr file, IntPtr imageBase)
        {
            string actual = EventPath(file);
            if (actual == null) return null;
            string name = Path.GetFileName(actual);
            if (!String.Equals(name, "ntdll.dll", StringComparison.OrdinalIgnoreCase) &&
                !String.Equals(name, "KernelBase.dll", StringComparison.OrdinalIgnoreCase)) return null;
            string expected = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), name);
            if (!String.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("hardware image is not the exact loaded system module");
            return ReadEventImage(file, imageBase, name.ToLowerInvariant());
        }
        static KernelImage ReadEventImage(IntPtr file, IntPtr imageBase, string name)
        {
            long size, position;
            Native.Check(GetFileSizeEx(file, out size), "read bounded OS image size");
            if (size < 256 || size > 16 * 1024 * 1024)
                throw new InvalidOperationException("hardware OS image exceeds fixed file bound");
            Native.Check(SetFilePointerEx(file, 0, out position, 0) && position == 0, "seek exact OS image handle");
            byte[] bytes = new byte[(int)size]; int offset = 0;
            while (offset < bytes.Length) {
                byte[] chunk = new byte[Math.Min(65536, bytes.Length - offset)]; uint read;
                Native.Check(Native.ReadFile(file, chunk, (uint)chunk.Length, out read, IntPtr.Zero), "read exact OS image handle");
                if (read == 0 || read > chunk.Length) throw new InvalidOperationException("hardware OS image read is truncated");
                Buffer.BlockCopy(chunk, 0, bytes, offset, (int)read); offset += (int)read;
            }
            return new KernelImage(bytes, unchecked((ulong)imageBase.ToInt64()), name.ToLowerInvariant());
        }
        KernelImage(byte[] bytes, ulong imageBase, string name)
        {
            data = bytes; Base = imageBase; Name = name;
            Need(data != null && data.Length >= 256 && data.Length <= 16 * 1024 * 1024 && Base != 0);
            Need(U16(0) == 0x5A4D); uint nt = U32(0x3C);
            Need(U32(nt) == 0x4550 && U16((ulong)nt + 4) == 0x8664);
            ushort count = U16((ulong)nt + 6), optionalBytes = U16((ulong)nt + 20);
            Need(count > 0 && count <= 64 && optionalBytes >= 240);
            ulong optional = (ulong)nt + 24; Range(optional, optionalBytes);
            Need(U16(optional) == 0x20B && U32(optional + 108) >= 16);
            Entry = U32(optional + 16); imageSize = U32(optional + 56); headers = U32(optional + 60);
            Need(headers > 0 && headers <= data.Length && imageSize >= headers && imageSize <= 64 * 1024 * 1024);
            ulong table = optional + optionalBytes; Range(table, (ulong)count * 40);
            Need(table + (ulong)count * 40 <= headers && Base <= 0x7FFFFFFFFFFFFFFFUL - imageSize);
            for (int index = 0; index < count; index++) {
                ulong item = table + (ulong)index * 40;
                var section = new Section { size = U32(item + 8), rva = U32(item + 12), rawSize = U32(item + 16),
                    raw = U32(item + 20), flags = U32(item + 36) };
                ulong extent = Math.Max(section.size, section.rawSize);
                Need(section.rva >= headers && extent > 0 && (ulong)section.rva + extent <= imageSize);
                Range(section.raw, section.rawSize);
                foreach (var old in sections) {
                    Need((ulong)section.rva + extent <= old.rva ||
                        (ulong)old.rva + Math.Max(old.size, old.rawSize) <= section.rva);
                    if (section.rawSize != 0 && old.rawSize != 0)
                        Need((ulong)section.raw + section.rawSize <= old.raw || (ulong)old.raw + old.rawSize <= section.raw);
                }
                sections.Add(section);
            }
            if (Entry != 0) Need(Executable(Entry));
        }
        static void Need(bool condition) { if (!condition) throw new InvalidOperationException("hardware OS image violates bounded PE contract"); }
        void Range(ulong offset, ulong bytes) { Need(offset <= (ulong)data.Length && bytes <= (ulong)data.Length - offset); }
        ushort U16(ulong offset) { Range(offset, 2); return BitConverter.ToUInt16(data, (int)offset); }
        uint U32(ulong offset) { Range(offset, 4); return BitConverter.ToUInt32(data, (int)offset); }
        int Map(uint rva, uint bytes)
        {
            int found = -1, matches = 0;
            ulong end = (ulong)rva + bytes; Need(bytes > 0 && end <= imageSize);
            if (end <= headers) { found = (int)rva; matches++; }
            foreach (var section in sections) {
                if (rva >= section.rva && end <= (ulong)section.rva + section.rawSize) {
                    ulong offset = (ulong)section.raw + rva - section.rva; Range(offset, bytes);
                    found = (int)offset; matches++;
                }
            }
            Need(matches == 1); return found;
        }
        internal bool Executable(uint rva)
        {
            foreach (var section in sections)
                if ((section.flags & 0x20000000) != 0 && rva >= section.rva &&
                    (ulong)rva < (ulong)section.rva + section.rawSize) return true;
            return false;
        }
        internal bool ContainsExecutable(ulong address)
        { return address >= Base && address - Base < imageSize && Executable((uint)(address - Base)); }
        internal ulong Address(uint rva) { Need(Executable(rva)); return Base + rva; }
        public static void CheckValidation()
        {
            CheckIdentityValidation();
            CheckStaticValidation();
            CheckObservationValidation();
            byte[] bytes = Fixture(); var image = new KernelImage(bytes, 0x10000000, "ntdll.dll");
            if (image.Entry != 0x1000 || !image.ContainsExecutable(0x10001000))
                throw new InvalidOperationException("hardware image positive parser fixture failed");
            foreach (Action<byte[]> change in new Action<byte[]>[] {
                b => Put(b, 0x3C, UInt32.MaxValue), b => Put16(b, 0x86, 65),
                b => Put(b, 0x98 + 16, 0x3000), b => Put(b, 0x188 + 36, 0x40000040),
                b => Put(b, 0x188 + 20, UInt32.MaxValue), b => Put(b, 0x188 + 12, UInt32.MaxValue),
                b => { Put16(b, 0x86, 2); Array.Copy(b, 0x188, b, 0x1B0, 40); }
            }) {
                byte[] bad = (byte[])bytes.Clone(); change(bad); bool rejected = false;
                try { new KernelImage(bad, 0x10000000, "ntdll.dll"); }
                catch (InvalidOperationException) { rejected = true; }
                if (!rejected) throw new InvalidOperationException("malformed hardware image fixture was accepted");
            }
        }
        static byte[] Fixture()
        {
            byte[] b = new byte[1024]; Put16(b, 0, 0x5A4D); Put(b, 0x3C, 0x80); Put(b, 0x80, 0x4550);
            Put16(b, 0x84, 0x8664); Put16(b, 0x86, 1); Put16(b, 0x94, 240); Put16(b, 0x98, 0x20B);
            Put(b, 0x98 + 16, 0x1000); Put(b, 0x98 + 56, 0x2000); Put(b, 0x98 + 60, 0x200);
            Put(b, 0x98 + 108, 16);
            Put(b, 0x188 + 8, 0x200); Put(b, 0x188 + 12, 0x1000); Put(b, 0x188 + 16, 0x200);
            Put(b, 0x188 + 20, 0x200); Put(b, 0x188 + 36, 0x60000020);
            return b;
        }
        static void Put(byte[] b, int offset, uint value) { BitConverter.GetBytes(value).CopyTo(b, offset); }
        static void Put16(byte[] b, int offset, ushort value) { BitConverter.GetBytes(value).CopyTo(b, offset); }
    }
}
