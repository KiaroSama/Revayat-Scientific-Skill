using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace ScientificSecurity
{
    public sealed partial class KernelImage
    {
        // Identity of the exact cached load-event file. No reopen, remote reads or symbol acquisition.
        internal string KernelBaseIdentity()
        {
            Need(Name == "kernelbase.dll");
            uint nt = U32(0x3C); ulong optional = (ulong)nt + 24;
            uint tableRva = U32(optional + 112 + 6 * 8), tableBytes = U32(optional + 116 + 6 * 8);
            Need(tableRva != 0 && tableBytes >= 28 && tableBytes % 28 == 0 && tableBytes / 28 <= 64);
            int table = Map(tableRva, tableBytes);
            var ranges = new List<Tuple<ulong, ulong>> { Tuple.Create((ulong)table, (ulong)table + tableBytes) };
            Guid guid = Guid.Empty; uint age = 0; int codeViews = 0;
            for (uint index = 0; index < tableBytes / 28; index++) {
                ulong record = (ulong)table + index * 28;
                Need(U32(record) == 0); // Reserved IMAGE_DEBUG_DIRECTORY characteristics.
                uint kind = U32(record + 12), size = U32(record + 16), rva = U32(record + 20), raw = U32(record + 24);
                if (size == 0) { Need(kind != 2 && rva == 0 && raw == 0); continue; }
                Need(raw != 0); Range(raw, size);
                if (rva != 0) Need((ulong)Map(rva, size) == raw);
                if (kind == 2) Need(rva != 0); // Selected CodeView must be mapped; unused records may be file-only.
                ulong end = (ulong)raw + size;
                foreach (var range in ranges) Need(end <= range.Item1 || raw >= range.Item2);
                ranges.Add(Tuple.Create((ulong)raw, end));
                if (kind != 2) continue;
                Need(++codeViews == 1 && size >= 25 && size <= 512 && U32(raw) == 0x53445352);
                byte[] signature = new byte[16]; Array.Copy(data, (long)raw + 4, signature, 0, 16);
                guid = new Guid(signature); age = U32((ulong)raw + 20);
                Need(guid != Guid.Empty && age != 0);
                byte[] name = Encoding.ASCII.GetBytes("kernelbase.pdb\0");
                Need(size == 24 + name.Length);
                for (int offset = 0; offset < name.Length; offset++) Need(data[raw + 24 + offset] == name[offset]);
            }
            Need(codeViews == 1);
            return "phase=image-identity module=kernelbase.dll sha256=" + Hash(data)
                + " pdb_guid=" + guid.ToString("D") + " pdb_age=" + Number(age) + " pdb_name=kernelbase.pdb"
                + " pe_timestamp=" + Number(U32((ulong)nt + 8)) + " image_size=" + Number(imageSize)
                + " file_size=" + Number((uint)data.Length);
        }
        static string Number(uint value) { return value.ToString(CultureInfo.InvariantCulture); }
        static string Hash(byte[] bytes)
        {
            using (SHA256 sha = SHA256.Create()) {
                byte[] digest = sha.ComputeHash(bytes);
                try { return BitConverter.ToString(digest).Replace("-", "").ToLowerInvariant(); }
                finally { Array.Clear(digest, 0, digest.Length); }
            }
        }
        static void CheckIdentityValidation()
        {
            // Independent SHA and GUID byte-order literals, not values derived from the parser.
            Need(Hash(Encoding.ASCII.GetBytes("abc")) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
            byte[] bytes = IdentityFixture(); string line = new KernelImage(bytes, 0x10000000, "kernelbase.dll").KernelBaseIdentity();
            Need(line.Contains("pdb_guid=00112233-4455-6677-8899-aabbccddeeff pdb_age=7 pdb_name=kernelbase.pdb") &&
                line.EndsWith("pe_timestamp=305419896 image_size=8192 file_size=2048", StringComparison.Ordinal) &&
                line.Length < 512 && !line.Contains("\\") && !line.Contains("/") && !line.Contains("0x10000000"));
            byte[] changed = (byte[])bytes.Clone(); changed[0x700] = 1;
            Need(new KernelImage(changed, 0x10000000, "kernelbase.dll").KernelBaseIdentity() != line);
            foreach (Action<byte[]> mutate in new Action<byte[]>[] {
                b => Put(b, 0x98 + 160, 0), b => Put(b, 0x98 + 164, 27), b => Put(b, 0x400, 1),
                b => Put(b, 0x98 + 164, 65 * 28), b => Put(b, 0x98 + 164, UInt32.MaxValue),
                b => Put(b, 0x400 + 12, 1), b => Put(b, 0x400 + 16, 24), b => Put(b, 0x400 + 16, 513),
                b => Put(b, 0x400 + 20, 0x1281), b => Put(b, 0x400 + 24, 0x481),
                b => Put(b, 0x400 + 24, UInt32.MaxValue), b => Put(b, 0x480, 0x3031424e),
                b => Array.Clear(b, 0x484, 16), b => Put(b, 0x494, 0),
                b => b[0x498] = (byte)'X', b => b[0x498] = (byte)'/',
                b => b[0x499] = 0, b => b[0x4A6] = (byte)'X', b => Put(b, 0x400 + 16, 40),
                b => { Put(b, 0x98 + 164, 56); Array.Copy(b, 0x400, b, 0x41C, 28); },
                b => { Put(b, 0x98 + 164, 56); Array.Copy(b, 0x400, b, 0x41C, 28);
                    Put(b, 0x41C + 20, 0x1300); Put(b, 0x41C + 24, 0x500); Array.Copy(b, 0x480, b, 0x500, 39); },
                b => { Put(b, 0x400 + 20, 0); Put(b, 0x400 + 24, 0); },
                b => { Put(b, 0x400 + 16, 0); Put(b, 0x400 + 20, 0); Put(b, 0x400 + 24, 0); },
                b => { Put(b, 0x400 + 20, 0x1200); Put(b, 0x400 + 24, 0x400); }
            }) {
                byte[] bad = (byte[])bytes.Clone(); mutate(bad); bool refused = false;
                try { new KernelImage(bad, 0x10000000, "kernelbase.dll").KernelBaseIdentity(); }
                catch (InvalidOperationException) { refused = true; }
                if (!refused) throw new InvalidOperationException("malformed or ambiguous cached KernelBase identity was accepted");
            }
            byte[] withEmptyRepro = IdentityFixture(); Put(withEmptyRepro, 0x98 + 164, 56); Put(withEmptyRepro, 0x41C + 12, 16);
            Need(new KernelImage(withEmptyRepro, 0x10000000, "kernelbase.dll").KernelBaseIdentity().Contains("pdb_age=7"));
            byte[] fileOnly = IdentityFixture(); Put(fileOnly, 0x98 + 164, 56);
            Put(fileOnly, 0x41C + 12, 1); Put(fileOnly, 0x41C + 16, 4); Put(fileOnly, 0x41C + 24, 0x600);
            Need(new KernelImage(fileOnly, 0x10000000, "kernelbase.dll").KernelBaseIdentity().Contains("pdb_age=7"));
            foreach (Action<byte[]> mutate in new Action<byte[]>[] {
                b => Put(b, 0x41C + 24, 0), b => Put(b, 0x41C + 24, UInt32.MaxValue),
                b => Put(b, 0x41C + 24, 0x480),
                b => { Put(b, 0x41C + 20, 0x1401); },
                b => Put(b, 0x400 + 20, 0)
            }) {
                byte[] bad = (byte[])fileOnly.Clone(); mutate(bad); bool refused = false;
                try { new KernelImage(bad, 0x10000000, "kernelbase.dll").KernelBaseIdentity(); }
                catch (InvalidOperationException) { refused = true; }
                if (!refused) throw new InvalidOperationException("unused file-only debug record violated its qualified bounds");
            }
            byte[] second = IdentityFixture(); Put(second, 0x494, 8);
            string next = new KernelImage(second, 0x10000000, "kernelbase.dll").KernelBaseIdentity();
            Need(next.Contains("pdb_age=8") && !next.Contains("pdb_age=7") &&
                new KernelImage(bytes, 0x10000000, "kernelbase.dll").KernelBaseIdentity() == line);
            bool wrongImage = false;
            try { new KernelImage(bytes, 0x10000000, "ntdll.dll").KernelBaseIdentity(); }
            catch (InvalidOperationException) { wrongImage = true; }
            Need(wrongImage);
        }
        static byte[] IdentityFixture()
        {
            byte[] bytes = new byte[2048]; Array.Copy(Fixture(), bytes, 1024);
            Put(bytes, 0x188 + 8, 0x600); Put(bytes, 0x188 + 16, 0x600); Put(bytes, 0x80 + 8, 0x12345678);
            Put(bytes, 0x98 + 160, 0x1200); Put(bytes, 0x98 + 164, 28);
            Put(bytes, 0x400 + 12, 2); Put(bytes, 0x400 + 16, 39); Put(bytes, 0x400 + 20, 0x1280); Put(bytes, 0x400 + 24, 0x480);
            Put(bytes, 0x480, 0x53445352);
            new byte[] { 0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }.CopyTo(bytes, 0x484);
            Put(bytes, 0x494, 7); Encoding.ASCII.GetBytes("kernelbase.pdb\0").CopyTo(bytes, 0x498);
            return bytes;
        }
    }
}
