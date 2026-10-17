using System;
using System.Collections.Generic;

namespace ScientificSecurity
{
    public sealed partial class KernelImage
    {
        // Qualifies only actual numeric RT_MANIFEST/1/one-language metadata; never loads the image.
        internal static Tuple<ushort, uint> PythonManifest(byte[] bytes)
        { return new KernelImage(bytes, 1, "python-manifest").Manifest(); }
        Tuple<ushort, uint> Manifest()
        { int offset; return Manifest(false, out offset); }
        internal static Tuple<ushort, byte[]> DefaultManifest(byte[] bytes, bool sole)
        {
            var image = new KernelImage(bytes, 1, "fixed-default-manifest"); int offset;
            var metadata = image.Manifest(sole, out offset);
            var payload = new byte[metadata.Item2]; Array.Copy(bytes, offset, payload, 0, payload.Length);
            return Tuple.Create(metadata.Item1, payload);
        }
        Tuple<ushort, uint> Manifest(bool sole, out int offset)
        {
            ulong optional = (ulong)U32(0x3C) + 24;
            uint rva = U32(optional + 128), size = U32(optional + 132);
            Need(rva != 0 && size >= 16 && size <= 1048576);
            int root = Map(rva, size);
            if (sole) Need(U16((ulong)root + 14) == 1);
            var spans = new List<Tuple<uint, uint>>();
            uint type = ResourceEntry(root, size, 0, 24, 128, spans);
            Need((type & 0x80000000) != 0);
            if (sole) Need(U16((ulong)root + (type & 0x7FFFFFFF) + 14) == 1);
            uint name = ResourceEntry(root, size, type & 0x7FFFFFFF, 1, 16, spans);
            Need((name & 0x80000000) != 0);
            uint languageTable = name & 0x7FFFFFFF;
            ResourceSpan(size, languageTable, 24, spans);
            ulong table = (ulong)root + languageTable;
            Need(U16(table + 12) == 0 && U16(table + 14) == 1);
            uint language = U32(table + 16), entry = U32(table + 20);
            Need(language <= UInt16.MaxValue && (entry & 0x80000000) == 0);
            ResourceSpan(size, entry, 16, spans);
            ulong dataEntry = (ulong)root + entry;
            uint payload = U32(dataEntry), length = U32(dataEntry + 4);
            Need(U32(dataEntry + 12) == 0 && length > 0 && length <= 65536 && payload >= rva);
            uint relative = payload - rva;
            ResourceSpan(size, relative, length, spans);
            offset = Map(payload, length); Need(offset == root + relative);
            return Tuple.Create((ushort)language, length);
        }
        uint ResourceEntry(int root, uint size, uint offset, uint selected, uint maximum, List<Tuple<uint, uint>> spans)
        {
            Need(offset <= size && size - offset >= 16);
            ulong table = (ulong)root + offset;
            uint named = U16(table + 12), count = U16(table + 14);
            Need(named == 0 && count > 0 && count <= maximum);
            ResourceSpan(size, offset, checked(16 + count * 8), spans);
            uint prior = 0, found = 0; bool matched = false;
            for (uint index = 0; index < count; index++) {
                uint id = U32(table + 16 + index * 8);
                Need(id <= UInt16.MaxValue && (index == 0 || id > prior)); prior = id;
                if (id == selected) { Need(!matched); found = U32(table + 20 + index * 8); matched = true; }
            }
            Need(matched); return found;
        }
        static void ResourceSpan(uint size, uint offset, uint length, List<Tuple<uint, uint>> spans)
        {
            Need(offset <= size && length <= size - offset);
            foreach (var span in spans)
                Need((ulong)offset + length <= span.Item1 || (ulong)span.Item1 + span.Item2 <= offset);
            spans.Add(Tuple.Create(offset, length));
        }
        public static void CheckManifestValidation()
        {
            byte[] bytes = Fixture();
            Put(bytes, 0x98 + 128, 0x1000); Put(bytes, 0x98 + 132, 0x200);
            Array.Clear(bytes, 0x200, 0x200);
            Put16(bytes, 0x20E, 1); Put(bytes, 0x210, 24); Put(bytes, 0x214, 0x80000020);
            Put16(bytes, 0x22E, 1); Put(bytes, 0x230, 1); Put(bytes, 0x234, 0x80000040);
            Put16(bytes, 0x24E, 1); Put(bytes, 0x250, 1033); Put(bytes, 0x254, 0x60);
            Put(bytes, 0x260, 0x1080); Put(bytes, 0x264, 4);
            bytes[0x280] = 1; bytes[0x281] = 2; bytes[0x282] = 3; bytes[0x283] = 4;
            var actual = PythonManifest(bytes);
            Need(actual.Item1 == 1033 && actual.Item2 == 4);
            var payload = DefaultManifest(bytes, true);
            Need(payload.Item1 == 1033 && payload.Item2.Length == 4 && payload.Item2[0] == 1 && payload.Item2[3] == 4);
            payload.Item2[0] = 9; Need(bytes[0x280] == 1);
            foreach (bool extraType in new [] { true, false }) {
                byte[] extra = (byte[])bytes.Clone();
                if (extraType) { Put16(extra, 0x20E, 2); Put(extra, 0x218, 25); Put(extra, 0x21C, 0x80000020); }
                else { Put16(extra, 0x22E, 2); Put(extra, 0x238, 2); Put(extra, 0x23C, 0x80000040); }
                Need(PythonManifest(extra).Item2 == 4);
                bool rejected = false; try { DefaultManifest(extra, true); } catch (InvalidOperationException) { rejected = true; }
                Need(rejected);
            }
            foreach (Action<byte[]> change in new Action<byte[]>[] {
                b => Put(b, 0x98 + 128, 0), b => Put(b, 0x98 + 132, 15),
                b => Put16(b, 0x20E, 129), b => Put16(b, 0x20C, 1), b => Put(b, 0x210, 23),
                b => Put(b, 0x214, 0x80000000), b => Put(b, 0x214, 0xFFFFFFF0),
                b => Put(b, 0x234, 0x80000020), b => Put(b, 0x254, 0x80000060),
                b => Put16(b, 0x24E, 2), b => Put(b, 0x250, 65536), b => Put(b, 0x26C, 1),
                b => Put(b, 0x260, 0x1040), b => Put(b, 0x264, 65537), b => Put(b, 0x264, 0),
                b => { Put16(b, 0x20E, 2); Put(b, 0x218, 24); Put(b, 0x21C, 0x80000020); }
            }) {
                byte[] bad = (byte[])bytes.Clone(); change(bad); bool refused = false;
                try { PythonManifest(bad); } catch (InvalidOperationException) { refused = true; }
                Need(refused); refused = false;
                try { DefaultManifest(bad, true); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
        }
    }
}
