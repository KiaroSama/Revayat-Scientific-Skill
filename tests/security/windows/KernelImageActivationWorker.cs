using System;
using System.Collections.Generic;
using System.Text;

namespace ScientificSecurity
{
    public sealed partial class KernelImage
    {
        public static void CheckActivationWorkerValidation()
        {
            byte[] bytes = ActivationWorkerFixture(); var image = FromActivationWorker(bytes);
            var slice = image.ActivationWorkerSlice();
            Need(slice.Rva == 0x1020 && slice.Start == 0x180001020UL && slice.Raw == 0x220 && slice.Length == 1504);
            var view = image.QualifyStatic("Dump of file C:\\private\\kernel32.dll\n" +
                "  0000000180001020: B8 01 00 00 00     mov eax,1\n" +
                "  0000000180001025: E9 D6 FF FF FF     jmp 0000000180001000\n", slice);
            Need(view.Records == 2 && view.Unsupported == 0 && view.Text ==
                "rva=0x00001020 bytes=B801000000 mnemonic=mov operands=eax,1\n" +
                "rva=0x00001025 bytes=E9D6FFFFFF mnemonic=jmp operands=rva:0x00001000\n");
            Need(!view.Text.Contains("private") && !view.Text.Contains("18000") && !view.Text.Contains("\\"));
            string identity = image.ActivationWorkerIdentity();
            Need(identity.StartsWith("phase=image-identity module=kernel32.dll sha256=", StringComparison.Ordinal) &&
                identity.EndsWith(" pe_timestamp=305419896 image_size=8192 file_size=2048", StringComparison.Ordinal) &&
                identity.Length < 256 && !identity.Contains("pdb") && !identity.Contains("\\"));
            byte[] drift = (byte[])bytes.Clone(); drift[0x700] ^= 1;
            Need(FromActivationWorker(drift).ActivationWorkerIdentity() != identity);
            var partial = image.QualifyStatic("  0000000180001020: B8 01     mov eax,1\n       00 00 00\n" +
                "  0000000180001025: E9 D6 FF FF FF     jmp 0000000180001000\n", slice);
            Need(partial.Records == 1 && partial.Unsupported == 1 && partial.Text ==
                "rva=0x00001025 bytes=E9D6FFFFFF mnemonic=jmp operands=rva:0x00001000\n");
            foreach (Action<byte[]> change in new Action<byte[]>[] {
                b => Put(b, 0x98 + 112, 0), b => Put(b, 0x98 + 112, UInt32.MaxValue),
                b => Put(b, 0x98 + 116, 39), b => Put(b, 0x98 + 116, 1048577),
                b => Put(b, 0x400, 1), b => Put(b, 0x400 + 20, 0),
                b => Put(b, 0x400 + 20, 4097), b => Put(b, 0x400 + 24, 0),
                b => Put(b, 0x400 + 24, 4097), b => Put(b, 0x400 + 16, UInt32.MaxValue),
                b => Put(b, 0x400 + 28, UInt32.MaxValue), b => Put(b, 0x400 + 32, UInt32.MaxValue),
                b => Put(b, 0x400 + 36, UInt32.MaxValue), b => Put16(b, 0x458, 2),
                b => Put(b, 0x450, 0), b => Put(b, 0x450, UInt32.MaxValue),
                b => b[0x480] = (byte)'X', b => b[0x480] = 0, b => b[0x480] = 0x80,
                b => { for (int i = 0; i < 129; i++) b[0x480 + i] = (byte)'A'; },
                b => { Put(b, 0x400 + 24, 2); Put(b, 0x454, 0x1280); Put16(b, 0x45A, 0); },
                b => Put(b, 0x440, 0), b => Put(b, 0x440, 0x1300),
                b => Put(b, 0x440, 0x1600), b => Put(b, 0x440, 0x2000),
                b => Put(b, 0x440, UInt32.MaxValue), b => Put(b, 0x188 + 36, 0x40000040),
                b => Put(b, 0x188 + 8, 0x20), b => Put(b, 0x188 + 20, 0x100),
                b => Array.Clear(b, 0x98 + 24, 8), b => BitConverter.GetBytes(UInt64.MaxValue).CopyTo(b, 0x98 + 24),
                b => Put(b, 0x98 + 112 + 14 * 8, 1), b => Put16(b, 0x96, 2)
            }) {
                byte[] bad = (byte[])bytes.Clone(); change(bad); bool refused = false;
                try { FromActivationWorker(bad).ActivationWorkerSlice(); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            // A forwarded RVA exactly at the export directory's start is refused too.
            byte[] forwardStart = (byte[])bytes.Clone(); Put(forwardStart, 0x440, 0x1200);
            bool forwardRefused = false;
            try { FromActivationWorker(forwardStart).ActivationWorkerSlice(); } catch (InvalidOperationException) { forwardRefused = true; }
            Need(forwardRefused);
            byte[] ordinal = (byte[])bytes.Clone(); Put16(ordinal, 0x458, 1); Put(ordinal, 0x444, 0x1020); Put(ordinal, 0x440, 0);
            Need(FromActivationWorker(ordinal).ActivationWorkerSlice().Rva == 0x1020); // Unbiased name ordinal, not public base 7.
            byte[] second = (byte[])bytes.Clone(); Put(second, 0x400 + 24, 2);
            Put(second, 0x450, 0x12B0); Put(second, 0x454, 0x1280); Put16(second, 0x458, 1); Put16(second, 0x45A, 0);
            Encoding.ASCII.GetBytes("OtherExport\0").CopyTo(second, 0x4B0);
            Need(FromActivationWorker(second).ActivationWorkerSlice().Rva == 0x1020);
            byte[] clipped = (byte[])bytes.Clone(); Put(clipped, 0x188 + 8, 0x30);
            Need(FromActivationWorker(clipped).ActivationWorkerSlice().Length == 16);
            byte[] large = new byte[8192]; Array.Copy(bytes, large, bytes.Length);
            Put(large, 0x188 + 8, 6144); Put(large, 0x188 + 16, 6144); Put(large, 0x98 + 56, 12288);
            Need(FromActivationWorker(large).ActivationWorkerSlice().Length == 4096);
            foreach (string invalid in new [] { "", "  0000000180001020: C3     ret\n", "  0000000180001000: B8     mov eax,1\n" }) {
                bool refused = false;
                try { image.QualifyStatic(invalid, slice); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            var tampered = slice; tampered.Raw++;
            bool sliceRefused = false;
            try { image.QualifyStatic("  0000000180001020: B8 01 00 00 00     mov eax,1\n", tampered); }
            catch (InvalidOperationException) { sliceRefused = true; }
            Need(sliceRefused);
            bool wrongImage = false;
            try { FromStatic(bytes).ActivationWorkerSlice(); } catch (InvalidOperationException) { wrongImage = true; }
            Need(wrongImage);
        }
        static byte[] ActivationWorkerFixture()
        {
            byte[] bytes = StaticFixture(); Put16(bytes, 0x96, 0x2002);
            Put(bytes, 0x98 + 112, 0x1200); Put(bytes, 0x98 + 116, 0x200);
            Array.Clear(bytes, 0x400, 0x200);
            Put(bytes, 0x400 + 16, 7); Put(bytes, 0x400 + 20, 2); Put(bytes, 0x400 + 24, 1);
            Put(bytes, 0x400 + 28, 0x1240); Put(bytes, 0x400 + 32, 0x1250); Put(bytes, 0x400 + 36, 0x1258);
            Put(bytes, 0x440, 0x1020); Put(bytes, 0x450, 0x1280);
            Encoding.ASCII.GetBytes("CreateActCtxWWorker\0").CopyTo(bytes, 0x480);
            new byte[] { 0xB8, 1, 0, 0, 0, 0xE9, 0xD6, 0xFF, 0xFF, 0xFF }.CopyTo(bytes, 0x220);
            return bytes;
        }
        internal static KernelImage FromActivationWorker(byte[] bytes)
        { return new KernelImage(bytes, 1, "kernel32.dll"); }
        internal string ActivationWorkerIdentity()
        {
            Need(Name == "kernel32.dll"); ulong nt = U32(0x3C);
            return "phase=image-identity module=kernel32.dll sha256=" + Hash(data) +
                " pe_timestamp=" + Number(U32(nt + 8)) + " image_size=" + Number(imageSize) + " file_size=" + Number((uint)data.Length);
        }
        internal StaticSlice ActivationWorkerSlice()
        {
            Need(Name == "kernel32.dll" && (U16((ulong)U32(0x3C) + 22) & 0x2002) == 0x2002);
            ulong optional = (ulong)U32(0x3C) + 24;
            uint rva = U32(optional + 112), size = U32(optional + 116);
            Need(rva >= headers && size >= 40 && size <= 1048576);
            int table = Map(rva, size); Need(U32((ulong)table) == 0);
            uint functions = U32((ulong)table + 20), names = U32((ulong)table + 24), ordinalBase = U32((ulong)table + 16);
            Need(functions >= 1 && functions <= 4096 && names >= 1 && names <= 4096 &&
                (ulong)ordinalBase + functions - 1 <= UInt32.MaxValue);
            int addresses = Map(U32((ulong)table + 28), functions * 4);
            int pointers = Map(U32((ulong)table + 32), names * 4);
            int ordinals = Map(U32((ulong)table + 36), names * 2);
            var unique = new HashSet<string>(StringComparer.Ordinal); uint target = 0; int matches = 0;
            for (uint index = 0; index < names; index++) {
                string name = ActivationExportName(U32((ulong)pointers + index * 4));
                Need(unique.Add(name)); ushort ordinal = U16((ulong)ordinals + index * 2); Need(ordinal < functions);
                if (name != "CreateActCtxWWorker") continue;
                matches++; target = U32((ulong)addresses + (ulong)ordinal * 4);
            }
            Need(matches == 1 && target != 0 && (target < rva || (ulong)target >= (ulong)rva + size));
            return StaticSliceAt(target);
        }
        string ActivationExportName(uint rva)
        {
            Need(rva >= headers); var name = new StringBuilder();
            for (uint index = 0; index <= 128; index++) {
                ulong position = (ulong)rva + index; Need(position <= UInt32.MaxValue);
                byte value = data[Map((uint)position, 1)];
                if (value == 0) { Need(name.Length != 0); return name.ToString(); }
                Need(index < 128 && value >= 32 && value <= 126); name.Append((char)value);
            }
            throw new InvalidOperationException("fixed activation-worker export name exceeds bound");
        }
    }
}
