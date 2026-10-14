using System;
using System.Globalization;

namespace ScientificSecurity
{
    public sealed partial class KernelImage
    {
        internal const uint ObservationRva = 0xBD243;
        static readonly uint[] observationRvas = { 0xBD273, 0xBD278, 0xBD27A, 0xBD300, 0xBD302, 0xBD1FA, 0xBD1FD, 0xBD201, 0xBD202, 0xBD243, 0xBD245 };
        static readonly string[] observationBytes = { "E8F8110000", "85C0", "0F8880000000", "32C0", "E9F3FEFFFF", "0FB6C0", "4883C440", "5B", "C3", "3C01", "75B3" };
        static readonly string[] observationText = { "call operands=rva:0x000BE470", "test operands=eax,eax", "js operands=rva:0x000BD300",
            "xor operands=al,al", "jmp operands=rva:0x000BD1FA", "movzx operands=eax,al", "add operands=withheld", "pop operands=rbx", "ret operands=none",
            "cmp operands=al,1", "jne operands=rva:0x000BD1FA" };
        static void RequireObservationIdentity(string identity)
        {
            Need(identity == "phase=image-identity module=kernelbase.dll sha256=f4acdac5f1dc54b20c84a51ad0f507f421f5d1170e276a5a75d4e7dcf88750e2" +
                " pdb_guid=0b01ed22-aa49-026d-b0b3-95e011af2a5e pdb_age=1 pdb_name=kernelbase.pdb pe_timestamp=2900858579 image_size=4120576 file_size=4129456");
        }
        internal uint RequireObservationProfile()
        {
            RequireObservationIdentity(KernelBaseIdentity()); return ObservationBytes();
        }
        static void RequireObservationRecords(StaticView view)
        {
            Need(view != null && view.Text != null);
            string[] lines = view.Text.Split('\n');
            for (int index = 0; index < observationRvas.Length; index++) {
                string expected = "rva=0x" + observationRvas[index].ToString("X8", CultureInfo.InvariantCulture) +
                    " bytes=" + observationBytes[index] + " mnemonic=" + observationText[index];
                int matches = 0; foreach (string line in lines) if (line == expected) matches++;
                Need(matches == 1);
            }
        }
        internal void RequireObservationStatic(StaticView view)
        { RequireObservationProfile(); RequireObservationRecords(view); }
        bool FullExecutable(uint rva, uint length)
        {
            int matches = 0;
            foreach (var section in sections)
                if ((section.flags & 0x20000000) != 0 && rva >= section.rva &&
                    (ulong)rva + length <= (ulong)section.rva + Math.Min(section.size, section.rawSize)) matches++;
            return length != 0 && (ulong)rva + length <= imageSize && matches == 1;
        }
        uint ObservationBytes()
        {
            Need(Name == "kernelbase.dll" && Entry == 0xBD1A0);
            var slice = EntrySlice(); ulong end = (ulong)Entry + slice.Length;
            for (int index = 0; index < observationRvas.Length; index++) {
                uint rva = observationRvas[index], length = (uint)observationBytes[index].Length / 2;
                Need(rva >= Entry && (ulong)rva + length <= end && FullExecutable(rva, length));
                for (int prior = 0; prior < index; prior++) {
                    uint old = observationRvas[prior], oldLength = (uint)observationBytes[prior].Length / 2;
                    Need((ulong)rva + length <= old || (ulong)old + oldLength <= rva);
                }
                int raw = Map(rva, length);
                for (int item = 0; item < length; item++)
                    Need(data[raw + item] == Byte.Parse(observationBytes[index].Substring(item * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
            }
            long call = checked(0xBD278L + BitConverter.ToInt32(data, Map(0xBD274, 4)));
            long sign = checked(0xBD280L + BitConverter.ToInt32(data, Map(0xBD27C, 4)));
            long tail = checked(0xBD307L + BitConverter.ToInt32(data, Map(0xBD303, 4)));
            long earlier = checked(0xBD247L + unchecked((sbyte)data[Map(0xBD246, 1)]));
            Need(call == 0xBE470 && sign == 0xBD300 && tail == 0xBD1FA && earlier == 0xBD1FA && FullExecutable((uint)call, 1));
            Need(FullExecutable(ObservationRva, 2)); return ObservationRva;
        }
        static void CheckObservationValidation()
        {
            const string identity = "phase=image-identity module=kernelbase.dll sha256=f4acdac5f1dc54b20c84a51ad0f507f421f5d1170e276a5a75d4e7dcf88750e2 pdb_guid=0b01ed22-aa49-026d-b0b3-95e011af2a5e pdb_age=1 pdb_name=kernelbase.pdb pe_timestamp=2900858579 image_size=4120576 file_size=4129456";
            RequireObservationIdentity(identity);
            foreach (string changed in new [] { null, "", identity + " ", identity.Replace("pdb_age=1", "pdb_age=2"),
                identity.Replace("f4acdac5", "04acdac5"), identity.Replace("4129456", "4129455"), identity.Replace("0b01ed22", "0b01ed23"),
                identity.Replace("2900858579", "2900858578"), identity.Replace("4120576", "4120575"), identity.Replace("kernelbase.pdb", "other.pdb") }) {
                bool refused = false;
                try { RequireObservationIdentity(changed); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            // Synthetic mapped bytes exercise subvalidators only, never the real image's SHA-qualified profile.
            byte[] bytes = ObservationFixture(); var image = FromStatic(bytes);
            Need(image.ObservationBytes() == 0xBD243);
            uint firstRaw = 0x00000101, secondRaw = 0x00000001;
            Need(firstRaw != secondRaw && (firstRaw & 0xFF) == 1 && (secondRaw & 0xFF) == 1); // CMP consumes AL, not the full raw EAX receipt.
            string listing = "  00000001800BD1FA: 0F B6 C0     movzx eax,al\n" +
                "  00000001800BD1FD: 48 83 C4 40     add rsp,40h\n" +
                "  00000001800BD201: 5B     pop rbx\n  00000001800BD202: C3     ret\n" +
                "  00000001800BD243: 3C 01     cmp al,1\n  00000001800BD245: 75 B3     jne 00000001800BD1FA\n" +
                "  00000001800BD273: E8 F8 11 00 00     call 00000001800BE470\n" +
                "  00000001800BD278: 85 C0     test eax,eax\n" +
                "  00000001800BD27A: 0F 88 80 00 00 00     js 00000001800BD300\n" +
                "  00000001800BD300: 32 C0     xor al,al\n  00000001800BD302: E9 F3 FE FF FF     jmp 00000001800BD1FA\n";
            var view = image.QualifyStatic(listing); RequireObservationRecords(view);
            foreach (string changed in new [] { listing.Replace("  00000001800BD278: 85 C0     test eax,eax\n", ""),
                listing.Replace("85 C0     test eax,eax\n", "85 C0     test eax,eax\n       00\n"),
                listing.Replace("test eax,eax", "bogus eax,eax"),
                listing.Replace("00000001800BE470", "00000001800BE471"),
                listing.Replace("movzx eax,al", "movzx eax,0"),
                listing.Replace("  00000001800BD243: 3C 01     cmp al,1\n", ""),
                listing.Replace("  00000001800BD245: 75 B3     jne 00000001800BD1FA\n", ""),
                listing.Replace("cmp al,1\n", "cmp al,1\n       00\n"),
                listing.Replace("jne 00000001800BD1FA\n", "jne 00000001800BD1FA\n       00\n"),
                listing.Replace("cmp al,1", "cmp eax,1"),
                listing.Replace("75 B3     jne", "75 B3     je"),
                listing.Replace("jne 00000001800BD1FA", "jne 00000001800BD1FB") }) {
                bool refused = false;
                try { RequireObservationRecords(image.QualifyStatic(changed)); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            foreach (Action<byte[]> change in new Action<byte[]>[] {
                b => b[0x378] = 0x84, b => b[0x37A] = 0x78, b => b[0x374] = 0,
                b => b[0x343] = 0x3D, b => b[0x344] = 0, b => b[0x345] = 0x74, b => b[0x346] = 0xB4,
                b => Put(b, 0x188 + 8, 0x144), b => Put(b, 0x188 + 16, 0x144),
                b => b[0x403] = 0, b => b[0x2FA] = 0, b => b[0x2FE] = 0,
                b => Put(b, 0x98 + 16, 0xBD1A1), b => Put(b, 0x188 + 8, 0x179),
                b => Put(b, 0x188 + 16, 0x179), b => Put(b, 0x188 + 36, 0x40000040),
                b => Put(b, 0x98 + 112 + 14 * 8, 1), b => Put(b, 0x188 + 8, 0x1200)
            }) {
                byte[] bad = (byte[])bytes.Clone(); change(bad); bool refused = false;
                try { FromStatic(bad).ObservationBytes(); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            bool fakeIdentityRefused = false;
            try { image.RequireObservationProfile(); } catch (InvalidOperationException) { fakeIdentityRefused = true; }
            Need(fakeIdentityRefused);
        }
        static byte[] ObservationFixture()
        {
            byte[] bytes = new byte[0x2400]; Array.Copy(Fixture(), bytes, 1024);
            BitConverter.GetBytes(0x180000000UL).CopyTo(bytes, 0x98 + 24);
            Put(bytes, 0x98 + 16, 0xBD1A0); Put(bytes, 0x98 + 56, 0xC0000);
            Put(bytes, 0x188 + 12, 0xBD100); Put(bytes, 0x188 + 8, 0x2000); Put(bytes, 0x188 + 16, 0x2000);
            new byte[] { 0x3C, 0x01, 0x75, 0xB3 }.CopyTo(bytes, 0x343);
            new byte[] { 0xE8, 0xF8, 0x11, 0, 0, 0x85, 0xC0, 0x0F, 0x88, 0x80, 0, 0, 0 }.CopyTo(bytes, 0x373);
            new byte[] { 0x32, 0xC0, 0xE9, 0xF3, 0xFE, 0xFF, 0xFF }.CopyTo(bytes, 0x400);
            new byte[] { 0x0F, 0xB6, 0xC0, 0x48, 0x83, 0xC4, 0x40, 0x5B, 0xC3 }.CopyTo(bytes, 0x2FA);
            return bytes;
        }
    }
}
