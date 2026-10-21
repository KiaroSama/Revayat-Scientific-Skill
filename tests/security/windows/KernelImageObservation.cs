using System;
using System.Globalization;

namespace ScientificSecurity
{
    public sealed partial class KernelImage
    {
        internal const uint ObservationRva = 0xBD0E3;
        static readonly uint[] observationRvas = { 0xBD113, 0xBD118, 0xBD11A, 0xBD1A0, 0xBD1A2, 0xBD09A, 0xBD09D, 0xBD0A1, 0xBD0A2, 0xBD0E3, 0xBD0E5 };
        static readonly string[] observationBytes = { "E8F8110000", "85C0", "0F8880000000", "32C0", "E9F3FEFFFF", "0FB6C0", "4883C440", "5B", "C3", "3C01", "75B3" };
        static readonly string[] observationText = { "call operands=rva:0x000BE310", "test operands=eax,eax", "js operands=rva:0x000BD1A0",
            "xor operands=al,al", "jmp operands=rva:0x000BD09A", "movzx operands=eax,al", "add operands=withheld", "pop operands=rbx", "ret operands=none",
            "cmp operands=al,1", "jne operands=rva:0x000BD09A" };
        static void RequireObservationIdentity(string identity)
        {
            Need(identity == "phase=image-identity module=kernelbase.dll sha256=96c0459f0d73d728e5c13a10d83d840f56913ef7281d17370a5e1eb197faa450" +
                " pdb_guid=cabdac12-ca43-8c8b-4dc4-b60b7499c804 pdb_age=1 pdb_name=kernelbase.pdb pe_timestamp=1038034819 image_size=4116480 file_size=4171392");
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
        { QualifyObservation(() => RequireObservationIdentity(KernelBaseIdentity()), () => ObservationBytes(), () => RequireObservationRecords(view)); }
        static void QualifyObservation(Action identity, Action bytes, Action records)
        {
            string phase = "identity";
            try { identity(); phase = "bytes"; bytes(); phase = "records"; records(); }
            catch (InvalidOperationException failure) {
                throw new InvalidOperationException("fixed KernelBase observation profile refused check=" + phase, failure);
            }
        }
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
            Need(Name == "kernelbase.dll" && Entry == 0xBD040);
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
            long call = checked(0xBD118L + BitConverter.ToInt32(data, Map(0xBD114, 4)));
            long sign = checked(0xBD120L + BitConverter.ToInt32(data, Map(0xBD11C, 4)));
            long tail = checked(0xBD1A7L + BitConverter.ToInt32(data, Map(0xBD1A3, 4)));
            long earlier = checked(0xBD0E7L + unchecked((sbyte)data[Map(0xBD0E6, 1)]));
            Need(call == 0xBE310 && sign == 0xBD1A0 && tail == 0xBD09A && earlier == 0xBD09A && FullExecutable((uint)call, 1));
            Need(FullExecutable(ObservationRva, 2)); return ObservationRva;
        }
        static void CheckObservationValidation()
        {
            const string identity = "phase=image-identity module=kernelbase.dll sha256=96c0459f0d73d728e5c13a10d83d840f56913ef7281d17370a5e1eb197faa450 pdb_guid=cabdac12-ca43-8c8b-4dc4-b60b7499c804 pdb_age=1 pdb_name=kernelbase.pdb pe_timestamp=1038034819 image_size=4116480 file_size=4171392";
            const string oldIdentity = "phase=image-identity module=kernelbase.dll sha256=f4acdac5f1dc54b20c84a51ad0f507f421f5d1170e276a5a75d4e7dcf88750e2 pdb_guid=0b01ed22-aa49-026d-b0b3-95e011af2a5e pdb_age=1 pdb_name=kernelbase.pdb pe_timestamp=2900858579 image_size=4120576 file_size=4129456";
            RequireObservationIdentity(identity);
            foreach (string changed in new [] { null, "", identity + " ", oldIdentity, identity.Replace("pdb_age=1", "pdb_age=2"),
                identity.Replace("96c0459f", "06c0459f"), identity.Replace("4171392", "4171391"), identity.Replace("cabdac12", "cabdac13"),
                identity.Replace("1038034819", "1038034818"), identity.Replace("4116480", "4116479"), identity.Replace("kernelbase.pdb", "other.pdb"),
                identity.Replace("96c0459f0d73d728e5c13a10d83d840f56913ef7281d17370a5e1eb197faa450", "f4acdac5f1dc54b20c84a51ad0f507f421f5d1170e276a5a75d4e7dcf88750e2") }) {
                bool refused = false;
                try { RequireObservationIdentity(changed); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            // Synthetic mapped bytes exercise subvalidators only, never the real image's SHA-qualified profile.
            byte[] bytes = ObservationFixture(); var image = FromStatic(bytes);
            Need(image.ObservationBytes() == 0xBD0E3);
            uint firstRaw = 0x00000101, secondRaw = 0x00000001;
            Need(firstRaw != secondRaw && (firstRaw & 0xFF) == 1 && (secondRaw & 0xFF) == 1); // CMP consumes AL, not the full raw EAX receipt.
            string listing = "  00000001800BD09A: 0F B6 C0     movzx eax,al\n" +
                "  00000001800BD09D: 48 83 C4 40     add rsp,40h\n" +
                "  00000001800BD0A1: 5B     pop rbx\n  00000001800BD0A2: C3     ret\n" +
                "  00000001800BD0E3: 3C 01     cmp al,1\n  00000001800BD0E5: 75 B3     jne 00000001800BD09A\n" +
                "  00000001800BD113: E8 F8 11 00 00     call 00000001800BE310\n" +
                "  00000001800BD118: 85 C0     test eax,eax\n" +
                "  00000001800BD11A: 0F 88 80 00 00 00     js 00000001800BD1A0\n" +
                "  00000001800BD1A0: 32 C0     xor al,al\n  00000001800BD1A2: E9 F3 FE FF FF     jmp 00000001800BD09A\n";
            var view = image.QualifyStatic(listing); RequireObservationRecords(view);
            foreach (string changed in new [] { listing.Replace("  00000001800BD118: 85 C0     test eax,eax\n", ""),
                listing.Replace("85 C0     test eax,eax\n", "85 C0     test eax,eax\n       00\n"),
                listing.Replace("test eax,eax", "bogus eax,eax"),
                listing.Replace("00000001800BE310", "00000001800BE311"),
                listing.Replace("movzx eax,al", "movzx eax,0"),
                listing.Replace("  00000001800BD0E3: 3C 01     cmp al,1\n", ""),
                listing.Replace("  00000001800BD0E5: 75 B3     jne 00000001800BD09A\n", ""),
                listing.Replace("cmp al,1\n", "cmp al,1\n       00\n"),
                listing.Replace("jne 00000001800BD09A\n", "jne 00000001800BD09A\n       00\n"),
                listing.Replace("cmp al,1", "cmp eax,1"),
                listing.Replace("75 B3     jne", "75 B3     je"),
                listing.Replace("jne 00000001800BD09A", "jne 00000001800BD09B"),
                listing.Replace("00000001800BD0E3", "00000001800BD0E4"), listing + listing }) {
                bool refused = false;
                try { RequireObservationRecords(image.QualifyStatic(changed)); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            foreach (Action<byte[]> change in new Action<byte[]>[] {
                b => b[0x378] = 0x84, b => b[0x37A] = 0x78, b => b[0x374] = 0,
                b => b[0x343] = 0x3D, b => b[0x344] = 0, b => b[0x345] = 0x74, b => b[0x346] = 0xB4,
                b => Put(b, 0x188 + 8, 0x144), b => Put(b, 0x188 + 16, 0x144),
                b => b[0x403] = 0, b => b[0x2FA] = 0, b => b[0x2FE] = 0,
                b => Put(b, 0x98 + 16, 0xBD041), b => Put(b, 0x98 + 16, 0xBD1A0),
                b => Put(b, 0x188 + 12, 0xBD100), b => Put(b, 0x188 + 8, 0x179),
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
            foreach (string failedPhase in new [] { "identity", "bytes", "records" }) {
                string order = ""; var original = new InvalidOperationException("fixed qualification fixture");
                Action<string> check = phase => { order += phase + ","; if (phase == failedPhase) throw original; };
                InvalidOperationException observed = null;
                try { QualifyObservation(() => check("identity"), () => check("bytes"), () => check("records")); }
                catch (InvalidOperationException failure) { observed = failure; }
                Need(observed != null && observed.Message == "fixed KernelBase observation profile refused check=" + failedPhase &&
                    Object.ReferenceEquals(observed.InnerException, original));
                Need(order == (failedPhase == "identity" ? "identity," : failedPhase == "bytes" ? "identity,bytes," : "identity,bytes,records,"));
            }
            string completed = "";
            QualifyObservation(() => completed += "identity,", () => completed += "bytes,", () => completed += "records,");
            Need(completed == "identity,bytes,records,");
        }
        static byte[] ObservationFixture()
        {
            byte[] bytes = new byte[0x2400]; Array.Copy(Fixture(), bytes, 1024);
            BitConverter.GetBytes(0x180000000UL).CopyTo(bytes, 0x98 + 24);
            Put(bytes, 0x98 + 16, 0xBD040); Put(bytes, 0x98 + 56, 0xC0000);
            Put(bytes, 0x188 + 12, 0xBCFA0); Put(bytes, 0x188 + 8, 0x2000); Put(bytes, 0x188 + 16, 0x2000);
            new byte[] { 0x3C, 0x01, 0x75, 0xB3 }.CopyTo(bytes, 0x343);
            new byte[] { 0xE8, 0xF8, 0x11, 0, 0, 0x85, 0xC0, 0x0F, 0x88, 0x80, 0, 0, 0 }.CopyTo(bytes, 0x373);
            new byte[] { 0x32, 0xC0, 0xE9, 0xF3, 0xFE, 0xFF, 0xFF }.CopyTo(bytes, 0x400);
            new byte[] { 0x0F, 0xB6, 0xC0, 0x48, 0x83, 0xC4, 0x40, 0x5B, 0xC3 }.CopyTo(bytes, 0x2FA);
            return bytes;
        }
    }
}
