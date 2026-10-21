using System;
using System.Globalization;

namespace ScientificSecurity
{
    public sealed partial class KernelImage
    {
        const string OriginalObservationIdentity = "phase=image-identity module=kernelbase.dll sha256=f4acdac5f1dc54b20c84a51ad0f507f421f5d1170e276a5a75d4e7dcf88750e2 pdb_guid=0b01ed22-aa49-026d-b0b3-95e011af2a5e pdb_age=1 pdb_name=kernelbase.pdb pe_timestamp=2900858579 image_size=4120576 file_size=4129456";
        const string ServicedObservationIdentity = "phase=image-identity module=kernelbase.dll sha256=96c0459f0d73d728e5c13a10d83d840f56913ef7281d17370a5e1eb197faa450 pdb_guid=cabdac12-ca43-8c8b-4dc4-b60b7499c804 pdb_age=1 pdb_name=kernelbase.pdb pe_timestamp=1038034819 image_size=4116480 file_size=4171392";
        sealed class ObservationProfile
        {
            internal readonly string Identity;
            internal readonly uint Entry, Site, Call, Checkpoint, ImageSize;
            internal readonly Section DataSection;
            internal readonly uint[] Rvas;
            internal ObservationProfile(string identity, uint entry, uint site, uint call, uint checkpoint, uint imageSize, Section section, uint[] rvas)
            { Identity = identity; Entry = entry; Site = site; Call = call; Checkpoint = checkpoint; ImageSize = imageSize; DataSection = section; Rvas = (uint[])rvas.Clone(); }
        }
        static readonly ObservationProfile originalObservation = new ObservationProfile(OriginalObservationIdentity, 0xBD1A0, 0xBD243, 0xBE470, 0x39B8F8, 0x3EE000,
            new Section { rva = 0x395000, size = 0xA368, raw = 0x395000, rawSize = 0x2000, flags = 0xC0000040 },
            new uint[] { 0xBD273, 0xBD278, 0xBD27A, 0xBD300, 0xBD302, 0xBD1FA, 0xBD1FD, 0xBD201, 0xBD202, 0xBD243, 0xBD245 });
        static readonly ObservationProfile servicedObservation = new ObservationProfile(ServicedObservationIdentity, 0xBD040, 0xBD0E3, 0xBE310, 0x39A7E8, 0x3ED000,
            new Section { rva = 0x394000, size = 0xA338, raw = 0x394000, rawSize = 0x2000, flags = 0xC0000040 },
            new uint[] { 0xBD113, 0xBD118, 0xBD11A, 0xBD1A0, 0xBD1A2, 0xBD09A, 0xBD09D, 0xBD0A1, 0xBD0A2, 0xBD0E3, 0xBD0E5 });
        static readonly string[] observationBytes = { "E8F8110000", "85C0", "0F8880000000", "32C0", "E9F3FEFFFF", "0FB6C0", "4883C440", "5B", "C3", "3C01", "75B3" };
        static ObservationProfile SelectObservation(string identity)
        {
            if (identity == OriginalObservationIdentity) return originalObservation;
            if (identity == ServicedObservationIdentity) return servicedObservation;
            throw new InvalidOperationException("fixed KernelBase identity is unsupported");
        }
        internal uint RequireObservationProfile()
        { return ObservationBytes(SelectObservation(KernelBaseIdentity())); }
        static string[] ObservationText(ObservationProfile profile)
        {
            return new[] { "call operands=rva:0x" + profile.Call.ToString("X8"), "test operands=eax,eax", "js operands=rva:0x" + profile.Rvas[3].ToString("X8"),
                "xor operands=al,al", "jmp operands=rva:0x" + profile.Rvas[5].ToString("X8"), "movzx operands=eax,al", "add operands=withheld", "pop operands=rbx", "ret operands=none",
                "cmp operands=al,1", "jne operands=rva:0x" + profile.Rvas[5].ToString("X8") };
        }
        static void RequireObservationRecords(StaticView view, ObservationProfile profile)
        {
            Need(view != null && view.Text != null);
            string[] lines = view.Text.Split('\n'), text = ObservationText(profile);
            for (int index = 0; index < profile.Rvas.Length; index++) {
                string expected = "rva=0x" + profile.Rvas[index].ToString("X8", CultureInfo.InvariantCulture) +
                    " bytes=" + observationBytes[index] + " mnemonic=" + text[index];
                int matches = 0; foreach (string line in lines) if (line == expected) matches++;
                Need(matches == 1);
            }
        }
        internal void RequireObservationStatic(StaticView view)
        {
            ObservationProfile profile = null;
            QualifyObservation(() => profile = SelectObservation(KernelBaseIdentity()), () => ObservationBytes(profile), () => RequireObservationRecords(view, profile));
        }
        static void QualifyObservation(Action identity, Action bytes, Action records)
        {
            string phase = "identity";
            try { identity(); phase = "bytes"; bytes(); phase = "records"; records(); }
            catch (InvalidOperationException failure) { throw new InvalidOperationException("fixed KernelBase observation profile refused check=" + phase, failure); }
        }
        bool FullExecutable(uint rva, uint length)
        {
            int matches = 0;
            foreach (var section in sections)
                if ((section.flags & 0x20000000) != 0 && rva >= section.rva &&
                    (ulong)rva + length <= (ulong)section.rva + Math.Min(section.size, section.rawSize)) matches++;
            return length != 0 && (ulong)rva + length <= imageSize && matches == 1;
        }
        uint ObservationBytes(ObservationProfile profile)
        {
            Need(profile != null && Name == "kernelbase.dll" && Entry == profile.Entry);
            uint[] rvas = profile.Rvas; var slice = EntrySlice(); ulong end = (ulong)Entry + slice.Length;
            for (int index = 0; index < rvas.Length; index++) {
                uint rva = rvas[index], length = (uint)observationBytes[index].Length / 2;
                Need(rva >= Entry && (ulong)rva + length <= end && FullExecutable(rva, length));
                for (int prior = 0; prior < index; prior++) {
                    uint old = rvas[prior], oldLength = (uint)observationBytes[prior].Length / 2;
                    Need((ulong)rva + length <= old || (ulong)old + oldLength <= rva);
                }
                int raw = Map(rva, length);
                for (int item = 0; item < length; item++) Need(data[raw + item] == Byte.Parse(observationBytes[index].Substring(item * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
            }
            long call = checked((long)rvas[0] + 5 + BitConverter.ToInt32(data, Map(rvas[0] + 1, 4)));
            long sign = checked((long)rvas[2] + 6 + BitConverter.ToInt32(data, Map(rvas[2] + 2, 4)));
            long tail = checked((long)rvas[4] + 5 + BitConverter.ToInt32(data, Map(rvas[4] + 1, 4)));
            long earlier = checked((long)rvas[10] + 2 + unchecked((sbyte)data[Map(rvas[10] + 1, 1)]));
            Need(call == profile.Call && sign == rvas[3] && tail == rvas[5] && earlier == rvas[5] && FullExecutable((uint)call, 1));
            Need(FullExecutable(profile.Site, 2)); return profile.Site;
        }
        static void CheckObservationValidation()
        {
            Need(SelectObservation(OriginalObservationIdentity) == originalObservation && SelectObservation(ServicedObservationIdentity) == servicedObservation);
            foreach (var profile in new[] { originalObservation, servicedObservation }) {
                string identity = profile.Identity;
                foreach (string changed in new[] { null, "", identity + " ", identity.Replace("pdb_age=1", "pdb_age=2"),
                    identity.Replace("kernelbase.pdb", "other.pdb"), identity.Replace("module=kernelbase.dll", "module=kernel32.dll"),
                    identity.Replace("pe_timestamp=", "pe_timestamp=0"), identity.Replace("file_size=", "file_size=0"),
                    identity.Replace("image_size=", "image_size=0"), identity.Replace("pdb_guid=", "pdb_guid=0"),
                    identity.Replace(identity.Substring(identity.IndexOf("sha256=") + 7, 64), profile == originalObservation ? "96c0459f0d73d728e5c13a10d83d840f56913ef7281d17370a5e1eb197faa450" : "f4acdac5f1dc54b20c84a51ad0f507f421f5d1170e276a5a75d4e7dcf88750e2") }) {
                    bool refused = false; try { SelectObservation(changed); } catch (InvalidOperationException) { refused = true; } Need(refused);
                }
                byte[] bytes = ObservationFixture(profile); var image = FromStatic(bytes);
                Need(image.ObservationBytes(profile) == profile.Site);
                var other = profile == originalObservation ? servicedObservation : originalObservation;
                bool cross = false; try { image.ObservationBytes(other); } catch (InvalidOperationException) { cross = true; } Need(cross);
                // Literal fixture disassembly is independent of the production record formatter.
                string listing = profile == servicedObservation ?
                    "  00000001800BD09A: 0F B6 C0     movzx eax,al\n  00000001800BD09D: 48 83 C4 40     add rsp,40h\n  00000001800BD0A1: 5B     pop rbx\n  00000001800BD0A2: C3     ret\n  00000001800BD0E3: 3C 01     cmp al,1\n  00000001800BD0E5: 75 B3     jne 00000001800BD09A\n  00000001800BD113: E8 F8 11 00 00     call 00000001800BE310\n  00000001800BD118: 85 C0     test eax,eax\n  00000001800BD11A: 0F 88 80 00 00 00     js 00000001800BD1A0\n  00000001800BD1A0: 32 C0     xor al,al\n  00000001800BD1A2: E9 F3 FE FF FF     jmp 00000001800BD09A\n" :
                    "  00000001800BD1FA: 0F B6 C0     movzx eax,al\n  00000001800BD1FD: 48 83 C4 40     add rsp,40h\n  00000001800BD201: 5B     pop rbx\n  00000001800BD202: C3     ret\n  00000001800BD243: 3C 01     cmp al,1\n  00000001800BD245: 75 B3     jne 00000001800BD1FA\n  00000001800BD273: E8 F8 11 00 00     call 00000001800BE470\n  00000001800BD278: 85 C0     test eax,eax\n  00000001800BD27A: 0F 88 80 00 00 00     js 00000001800BD300\n  00000001800BD300: 32 C0     xor al,al\n  00000001800BD302: E9 F3 FE FF FF     jmp 00000001800BD1FA\n";
                var view = image.QualifyStatic(listing); RequireObservationRecords(view, profile);
                cross = false; try { RequireObservationRecords(view, other); } catch (InvalidOperationException) { cross = true; } Need(cross);
                string site = "00000001800" + profile.Site.ToString("X5"), jump = "00000001800" + profile.Rvas[5].ToString("X5");
                foreach (string changed in new[] { listing.Replace("  " + site + ": 3C 01     cmp al,1\n", ""),
                    listing.Replace("  00000001800" + profile.Rvas[10].ToString("X5") + ": 75 B3     jne " + jump + "\n", ""),
                    listing.Replace("  00000001800" + profile.Rvas[1].ToString("X5") + ": 85 C0     test eax,eax\n", ""),
                    listing.Replace("test eax,eax", "bogus eax,eax"), listing.Replace("movzx eax,al", "movzx eax,0"),
                    listing.Replace("cmp al,1", "cmp eax,1"), listing.Replace("75 B3     jne", "75 B3     je"),
                    listing.Replace("cmp al,1\n", "cmp al,1\n       00\n"), listing.Replace("jne " + jump + "\n", "jne " + jump + "\n       00\n"),
                    listing.Replace(site, "00000001800" + (profile.Site + 1).ToString("X5")), listing + listing,
                    listing.Replace("85 C0     test eax,eax\n", "85 C0     test eax,eax\n       00\n"),
                    listing.Replace("jne " + jump, "jne 00000001800" + (profile.Rvas[5] + 1).ToString("X5")) }) {
                    bool refused = false; try { RequireObservationRecords(image.QualifyStatic(changed), profile); } catch (InvalidOperationException) { refused = true; } Need(refused);
                }
                for (int index = 0; index < profile.Rvas.Length; index++) {
                    byte[] bad = (byte[])bytes.Clone(); bad[image.Map(profile.Rvas[index], 1)] ^= 1;
                    bool refused = false; try { FromStatic(bad).ObservationBytes(profile); } catch (InvalidOperationException) { refused = true; } Need(refused);
                }
                foreach (Action<byte[]> change in new Action<byte[]>[] {
                    b => b[0x374] = 0, b => b[0x37C] = 0, b => b[0x403] = 0, b => b[0x346] = 0xB4,
                    b => Put(b, 0x98 + 16, profile.Entry + 1), b => Put(b, 0x98 + 16, other.Entry),
                    b => Put(b, 0x188 + 8, 0x144), b => Put(b, 0x188 + 16, 0x144),
                    b => Put(b, 0x188 + 8, 0x179), b => Put(b, 0x188 + 16, 0x179),
                    b => Put(b, 0x188 + 36, 0x40000040), b => Put(b, 0x98 + 112 + 14 * 8, 1), b => Put(b, 0x188 + 8, 0x1200)
                }) {
                    byte[] bad = (byte[])bytes.Clone(); change(bad); bool refused = false;
                    try { FromStatic(bad).ObservationBytes(profile); } catch (InvalidOperationException) { refused = true; } Need(refused);
                }
                bool fake = false; try { image.RequireObservationProfile(); } catch (InvalidOperationException) { fake = true; } Need(fake);
            }
            uint firstRaw = 0x101, secondRaw = 1; Need(firstRaw != secondRaw && (firstRaw & 0xFF) == 1 && (secondRaw & 0xFF) == 1);
            foreach (string failedPhase in new[] { "identity", "bytes", "records" }) {
                string order = ""; var original = new InvalidOperationException("fixed qualification fixture");
                Action<string> check = phase => { order += phase + ","; if (phase == failedPhase) throw original; };
                InvalidOperationException observed = null;
                try { QualifyObservation(() => check("identity"), () => check("bytes"), () => check("records")); } catch (InvalidOperationException failure) { observed = failure; }
                Need(observed != null && observed.Message == "fixed KernelBase observation profile refused check=" + failedPhase && Object.ReferenceEquals(observed.InnerException, original));
                Need(order == (failedPhase == "identity" ? "identity," : failedPhase == "bytes" ? "identity,bytes," : "identity,bytes,records,"));
            }
            string completed = ""; QualifyObservation(() => completed += "identity,", () => completed += "bytes,", () => completed += "records,"); Need(completed == "identity,bytes,records,");
        }
        static byte[] ObservationFixture() { return ObservationFixture(servicedObservation); }
        static byte[] ObservationFixture(ObservationProfile profile)
        {
            byte[] bytes = new byte[0x2400]; Array.Copy(Fixture(), bytes, 1024);
            BitConverter.GetBytes(0x180000000UL).CopyTo(bytes, 0x98 + 24);
            Put(bytes, 0x98 + 16, profile.Entry); Put(bytes, 0x98 + 56, 0xC0000);
            Put(bytes, 0x188 + 12, profile == originalObservation ? 0xBD100U : 0xBCFA0U); Put(bytes, 0x188 + 8, 0x2000); Put(bytes, 0x188 + 16, 0x2000);
            new byte[] { 0x3C, 1, 0x75, 0xB3 }.CopyTo(bytes, 0x343);
            new byte[] { 0xE8, 0xF8, 0x11, 0, 0, 0x85, 0xC0, 0x0F, 0x88, 0x80, 0, 0, 0 }.CopyTo(bytes, 0x373);
            new byte[] { 0x32, 0xC0, 0xE9, 0xF3, 0xFE, 0xFF, 0xFF }.CopyTo(bytes, 0x400);
            new byte[] { 0x0F, 0xB6, 0xC0, 0x48, 0x83, 0xC4, 0x40, 0x5B, 0xC3 }.CopyTo(bytes, 0x2FA);
            return bytes;
        }
    }
}
