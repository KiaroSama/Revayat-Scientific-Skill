using System;
using System.Globalization;
using System.IO;

namespace ScientificSecurity
{
    public sealed partial class KernelImage
    {
        internal const uint WorkerEntryRva = 0x24D20, RegistryResultRva = 0x277A8, FailureFunnelRva = 0x25A1A;
        static readonly uint[] activationRvas = { 0x24BAD, 0x24BB4, 0x24BB9, 0x24BBB, 0x24BBD,
            0x24BC9, 0x24BCF, 0x24BD5, 0x24BDC, 0x24BE1, WorkerEntryRva, 0x25A16, 0x25A18,
            FailureFunnelRva, 0x25A1C, 0x25A21, 0x25A27, 0x25861, 0x25868, 0x2586D, 0x25871, 0x25875,
            0x258C4, 0x258C9, 0x258CB, 0x258CD, 0x2623A, 0x26257, 0x2625E, 0x26263, 0x26265, 0x26267,
            0x272A6, 0x272AD, 0x272B2, 0x272B6, 0x272BB, 0x272BD, 0x272BF,
            0x26991, 0x269A7, 0x269AE, 0x269B3, 0x269B5, 0x269B7, 0x269B9,
            0x26B3A, 0x26B65, 0x26B6A, 0x26B6E, 0x26B70, 0x26B72, 0x26B74,
            0x26BAC, 0x26BB3, 0x26BB8, 0x26BBA, 0x26BBC, 0x26BBE,
            0x27787, 0x2779C, 0x277A3, RegistryResultRva, 0x277AA, 0x277AC };
        static readonly string[] activationBytes = { "48FF152C6C0600", "0F1F440000", "8BD8", "85C0", "785D",
            "41B9F8010000", "41B81E000110", "48FF15E4670600", "0F1F440000", "8BD8",
            "488BC4488958104889701848897820", "85DB", "790D", "8BCB", "E8AF90FEFF", "48834C2440FF", "488B45F0",
            "48FF1528370600", "0F1F440000", "48894590", "4883F8FF", "7533",
            "E823040000", "8BD8", "85C0", "0F8819010000",
            "BA89001200", "48FF15B2500600", "0F1F440000", "8BD8", "85C0", "0F88690B0000",
            "48FF156B450600", "0F1F440000", "8B542448", "3D230000C0", "7424", "85C0", "790E",
            "BAA9001200", "48FF1562490600", "0F1F440000", "33D2", "8BD8", "85C0", "0F8989000000",
            "7536", "0F1F440000", "488B4DB0", "33D2", "8BD8", "85DB", "0F88EA000000",
            "48FF156D440600", "0F1F440000", "33C9", "8BD8", "85C0", "782B",
            "BA19000200", "48FF15753A0600", "0F1F440000", "8BD8", "85C0", "0F8896000000" };
        internal static void CheckActivationBoundaryValidation()
        {
            byte[] bytes = ActivationBoundaryFixture(); var image = FromActivationWorker(bytes);
            image.ActivationBoundaryBytes();
            Need(image.Address(WorkerEntryRva) != image.Address(FailureFunnelRva));
            foreach (Action<byte[]> change in new Action<byte[]>[] {
                b => b[0x2F20] ^= 1, b => b[0x3C16] ^= 1, b => b[0x3C19] ^= 1, b => b[0x3C1A] ^= 1,
                b => b[0x3C1D] ^= 1, b => b[0x3C21] ^= 1, b => b[0x3C27] ^= 1,
                b => b[0x3A61] ^= 1, b => b[0x3A64] ^= 1, b => b[0x3A68] ^= 1,
                b => b[0x3A6D] ^= 1, b => b[0x3A71] ^= 1, b => b[0x3A76] ^= 1,
                b => b[0x3AC4] ^= 1, b => b[0x3AC5] ^= 1, b => b[0x3AC9] ^= 1,
                b => b[0x3ACB] ^= 1, b => b[0x3ACF] ^= 1,
                b => b[0x443A] ^= 1, b => b[0x4457] ^= 1, b => b[0x445A] ^= 1,
                b => b[0x445E] ^= 1, b => b[0x4463] ^= 1, b => b[0x4465] ^= 1, b => b[0x4469] ^= 1,
                b => Put(b, 0x188 + 8, 0x4264), b => Put(b, 0x188 + 16, 0x4264),
                b => b[0x54A6] ^= 1, b => b[0x54A9] ^= 1, b => b[0x54AD] ^= 1, b => b[0x54B2] ^= 1,
                b => b[0x54B6] ^= 1, b => b[0x54BC] ^= 1, b => b[0x54BD] ^= 1, b => b[0x54C0] ^= 1,
                b => Put(b, 0x188 + 8, 0x52B4), b => Put(b, 0x188 + 16, 0x52B4),
                b => b[0x4B91] ^= 1, b => b[0x4BA7] ^= 1, b => b[0x4BAA] ^= 1, b => b[0x4BAE] ^= 1,
                b => b[0x4BB3] ^= 1, b => b[0x4BB5] ^= 1, b => b[0x4BB7] ^= 1, b => b[0x4BBB] ^= 1,
                b => Put(b, 0x188 + 8, 0x49B4), b => Put(b, 0x188 + 16, 0x49B4),
                b => b[0x4D3A] ^= 1, b => b[0x4D3B] ^= 1, b => b[0x4D65] ^= 1, b => b[0x4D6A] ^= 1,
                b => b[0x4D6E] ^= 1, b => b[0x4D70] ^= 1, b => b[0x4D72] ^= 1, b => b[0x4D76] ^= 1,
                b => b[0x4DAC] ^= 1, b => b[0x4DAF] ^= 1, b => b[0x4DB3] ^= 1, b => b[0x4DB8] ^= 1,
                b => b[0x4DBA] ^= 1, b => b[0x4DBC] ^= 1, b => b[0x4DBF] ^= 1,
                b => Put(b, 0x188 + 8, 0x4B73), b => Put(b, 0x188 + 16, 0x4B73),
                b => Put(b, 0x188 + 8, 0x4BB9), b => Put(b, 0x188 + 16, 0x4BB9),
                b => b[0x5987] ^= 1, b => b[0x599C] ^= 1, b => b[0x599F] ^= 1, b => b[0x59A3] ^= 1,
                b => b[0x59A8] ^= 1, b => b[0x59AA] ^= 1, b => b[0x59AE] ^= 1,
                b => Put(b, 0x188 + 8, 0x57A9), b => Put(b, 0x188 + 16, 0x57A9),
                b => Put(b, 0x188 + 8, 0x386F), b => Put(b, 0x188 + 16, 0x386F),
                b => Put(b, 0x188 + 8, 0x38CA), b => Put(b, 0x188 + 16, 0x38CA),
                b => Put(b, 0x188 + 8, 0x3CEC), b => Put(b, 0x188 + 16, 0x3CEC),
                b => Put(b, 0x188 + 8, 0x3A1B), b => Put(b, 0x188 + 16, 0x3A1B)
            }) {
                byte[] bad = (byte[])bytes.Clone(); change(bad); bool refused = false;
                try { FromActivationWorker(bad).ActivationBoundaryBytes(); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            foreach (Action<byte[]> change in new Action<byte[]>[] {
                b => b[0x2DAD] ^= 1, b => b[0x2DB9] ^= 1, b => b[0x2DE1] ^= 1,
                b => b[0x2DCF] ^= 1, b => b[0x2DBD] ^= 1,
                b => Put(b, 0x188 + 8, 0x1BE2), b => Put(b, 0x188 + 16, 0x1BE2),
                b => Put(b, 0x188 + 36, 0x40000040)
            }) {
                byte[] bad = (byte[])bytes.Clone(); change(bad); bool refused = false;
                try { FromActivationWorker(bad).ActivationBoundaryBytes(); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            const string identity = "phase=image-identity module=kernel32.dll sha256=347f1ac1b7dbec710cf06fb3f67d131bceebbc19076bc77daacd31cfe452b496 pe_timestamp=4227614027 image_size=823296 file_size=836208";
            RequireActivationBoundaryIdentity(identity);
            foreach (string bad in new [] { null, "", identity + " ", identity.Replace("347f", "047f"),
                identity.Replace("836208", "836207"), identity.Replace("4227614027", "4227614026") }) {
                bool refused = false;
                try { RequireActivationBoundaryIdentity(bad); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            bool syntheticRefused = false;
            try { image.RequireActivationBoundaryProfile(); } catch (InvalidOperationException) { syntheticRefused = true; }
            Need(syntheticRefused);
        }
        static byte[] ActivationBoundaryFixture()
        {
            byte[] bytes = new byte[0x5A00]; Array.Copy(ActivationWorkerFixture(), bytes, 2048);
            Put(bytes, 0x188 + 12, 0x22000); Put(bytes, 0x188 + 8, 0x5800); Put(bytes, 0x188 + 16, 0x5800);
            Put(bytes, 0x98 + 16, 0x22000); Put(bytes, 0x98 + 56, 0x28000);
            for (int index = 0; index < activationRvas.Length; index++) {
                int raw = 0x200 + (int)activationRvas[index] - 0x22000;
                for (int item = 0; item < activationBytes[index].Length / 2; item++)
                    bytes[raw + item] = Byte.Parse(activationBytes[index].Substring(item * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }
            return bytes;
        }
        static void RequireActivationBoundaryIdentity(string identity) { SelectActivation(identity); }
        void ActivationBoundaryBytes() { ActivationBoundaryBytes(ActivationProfiles.Original); }
        void ActivationBoundaryBytes(ActivationProfile profile)
        {
            Need(Name == "kernel32.dll");
            RequireActivationCode(profile.Code, profile.Bytes);
            int[] records = { 0,7,4,12,14,17,21,22,25,27,31,32,36,38,40,45,46,52,53,58,60,64 };
            int[] offsets = { 3,3,1,1,1,3,1,1,2,3,2,3,1,1,3,2,1,2,3,1,3,2 };
            for (int index = 0; index < records.Length; index++) {
                int record = records[index], offset = offsets[index];
                uint rva = profile.Code[record], size = (uint)profile.Bytes[record].Length / 2;
                Need(size - offset == 1 || size - offset == 4);
                long displacement = size - offset == 1 ? unchecked((sbyte)data[Map(rva + (uint)offset, 1)]) :
                    BitConverter.ToInt32(data, Map(rva + (uint)offset, 4));
                Need(checked((long)rva + size + displacement) == profile.Edges[index]);
            }
            Need(FullExecutable(profile.ExecutableTarget, 1)); Map(profile.ExecutableTarget, 1);
        }
        void RequireActivationCode(uint[] rvas, string[] bytes)
        {
            Need(rvas.Length == bytes.Length);
            for (int index = 0; index < rvas.Length; index++) {
                uint rva = rvas[index], size = (uint)bytes[index].Length / 2;
                Need(FullExecutable(rva, size)); int raw = Map(rva, size);
                for (int item = 0; item < size; item++)
                    Need(data[raw + item] == Byte.Parse(bytes[index].Substring(item * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
            }
        }
        internal void RequireActivationBoundaryProfile()
        {
            var profile = SelectActivation(ActivationWorkerIdentity());
            Need(ActivationWorkerSlice().Rva == profile.Worker); ActivationBoundaryBytes(profile);
        }
        internal static KernelImage FromActivationSystemLoad(IntPtr file, IntPtr imageBase)
        {
            string path = EventPath(file);
            if (path == null || !String.Equals(Path.GetFileName(path), "kernel32.dll", StringComparison.OrdinalIgnoreCase)) return null;
            Need(String.Equals(path, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "kernel32.dll"), StringComparison.OrdinalIgnoreCase));
            var image = ReadEventImage(file, imageBase, "kernel32.dll"); image.RequireActivationBoundaryProfile();
            StaticKernelInspection.BindActivationLoad(image); return image;
        }
        internal static KernelImage FromActivationCreation(IntPtr file, IntPtr imageBase, string expectedPath, string digest)
        {
            string path = EventPath(file);
            Need(path != null && Path.GetFileName(expectedPath) == "startup-activation.exe" &&
                String.Equals(path, expectedPath, StringComparison.OrdinalIgnoreCase));
            var image = ReadEventImage(file, imageBase, "fixed-child-activation");
            Need(Hash(image.data) == digest); image.ChildActivation();
            Need(image.FullExecutable(image.Entry, 1)); return image;
        }
    }
}
