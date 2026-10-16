using System;
using System.Globalization;
using System.IO;

namespace ScientificSecurity
{
    public sealed partial class KernelImage
    {
        internal const uint WorkerEntryRva = 0x24D20, GenerationResultRva = 0x258C9, FailureFunnelRva = 0x25A1A;
        static readonly uint[] activationRvas = { 0x24BAD, 0x24BB4, 0x24BB9, 0x24BBB, 0x24BBD,
            0x24BC9, 0x24BCF, 0x24BD5, 0x24BDC, 0x24BE1, WorkerEntryRva, 0x25A16, 0x25A18,
            FailureFunnelRva, 0x25A1C, 0x25A21, 0x25A27, 0x25861, 0x25868, 0x2586D, 0x25871, 0x25875,
            0x258C4, GenerationResultRva, 0x258CB, 0x258CD };
        static readonly string[] activationBytes = { "48FF152C6C0600", "0F1F440000", "8BD8", "85C0", "785D",
            "41B9F8010000", "41B81E000110", "48FF15E4670600", "0F1F440000", "8BD8",
            "488BC4488958104889701848897820", "85DB", "790D", "8BCB", "E8AF90FEFF", "48834C2440FF", "488B45F0",
            "48FF1528370600", "0F1F440000", "48894590", "4883F8FF", "7533",
            "E823040000", "8BD8", "85C0", "0F8819010000" };
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
            byte[] bytes = new byte[0x4200]; Array.Copy(ActivationWorkerFixture(), bytes, 2048);
            Put(bytes, 0x188 + 12, 0x22000); Put(bytes, 0x188 + 8, 0x4000); Put(bytes, 0x188 + 16, 0x4000);
            Put(bytes, 0x98 + 16, 0x22000); Put(bytes, 0x98 + 56, 0x27000);
            for (int index = 0; index < activationRvas.Length; index++) {
                int raw = 0x200 + (int)activationRvas[index] - 0x22000;
                for (int item = 0; item < activationBytes[index].Length / 2; item++)
                    bytes[raw + item] = Byte.Parse(activationBytes[index].Substring(item * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }
            return bytes;
        }
        static void RequireActivationBoundaryIdentity(string identity)
        {
            Need(identity == "phase=image-identity module=kernel32.dll sha256=347f1ac1b7dbec710cf06fb3f67d131bceebbc19076bc77daacd31cfe452b496 pe_timestamp=4227614027 image_size=823296 file_size=836208");
        }
        void ActivationBoundaryBytes()
        {
            Need(Name == "kernel32.dll");
            for (int index = 0; index < activationRvas.Length; index++) {
                uint rva = activationRvas[index], size = (uint)activationBytes[index].Length / 2;
                Need(FullExecutable(rva, size)); int raw = Map(rva, size);
                for (int item = 0; item < size; item++)
                    Need(data[raw + item] == Byte.Parse(activationBytes[index].Substring(item * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
            }
            Need(checked(0x24BB4L + BitConverter.ToInt32(data, Map(0x24BB0, 4))) == 0x8B7E0);
            Need(checked(0x24BDCL + BitConverter.ToInt32(data, Map(0x24BD8, 4))) == 0x8B3C0);
            Need(checked(0x24BBFL + unchecked((sbyte)data[Map(0x24BBE, 1)])) == 0x24C1C);
            Need(checked(0x25A1AL + unchecked((sbyte)data[Map(0x25A19, 1)])) == 0x25A27);
            Need(checked(0x25A21L + BitConverter.ToInt32(data, Map(0x25A1D, 4))) == 0xEAD0);
            Need(checked(0x25868L + BitConverter.ToInt32(data, Map(0x25864, 4))) == 0x88F90);
            Need(checked(0x25877L + unchecked((sbyte)data[Map(0x25876, 1)])) == 0x258AA);
            Need(checked(0x258C9L + BitConverter.ToInt32(data, Map(0x258C5, 4))) == 0x25CEC);
            Need(FullExecutable(0x25CEC, 1)); Map(0x25CEC, 1);
            Need(checked(0x258D3L + BitConverter.ToInt32(data, Map(0x258CF, 4))) == 0x259EC);
        }
        internal void RequireActivationBoundaryProfile()
        {
            RequireActivationBoundaryIdentity(ActivationWorkerIdentity());
            Need(ActivationWorkerSlice().Rva == 0x24D20); ActivationBoundaryBytes();
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
