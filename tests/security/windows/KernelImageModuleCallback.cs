using System;
using System.Globalization;
using System.IO;
using System.Text;

namespace ScientificSecurity
{
    public sealed partial class KernelImage
    {
        internal const uint ModuleCallbackResultRva = 0x25C81;
        static readonly uint[] callbackRvas = {
            0x2E2AE, 0x2E2B5, 0x2E2BC, 0x2E2C3, 0x2E2CA,
            0x25B90, 0x25B95, 0x25B9A, 0x25B9F, 0x25BA0, 0x25BA3, 0x25BAA,
            0x25BAC, 0x25BB3, 0x25BB7, 0x25BBA, 0x25BBD, 0x25BC0, 0x25BC3,
            0x25BC6, 0x25BCA, 0x25BCE, 0x25BD2, 0x25BD5, 0x25BD7, 0x25BDA,
            0x25BDF, 0x25BE1, 0x25BE3, 0x25BEC, 0x25BF0, 0x25BF2, 0x25BF7,
            0x25BFF, 0x25C05, 0x25C09, 0x25C0F, 0x25C12, 0x25C16, 0x25C1D,
            0x25C22, 0x25C24, 0x25C26, 0x25C2E, 0x25C32, 0x25C36, 0x25C3A,
            0x25C3D, 0x25C3E, 0x25C40, 0x25C45, 0x25C47, 0x25C4C, 0x25C4E,
            0x25C57, 0x25C5B, 0x25C5D, 0x25C5F, 0x25C63, 0x25C6A, 0x25C6E,
            0x25C76, 0x25C7A, ModuleCallbackResultRva, 0x25C86, 0x25C8A, 0x25C8C,
            0x25C8F, 0x25C91, 0x25C93, 0x25C9C, 0x25CA2 };
        static readonly string[] callbackBytes = {
            "4C8B0523C60500", "488D1574300300", "488D0DCD78FFFF", "48FF15A6D60500", "0F1F440000",
            "48895C2408", "4889742410", "48897C2420", "55", "488BEC", "4881EC80000000", "33C0",
            "C745C038000000", "48214520", "0F57C0", "8945F4", "498BD8", "488BF2", "488BF9",
            "0F1145C4", "0F1145D4", "0F1145E4", "4D85C0", "7470", "492100", "E8CD000000",
            "85C0", "745D", "65488B042560000000", "F6400302", "755C", "BA18000000", "C744243010000000",
            "488364242800", "4C8D4D20", "488364242000", "488BCF", "448D42EA", "48FF1523540600", "0F1F440000",
            "85C0", "7939", "4C8D9C2480000000", "498B5B10", "498B7318", "498B7B28", "498BE3",
            "5D", "C3", "B8BB0000C0", "EBDF", "B80D0000C0", "EBD8", "65488B042560000000",
            "F6400340", "7595", "EBE1", "488D4DC0", "C745C488000000", "488975C8", "48C745E002000000",
            "48897DF0", "48FF154F4C0600", "0F1F440000", "4883F8FF", "7407", "488903",
            "33C0", "EB93", "65488B042530000000", "8B8050120000", "EB82" };
        public static void CheckModuleCallbackProfileValidation()
        {
            CheckActivationProfiles();
            byte[] bytes = CallbackFixture(); var image = FromActivationWorker(bytes);
            image.ActivationBoundaryBytes(); image.CallbackBytes();
            Need(image.Entry == 0x2E1D0 && image.FullExecutable(ModuleCallbackResultRva, 5));
            for (int index = 0; index < callbackRvas.Length; index++) {
                byte[] bad = (byte[])bytes.Clone(); bad[image.Map(callbackRvas[index], 1)] ^= 1;
                ModuleRefuse(() => FromActivationWorker(bad).CallbackBytes());
            }
            foreach (Action<byte[]> change in new Action<byte[]>[] {
                b => Put(b, 0x98 + 16, 0x2E1D1), b => Put(b, 0x98 + 124, 0x820),
                b => Put(b, 0xB3CDC, 1), b => Put(b, 0xB34E4, 0xB5C90),
                b => Put(b, 0xB3B70, 0x8A890), b => b[0xC0100] ^= 1,
                b => b[0xB6A68] ^= 1, b => b[0xBC2FA] ^= 1,
                b => b[0xB6748] ^= 1, b => b[0x8A8D0] ^= 1,
                b => BitConverter.GetBytes(1UL).CopyTo(b, 0xB56B8),
                b => Put(b, 0x188 + 8, 0x3C84), b => Put(b, 0x188 + 36, 0x40000040)
            }) ModuleRefuse(() => { byte[] bad = (byte[])bytes.Clone(); change(bad); FromActivationWorker(bad).CallbackBytes(); });
            ModuleRefuse(() => image.RequireModuleCallbackProfile()); // Synthetic PE is never a real full-hash match.
            byte[] host = ModuleActivationFixtureImage(false, false);
            QualifyModuleCallbackHost(host, Hash(host));
            ModuleRefuse(() => QualifyModuleCallbackHost(host, "different"));
            ModuleRefuse(() => QualifyModuleCallbackHost(ModuleActivationFixtureImage(true, true), Hash(host)));
        }
        internal void RequireModuleCallbackProfile()
        {
            var profile = SelectActivation(ActivationWorkerIdentity());
            Need(ActivationWorkerSlice().Rva == profile.Worker);
            ActivationBoundaryBytes(profile); CallbackBytes(profile);
        }
        void CallbackBytes() { CallbackBytes(ActivationProfiles.Original); }
        void CallbackBytes(ActivationProfile profile)
        {
            Need(Name == "kernel32.dll" && Entry == profile.Entry);
            RequireActivationCode(profile.Callback, profile.CallbackBytes);
            int[] records32 = { 0,1,2,3,25,38,62 }, offsets32 = { 3,3,3,3,1,3,3 };
            for (int index = 0; index < records32.Length; index++) {
                int record = records32[index]; uint rva = profile.Callback[record];
                uint size = (uint)profile.CallbackBytes[record].Length / 2;
                Need(checked((long)rva + size + BitConverter.ToInt32(data, Map(rva + (uint)offsets32[index], 4))) == profile.CallbackEdges[index]);
            }
            int[] records8 = { 23,27,30,41,50,52,55,56,65,68,71 };
            for (int index = 0; index < records8.Length; index++) {
                int record = records8[index]; uint rva = profile.Callback[record];
                uint size = (uint)profile.CallbackBytes[record].Length / 2;
                Need(checked((long)rva + size + unchecked((sbyte)data[Map(rva + size - 1, 1)])) == profile.CallbackShortEdges[index]);
            }
            ulong optional = (ulong)U32(0x3C) + 24;
            Need(U32(optional + 120) == profile.ImportDirectory && U32(optional + 124) == 0x834);
            for (uint offset = 0; offset < 20; offset++) Need(data[Map(profile.NullDescriptor + offset, 1)] == 0);
            foreach (var imports in profile.Imports)
                CallbackImports(imports.Descriptor, imports.Owner, imports.Lookup, imports.Address, imports.Count,
                    imports.Indices, imports.Records, imports.Hints, imports.Names);
        }
        void CallbackImports(uint descriptor, string owner, uint lookup, uint address, uint count,
            uint[] indices, uint[] records, ushort[] hints, string[] names)
        {
            int raw = Map(descriptor, 20);
            Need(U32((ulong)raw) == lookup && U32((ulong)raw + 16) == address &&
                U32((ulong)raw + 4) == 0 && U32((ulong)raw + 8) == 0 && ActivationText(U32((ulong)raw + 12)) == owner);
            for (uint index = 0; index <= count; index++) {
                ulong symbol = BitConverter.ToUInt64(data, Map(lookup + index * 8, 8));
                Need(symbol == BitConverter.ToUInt64(data, Map(address + index * 8, 8)) && (index == count ? symbol == 0 : symbol != 0 && symbol <= UInt32.MaxValue));
            }
            for (int index = 0; index < indices.Length; index++) {
                Need(BitConverter.ToUInt64(data, Map(lookup + indices[index] * 8, 8)) == records[index]);
                Need(U16((ulong)Map(records[index], 2)) == hints[index] && ActivationText(records[index] + 2) == names[index]);
            }
        }
        static void QualifyModuleCallbackHost(byte[] bytes, string digest)
        {
            Need(Hash(bytes) == digest);
            var image = new KernelImage(bytes, 1, "fixed-module-activation");
            image.ModuleActivation(false, false); Need(image.FullExecutable(image.Entry, 1));
        }
        internal static KernelImage FromModuleCallbackCreation(IntPtr file, IntPtr imageBase, string expectedPath, string digest)
        {
            string path = EventPath(file);
            Need(path != null && Path.GetFileName(expectedPath) == "startup-module.exe" &&
                Path.GetFileName(Path.GetDirectoryName(expectedPath)) == "module-id2" &&
                String.Equals(path, expectedPath, StringComparison.OrdinalIgnoreCase));
            var image = ReadEventImage(file, imageBase, "fixed-module-activation");
            QualifyModuleCallbackHost(image.data, digest); return image;
        }
        static byte[] CallbackFixture()
        {
            byte[] b = new byte[0xC9000]; Array.Copy(ActivationBoundaryFixture(), b, 0x5A00);
            // Preserve the old code mapping; a separate file-backed data section holds imports.
            Put16(b, 0x86, 2); Put(b, 0x98 + 16, 0x2E1D0); Put(b, 0x98 + 56, 0xCA000);
            Put(b, 0x188 + 8, 0xD000); Put(b, 0x188 + 16, 0xD000);
            Put(b, 0x1B0 + 8, 0x49000); Put(b, 0x1B0 + 12, 0x80000);
            Put(b, 0x1B0 + 16, 0x49000); Put(b, 0x1B0 + 20, 0x80000); Put(b, 0x1B0 + 36, 0x40000040);
            var image = FromActivationWorker(b);
            for (int index = 0; index < callbackRvas.Length; index++) {
                int raw = image.Map(callbackRvas[index], (uint)callbackBytes[index].Length / 2);
                for (int item = 0; item < callbackBytes[index].Length / 2; item++)
                    b[raw + item] = Byte.Parse(callbackBytes[index].Substring(item * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }
            Put(b, 0x98 + 120, 0xB34BC); Put(b, 0x98 + 124, 0x834);
            uint[] descriptors = { 0xB34E4, 0xB3B60 }, lookups = { 0xB5C88, 0xB5660 }, addresses = { 0x8AEB0, 0x8A888 }, counts = { 365, 11 };
            string[] owners = { "ntdll.dll", "api-ms-win-core-sidebyside-l1-1-0.dll" };
            for (int row = 0; row < 2; row++) {
                Put(b, (int)descriptors[row], lookups[row]); Put(b, (int)descriptors[row] + 12, (uint)(0xC0100 + row * 128));
                Put(b, (int)descriptors[row] + 16, addresses[row]); Encoding.ASCII.GetBytes(owners[row] + "\0").CopyTo(b, 0xC0100 + row * 128);
                for (uint index = 0; index < counts[row]; index++) {
                    BitConverter.GetBytes(0xC0000UL).CopyTo(b, (int)(lookups[row] + index * 8));
                    BitConverter.GetBytes(0xC0000UL).CopyTo(b, (int)(addresses[row] + index * 8));
                }
            }
            uint[] ints = { 0xB6748, 0xB5E18, 0xB56A8, 0xB56B0 }, iats = { 0x8B970, 0x8B040, 0x8A8D0, 0x8A8D8 };
            uint[] records = { 0xB6A68, 0xB7616, 0xBC2F8, 0xBC2E8 }; ushort[] hints = { 0xA7, 0x9D, 2, 9 };
            string[] names = { "LdrSetDllManifestProber", "LdrResFindResourceDirectory", "CreateActCtxW", "ReleaseActCtx" };
            for (int index = 0; index < ints.Length; index++) {
                BitConverter.GetBytes((ulong)records[index]).CopyTo(b, (int)ints[index]);
                BitConverter.GetBytes((ulong)records[index]).CopyTo(b, (int)iats[index]);
                Put16(b, (int)records[index], hints[index]); Encoding.ASCII.GetBytes(names[index] + "\0").CopyTo(b, (int)records[index] + 2);
            }
            return b;
        }
    }
}
