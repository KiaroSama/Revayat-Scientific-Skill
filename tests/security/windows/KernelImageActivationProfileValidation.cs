using System;
using System.Globalization;
using System.Text;

namespace ScientificSecurity
{
    public sealed partial class KernelImage
    {
        public static void CheckActivationProfiles()
        {
            Need(SelectActivation(OriginalActivationIdentity) == ActivationProfiles.Original &&
                SelectActivation(ServicedActivationIdentity) == ActivationProfiles.Serviced);
            foreach (var profile in new[] { ActivationProfiles.Original, ActivationProfiles.Serviced }) {
                string identity = profile.Identity;
                string alternate = profile == ActivationProfiles.Original ? ServicedActivationIdentity : OriginalActivationIdentity;
                foreach (string bad in new[] { null, "", identity + " ", identity.Replace("kernel32.dll", "kernelbase.dll"),
                    identity.Replace("sha256=", "sha256=0"), identity.Replace("pe_timestamp=", "pe_timestamp=0"),
                    identity.Replace("image_size=", "image_size=0"), identity.Replace("file_size=", "file_size=0"),
                    identity.Replace(identity.Substring(identity.IndexOf("sha256=") + 7, 64),
                        alternate.Substring(alternate.IndexOf("sha256=") + 7, 64))
                }) ModuleRefuse(() => SelectActivation(bad));
                byte[] bytes = ActivationProfileFixture(profile); var image = FromActivationWorker(bytes);
                image.ActivationBoundaryBytes(profile); image.CallbackBytes(profile);
                Need(image.ActivationWorkerSlice().Rva == profile.Worker);
                uint[] expectedSites = profile == ActivationProfiles.Original ?
                    new uint[] { 0x24D20,0x277A8,0x25A1A,0x25C1D,0x25C81 } : new uint[] { 0x240D0,0x26B58,0x24DCA,0x24FCD,0x25031 };
                for (int role = 0; role < expectedSites.Length; role++) Need(ActivationSite(profile, role) == expectedSites[role]);
                ModuleRefuse(() => ActivationSite(profile, 5));
                var other = profile == ActivationProfiles.Original ? ActivationProfiles.Serviced : ActivationProfiles.Original;
                ModuleRefuse(() => image.ActivationBoundaryBytes(other));
                ModuleRefuse(() => image.CallbackBytes(other));
                ModuleRefuse(() => image.RequireModuleCallbackProfile());
                ModuleRefuse(() => { uint unused = image.ActivationResourceSite; });
                foreach (var group in new[] { profile.Code, profile.Callback }) foreach (uint rva in group) {
                    byte[] bad = (byte[])bytes.Clone(); bad[image.Map(rva, 1)] ^= 1;
                    ModuleRefuse(() => { var changed = FromActivationWorker(bad); changed.ActivationBoundaryBytes(profile); changed.CallbackBytes(profile); });
                }
                foreach (var imports in profile.Imports) {
                    foreach (Action<byte[]> change in new Action<byte[]>[] {
                        b => b[image.Map(imports.Descriptor, 1)] ^= 1,
                        b => b[image.Map(imports.Lookup + imports.Count * 8, 1)] = 1,
                        b => b[image.Map(imports.Address, 1)] ^= 1,
                        b => b[image.Map(imports.Records[0], 1)] ^= 1,
                        b => b[image.Map(imports.Records[0] + 2, 1)] ^= 1
                    }) ModuleRefuse(() => { byte[] bad = (byte[])bytes.Clone(); change(bad); FromActivationWorker(bad).CallbackBytes(profile); });
                }
                foreach (Action<byte[]> change in new Action<byte[]>[] {
                    b => Put(b, 0x98 + 16, profile.Entry + 1), b => Put(b, 0x98 + 120, other.ImportDirectory),
                    b => b[image.Map(profile.NullDescriptor, 1)] = 1,
                    b => Put(b, 0x188 + 36, 0x40000040),
                    b => Put(b, 0x188 + 8, profile.Callback[63] - 0x22000 + 4),
                    b => Put(b, 0x188 + 16, profile.Callback[63] - 0x22000 + 4)
                }) ModuleRefuse(() => { byte[] bad = (byte[])bytes.Clone(); change(bad); FromActivationWorker(bad).CallbackBytes(profile); });
            }
            var serviced = ActivationProfiles.Serviced;
            Need(serviced.Worker == 0x240D0 && serviced.Code[62] == 0x26B58 && serviced.Code[13] == 0x24DCA &&
                serviced.Callback[39] == 0x24FCD && serviced.Callback[63] == 0x25031 && serviced.Edges[4] == 0xEAD0);
            Need(serviced.Bytes[14] == "E8FF9CFEFF" && serviced.CallbackBytes[38] == "48FF15A3600600" && serviced.CallbackBytes[62] == "48FF15CF580600");
        }
        static byte[] ActivationProfileFixture(ActivationProfile profile)
        {
            byte[] bytes = CallbackFixture(); Array.Clear(bytes, 0x200, 0xD000);
            Put(bytes, 0x98 + 16, profile.Entry);
            var image = FromActivationWorker(bytes);
            uint[][] groups = { profile.Code, profile.Callback }; string[][] encodings = { profile.Bytes, profile.CallbackBytes };
            for (int group = 0; group < groups.Length; group++) for (int index = 0; index < groups[group].Length; index++) {
                string text = encodings[group][index]; int raw = image.Map(groups[group][index], (uint)text.Length / 2);
                for (int item = 0; item < text.Length / 2; item++) bytes[raw + item] = Byte.Parse(text.Substring(item * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }
            Put(bytes, 0x98 + 120, profile.ImportDirectory); Put(bytes, 0x98 + 124, 0x834);
            Array.Clear(bytes, image.Map(profile.ImportDirectory, 0x834), 0x834);
            int owner = 0xC1000;
            foreach (var imports in profile.Imports) {
                int descriptor = image.Map(imports.Descriptor, 20);
                Put(bytes, descriptor, imports.Lookup); Put(bytes, descriptor + 12, (uint)owner); Put(bytes, descriptor + 16, imports.Address);
                Encoding.ASCII.GetBytes(imports.Owner + "\0").CopyTo(bytes, owner); owner += 128;
                for (uint index = 0; index <= imports.Count; index++) {
                    ulong record = index == imports.Count ? 0UL : 0xC0000UL;
                    BitConverter.GetBytes(record).CopyTo(bytes, image.Map(imports.Lookup + index * 8, 8));
                    BitConverter.GetBytes(record).CopyTo(bytes, image.Map(imports.Address + index * 8, 8));
                }
                for (int index = 0; index < imports.Indices.Length; index++) {
                    ulong record = imports.Records[index];
                    BitConverter.GetBytes(record).CopyTo(bytes, image.Map(imports.Lookup + imports.Indices[index] * 8, 8));
                    BitConverter.GetBytes(record).CopyTo(bytes, image.Map(imports.Address + imports.Indices[index] * 8, 8));
                    Put16(bytes, image.Map((uint)record, 2), imports.Hints[index]);
                    Encoding.ASCII.GetBytes(imports.Names[index] + "\0").CopyTo(bytes, image.Map((uint)record + 2, (uint)imports.Names[index].Length + 1));
                }
            }
            Put(bytes, 0x98 + 112, 0xC2000); Put(bytes, 0x98 + 116, 0x200);
            Array.Clear(bytes, 0xC2000, 0x200);
            Put(bytes, 0xC2010, 1); Put(bytes, 0xC2014, 1); Put(bytes, 0xC2018, 1);
            Put(bytes, 0xC201C, 0xC2040); Put(bytes, 0xC2020, 0xC2050); Put(bytes, 0xC2024, 0xC2058);
            Put(bytes, 0xC2040, profile.Worker); Put(bytes, 0xC2050, 0xC2080);
            Encoding.ASCII.GetBytes("CreateActCtxWWorker\0").CopyTo(bytes, 0xC2080);
            return bytes;
        }
    }
}
