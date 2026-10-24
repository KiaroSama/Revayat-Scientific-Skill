using System;
using System.Collections.Generic;
using System.Text;

namespace ScientificSecurity
{
    public sealed partial class KernelImage
    {
        internal static KernelImage FromCsrDispatchNtdll(IntPtr file, IntPtr imageBase)
        {
            string path = EventPath(file);
            if (path == null || !String.Equals(System.IO.Path.GetFileName(path), "ntdll.dll", StringComparison.OrdinalIgnoreCase)) return null;
            Need(String.Equals(path, System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "ntdll.dll"), StringComparison.OrdinalIgnoreCase));
            return ReadEventImage(file, imageBase, "ntdll.dll");
        }
        internal uint[] CsrDispatchSites()
        {
            RequireModuleCallbackProfile();
            return DispatchSites(SelectActivation(ActivationWorkerIdentity()));
        }
        uint[] DispatchSites(ActivationProfile profile)
        {
            ActivationBoundaryBytes(profile); CallbackBytes(profile);
            Need(profile.Code[8] == profile.Code[7] + 7);
            uint slot = profile.Edges[1];
            var imports = profile.Imports[0];
            Need(imports.Owner == "ntdll.dll" && slot == imports.Address + 162 * 8);
            ulong record = BitConverter.ToUInt64(data, Map(imports.Lookup + 162 * 8, 8));
            Need(record != 0 && record <= UInt32.MaxValue - 2 &&
                record == BitConverter.ToUInt64(data, Map(slot, 8)) &&
                ActivationText((uint)record + 2) == "CsrClientCallServer");
            return new [] { profile.Code[7], profile.Code[8], slot };
        }
        internal ulong CsrDispatchExport()
        {
            Need(Name == "ntdll.dll");
            ulong optional = (ulong)U32(0x3C) + 24;
            uint rva = U32(optional + 112), size = U32(optional + 116);
            Need(rva >= headers && size >= 40 && size <= 1048576);
            int table = Map(rva, size);
            uint functions = U32((ulong)table + 20), names = U32((ulong)table + 24);
            Need(functions > 0 && functions <= 4096 && names > 0 && names <= 4096);
            int addresses = Map(U32((ulong)table + 28), functions * 4);
            int pointers = Map(U32((ulong)table + 32), names * 4);
            int ordinals = Map(U32((ulong)table + 36), names * 2);
            var unique = new HashSet<string>(StringComparer.Ordinal);
            var ordinalUses = new Dictionary<ushort, int>(); ushort selectedOrdinal = 0; uint selected = 0; int matches = 0;
            for (uint index = 0; index < names; index++) {
                string name = ActivationExportName(U32((ulong)pointers + index * 4));
                Need(unique.Add(name));
                ushort ordinal = U16((ulong)ordinals + index * 2); Need(ordinal < functions);
                int uses; ordinalUses.TryGetValue(ordinal, out uses); ordinalUses[ordinal] = uses + 1;
                if (name != "CsrClientCallServer") continue;
                matches++; selectedOrdinal = ordinal; selected = U32((ulong)addresses + ordinal * 4UL);
            }
            Need(matches == 1 && ordinalUses[selectedOrdinal] == 1 && selected != 0 &&
                (selected < rva || (ulong)selected >= (ulong)rva + size) && FullExecutable(selected, 1));
            return Address(selected);
        }
        internal ulong CsrDispatchIatAddress(uint rva)
        {
            Need(Name == "kernel32.dll"); Map(rva, 8);
            int matches = 0;
            foreach (var section in sections)
                if ((section.flags & 0x40000000) != 0 && (section.flags & 0x20000000) == 0 &&
                    rva >= section.rva && (ulong)rva + 8 <= (ulong)section.rva + Math.Min(section.size, section.rawSize)) matches++;
            Need(matches == 1); return Base + rva;
        }
        public static void CheckCsrDispatchValidation()
        {
            CsrDispatchPair.CheckValidation();
            foreach (var profile in new [] { ActivationProfiles.Original, ActivationProfiles.Serviced }) {
                byte[] bytes = ActivationProfileFixture(profile); var image = FromActivationWorker(bytes);
                var imports = profile.Imports[0]; uint slot = imports.Address + 162 * 8;
                uint record = profile == ActivationProfiles.Original ? 0xC1800U : 0xB6DA8U;
                if (profile == ActivationProfiles.Original) {
                    BitConverter.GetBytes((ulong)record).CopyTo(bytes, image.Map(imports.Lookup + 162 * 8, 8));
                    BitConverter.GetBytes((ulong)record).CopyTo(bytes, image.Map(slot, 8));
                    Encoding.ASCII.GetBytes("CsrClientCallServer\0").CopyTo(bytes, image.Map(record + 2, 20));
                }
                uint[] sites = image.DispatchSites(profile);
                uint[] expected = profile == ActivationProfiles.Original ?
                    new uint[] { 0x24BD5, 0x24BDC, 0x8B3C0 } : new uint[] { 0x23F85, 0x23F8C, 0x8B3F0 };
                Need(System.Linq.Enumerable.SequenceEqual(sites, expected) && image.CsrDispatchIatAddress(slot) == 1UL + slot);
                foreach (uint at in new [] { imports.Lookup + 162 * 8, slot, record + 2 }) {
                    byte[] bad = (byte[])bytes.Clone(); bad[image.Map(at, 1)] ^= 1;
                    ModuleRefuse(() => FromActivationWorker(bad).DispatchSites(profile));
                }
            }
            byte[] export = ActivationWorkerFixture();
            Array.Clear(export, 0x480, 129); Encoding.ASCII.GetBytes("CsrClientCallServer\0").CopyTo(export, 0x480);
            var ntdll = new KernelImage(export, 0x10000000, "ntdll.dll");
            Need(ntdll.CsrDispatchExport() == 0x10001020);
            foreach (Action<byte[]> change in new Action<byte[]>[] {
                b => Put(b, 0x98 + 112, 0), b => Put(b, 0x98 + 116, 39),
                b => Put(b, 0x414, 4097), b => Put(b, 0x418, 4097), b => Put16(b, 0x458, 2),
                b => Put(b, 0x440, 0x1200), b => Put(b, 0x440, 0x2000), b => b[0x480] ^= 1,
                b => Put(b, 0x450, UInt32.MaxValue), b => Put(b, 0x41C, UInt32.MaxValue),
                b => Put(b, 0x188 + 36, 0x40000040),
                b => { Put(b, 0x418, 2); Put(b, 0x454, 0x1280); Put16(b, 0x45A, 1); },
                b => { Put(b, 0x418, 2); Put(b, 0x454, 0x12B0); Put16(b, 0x45A, 0); Encoding.ASCII.GetBytes("OtherExport\0").CopyTo(b, 0x4B0); }
            }) ModuleRefuse(() => { byte[] bad = (byte[])export.Clone(); change(bad); new KernelImage(bad, 0x10000000, "ntdll.dll").CsrDispatchExport(); });
            ModuleRefuse(() => FromActivationWorker(export).CsrDispatchExport());
        }
    }
}
