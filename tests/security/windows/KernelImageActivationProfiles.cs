using System;

namespace ScientificSecurity
{
    public sealed partial class KernelImage
    {
        const string OriginalActivationIdentity = "phase=image-identity module=kernel32.dll sha256=347f1ac1b7dbec710cf06fb3f67d131bceebbc19076bc77daacd31cfe452b496 pe_timestamp=4227614027 image_size=823296 file_size=836208";
        const string ServicedActivationIdentity = "phase=image-identity module=kernel32.dll sha256=601aaacb3bdcbea24aec832d08a2f12ec7046183b6f40d18d61458d5e7008991 pe_timestamp=1269129758 image_size=823296 file_size=853648";
        sealed class ActivationImportProfile
        {
            internal readonly uint Descriptor, Lookup, Address, Count;
            internal readonly string Owner;
            internal readonly uint[] Indices, Records;
            internal readonly ushort[] Hints;
            internal readonly string[] Names;
            internal ActivationImportProfile(uint descriptor, string owner, uint lookup, uint address, uint count,
                uint[] indices, uint[] records, ushort[] hints, string[] names)
            {
                Descriptor = descriptor; Owner = owner; Lookup = lookup; Address = address; Count = count;
                Indices = (uint[])indices.Clone(); Records = (uint[])records.Clone();
                Hints = (ushort[])hints.Clone(); Names = (string[])names.Clone();
                Need(Indices.Length == Records.Length && Indices.Length == Hints.Length && Indices.Length == Names.Length);
            }
        }
        sealed class ActivationProfile
        {
            internal readonly string Identity;
            internal readonly uint Entry, Worker, ExecutableTarget, ImportDirectory, NullDescriptor;
            internal readonly uint[] Code, Edges, Callback, CallbackEdges, CallbackShortEdges;
            internal readonly string[] Bytes, CallbackBytes;
            internal readonly ActivationImportProfile[] Imports;
            internal ActivationProfile(string identity, uint entry, uint worker, uint[] code, string[] bytes, uint[] edges,
                uint executableTarget, uint[] callback, string[] callbackBytes, uint[] callbackEdges, uint[] callbackShortEdges,
                uint importDirectory, uint nullDescriptor, ActivationImportProfile[] imports)
            {
                Identity = identity; Entry = entry; Worker = worker; ExecutableTarget = executableTarget;
                Code = (uint[])code.Clone(); Bytes = (string[])bytes.Clone(); Edges = (uint[])edges.Clone();
                Callback = (uint[])callback.Clone(); CallbackBytes = (string[])callbackBytes.Clone();
                CallbackEdges = (uint[])callbackEdges.Clone(); CallbackShortEdges = (uint[])callbackShortEdges.Clone();
                ImportDirectory = importDirectory; NullDescriptor = nullDescriptor; Imports = (ActivationImportProfile[])imports.Clone();
                Need(Code.Length == 65 && Bytes.Length == 65 && Edges.Length == 22 && Callback.Length == 72 &&
                    CallbackBytes.Length == 72 && CallbackEdges.Length == 7 && CallbackShortEdges.Length == 11 && Code[10] == Worker);
            }
        }
        static string[] ActivationEncodings()
        {
            string[] bytes = (string[])activationBytes.Clone();
            int[] indices = { 0,7,14,17,27,32,40,53,60 };
            string[] values = { "48FF15AC780600","48FF1564740600","E8FF9CFEFF","48FF15A8430600","48FF15325D0600",
                "48FF15EB510600","48FF15E2550600","48FF15ED500600","48FF15F5460600" };
            for (int index = 0; index < indices.Length; index++) bytes[indices[index]] = values[index];
            return bytes;
        }
        static string[] CallbackEncodings()
        {
            string[] bytes = (string[])callbackBytes.Clone();
            int[] indices = { 0,1,3,38,62 };
            string[] values = { "4C8B05A3D20500","488D15743C0300","48FF1526E30500","48FF15A3600600","48FF15CF580600" };
            for (int index = 0; index < indices.Length; index++) bytes[indices[index]] = values[index];
            return bytes;
        }
        // Lazy construction avoids cross-partial field-initialization order dependencies.
        static class ActivationProfiles
        {
            internal static readonly ActivationProfile Original = new ActivationProfile(OriginalActivationIdentity, 0x2E1D0, 0x24D20,
                activationRvas, activationBytes,
                new uint[] { 0x8B7E0,0x8B3C0,0x24C1C,0x25A27,0xEAD0,0x88F90,0x258AA,0x25CEC,0x259EC,0x8B310,0x26DD6,
                    0x8B818,0x272E1,0x272CF,0x8B310,0x26A48,0x26B72,0x26C64,0x8B020,0x26BEB,0x8B218,0x27848 }, 0x25CEC,
                callbackRvas, callbackBytes, new uint[] { 0x8A8D8,0x61330,0x25B90,0x8B970,0x25CAC,0x8B040,0x8A8D0 },
                new uint[] { 0x25C47,0x25C40,0x25C4E,0x25C5F,0x25C26,0x25C26,0x25BF2,0x25C40,0x25C93,0x25C26,0x25C26 },
                0xB34BC, 0xB3CDC, new[] {
                    new ActivationImportProfile(0xB34E4,"ntdll.dll",0xB5C88,0x8AEB0,365,
                        new uint[] {344,50},new uint[] {0xB6A68,0xB7616},new ushort[] {0xA7,0x9D},
                        new[] {"LdrSetDllManifestProber","LdrResFindResourceDirectory"}),
                    new ActivationImportProfile(0xB3B60,"api-ms-win-core-sidebyside-l1-1-0.dll",0xB5660,0x8A888,11,
                        new uint[] {9,10},new uint[] {0xBC2F8,0xBC2E8},new ushort[] {2,9},new[] {"CreateActCtxW","ReleaseActCtx"}) });
            internal static readonly ActivationProfile Serviced = new ActivationProfile(ServicedActivationIdentity, 0x2D580, 0x240D0,
                new uint[] { 0x23F5D,0x23F64,0x23F69,0x23F6B,0x23F6D,0x23F79,0x23F7F,0x23F85,0x23F8C,0x23F91,
                    0x240D0,0x24DC6,0x24DC8,0x24DCA,0x24DCC,0x24DD1,0x24DD7,0x24C11,0x24C18,0x24C1D,
                    0x24C21,0x24C25,0x24C74,0x24C79,0x24C7B,0x24C7D,0x255EA,0x25607,0x2560E,0x25613,
                    0x25615,0x25617,0x26656,0x2665D,0x26662,0x26666,0x2666B,0x2666D,0x2666F,0x25D41,
                    0x25D57,0x25D5E,0x25D63,0x25D65,0x25D67,0x25D69,0x25EEA,0x25F15,0x25F1A,0x25F1E,
                    0x25F20,0x25F22,0x25F24,0x25F5C,0x25F63,0x25F68,0x25F6A,0x25F6C,0x25F6E,0x26B37,
                    0x26B4C,0x26B53,0x26B58,0x26B5A,0x26B5C }, ActivationEncodings(),
                new uint[] { 0x8B810,0x8B3F0,0x23FCC,0x24DD7,0xEAD0,0x88FC0,0x24C5A,0x2509C,0x24D9C,0x8B340,0x26186,
                    0x8B848,0x26691,0x2667F,0x8B340,0x25DF8,0x25F22,0x26014,0x8B050,0x25F9B,0x8B248,0x26BF8 }, 0x2509C,
                new uint[] { 0x2D65E,0x2D665,0x2D66C,0x2D673,0x2D67A,
                    0x24F40,0x24F45,0x24F4A,0x24F4F,0x24F50,0x24F53,0x24F5A,0x24F5C,0x24F63,0x24F67,0x24F6A,
                    0x24F6D,0x24F70,0x24F73,0x24F76,0x24F7A,0x24F7E,0x24F82,0x24F85,0x24F87,0x24F8A,0x24F8F,
                    0x24F91,0x24F93,0x24F9C,0x24FA0,0x24FA2,0x24FA7,0x24FAF,0x24FB5,0x24FB9,0x24FBF,0x24FC2,
                    0x24FC6,0x24FCD,0x24FD2,0x24FD4,0x24FD6,0x24FDE,0x24FE2,0x24FE6,0x24FEA,0x24FED,0x24FEE,
                    0x24FF0,0x24FF5,0x24FF7,0x24FFC,0x24FFE,0x25007,0x2500B,0x2500D,0x2500F,0x25013,0x2501A,
                    0x2501E,0x25026,0x2502A,0x25031,0x25036,0x2503A,0x2503C,0x2503F,0x25041,0x25043,0x2504C,0x25052 }, CallbackEncodings(),
                new uint[] { 0x8A908,0x612E0,0x24F40,0x8B9A0,0x2505C,0x8B070,0x8A900 },
                new uint[] { 0x24FF7,0x24FF0,0x24FFE,0x2500F,0x24FD6,0x24FD6,0x24FA2,0x24FF0,0x25043,0x24FD6,0x24FD6 },
                0xB371C,0xB3F3C,new[] {
                    new ActivationImportProfile(0xB3744,"ntdll.dll",0xB5EE8,0x8AEE0,365,
                        new uint[] {344,50,294,162,140,301,46,109},
                        new uint[] {0xB6CC8,0xB7876,0xBE312,0xB6DA8,0xB6FCC,0xBE3AC,0xB78E0,0xB72A4},
                        new ushort[] {0xA7,0x9D,0x19,0x1C,0x1AE,0x473,0x1A0,0x1B1},
                        new[] {"LdrSetDllManifestProber","LdrResFindResourceDirectory","CsrCaptureMessageMultiUnicodeStringsInPlace","CsrClientCallServer",
                            "NtOpenFile","RtlGetThreadPreferredUILanguages","NtMapViewOfSection","NtOpenKey"}),
                    new ActivationImportProfile(0xB3DC0,"api-ms-win-core-sidebyside-l1-1-0.dll",0xB58C0,0x8A8B8,11,
                        new uint[] {9,10},new uint[] {0xBC558,0xBC548},new ushort[] {2,9},new[] {"CreateActCtxW","ReleaseActCtx"}),
                    new ActivationImportProfile(0xB3758,"KERNELBASE.dll",0xB3F50,0x88F48,93,
                        new uint[] {15},new uint[] {0xB826C},new ushort[] {0x28},new[] {"BaseDllMapResourceIdW"}) });
        }
        static ActivationProfile SelectActivation(string identity)
        {
            if (identity == OriginalActivationIdentity) return ActivationProfiles.Original;
            if (identity == ServicedActivationIdentity) return ActivationProfiles.Serviced;
            throw new InvalidOperationException("fixed kernel32 identity is unsupported");
        }
        uint ActivationSite(int role)
        {
            var profile = SelectActivation(ActivationWorkerIdentity());
            Need(ActivationWorkerSlice().Rva == profile.Worker);
            ActivationBoundaryBytes(profile); CallbackBytes(profile);
            return ActivationSite(profile, role);
        }
        static uint ActivationSite(ActivationProfile profile, int role)
        {
            switch (role) {
                case 0: return profile.Worker;
                case 1: return profile.Code[62];
                case 2: return profile.Code[13];
                case 3: return profile.Callback[39];
                case 4: return profile.Callback[63];
                default: throw new InvalidOperationException("fixed activation observation role is unsupported");
            }
        }
        internal uint ActivationWorkerSite { get { return ActivationSite(0); } }
        internal uint ActivationRegistrySite { get { return ActivationSite(1); } }
        internal uint ActivationFunnelSite { get { return ActivationSite(2); } }
        internal uint ActivationResourceSite { get { return ActivationSite(3); } }
        internal uint ActivationCallbackSite { get { return ActivationSite(4); } }
    }
}
