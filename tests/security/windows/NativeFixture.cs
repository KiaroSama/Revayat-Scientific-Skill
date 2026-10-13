using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.Win32;

namespace ScientificSecurity
{
    // Fixed trusted no-CRT fixture only; no arbitrary build source, command or executable selector.
    public static class NativeFixture
    {
        public static void Build(string windowsSource, string runtime, string state)
        {
            string source = Path.Combine(Path.GetFullPath(windowsSource), "StartupNative.c");
            string output = Path.Combine(Path.GetFullPath(runtime), "startup-native.exe");
            string obj = Path.Combine(Path.GetFullPath(state), "startup-native.obj");
            Plain(source); Plain(runtime); Plain(state);
            const string fixtureSource = "/* Trusted CI startup differential only: no CRT, input, buffers or target code. */\n" +
                "__declspec(dllimport) void __stdcall ExitProcess(unsigned int code);\n" +
                "void __stdcall StartupEntry(void)\n{\n    ExitProcess(0);\n}\n";
            if (new FileInfo(source).Length > 1024 || File.ReadAllText(source, Encoding.UTF8).Replace("\r\n", "\n") != fixtureSource)
                throw new InvalidOperationException("native fixture source differs from fixed trusted pass contract");
            CheckValidation();
            Plain(output, true); Plain(obj, true);
            RequireNoManifest(output);
            if (File.Exists(output) || File.Exists(obj)) throw new InvalidOperationException("native fixture output must be new owned state");
            var tools = CompilerTools(state);
            string cl = tools.Item1, link = tools.Item2, kernel32 = tools.Item3;
            // /GS- is confined to this bufferless nonproduction fixture; never target/controller code.
            TrustedSetup.Run(cl, new [] { "/nologo", "/c", "/TC", "/GS-", "/Zl", "/Fo" + obj, source }, state);
            Plain(obj);
            TrustedSetup.Run(link, new [] { "/nologo", "/NODEFAULTLIB", "/MANIFEST:NO", "/ENTRY:StartupEntry", "/SUBSYSTEM:CONSOLE",
                "/MACHINE:X64", "/OUT:" + output, obj, kernel32 }, state);
            Validate(output);
            Console.Out.WriteLine("WINDOWS_NATIVE_FIXTURE pe_verified=true architecture=x64 imports=kernel32.ExitProcess crt=false clr=false manifest=false");
            Console.Out.Flush();
        }
        internal static Tuple<string, string, string> CompilerTools(string state)
        {
            string vswhere = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                "Microsoft Visual Studio", "Installer", "vswhere.exe");
            Plain(vswhere);
            string discovery = TrustedSetup.Run(vswhere, new [] { "-latest", "-products", "*", "-requires",
                "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath" }, state);
            string[] installs = discovery.Split(new [] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            bool firstAbsolute = installs.Length != 0 && Path.IsPathFullyQualified(installs[0]);
            Console.Out.WriteLine("WINDOWS_MSVC_DISCOVERY candidate_count=" + installs.Length + " output_length=" + discovery.Length
                + " first_absolute=" + firstAbsolute);
            Console.Out.Flush();
            if (installs.Length != 1 || !firstAbsolute)
                throw new InvalidOperationException("preinstalled MSVC discovery is unavailable or ambiguous");
            string versionFile = Path.Combine(installs[0], "VC", "Auxiliary", "Build", "Microsoft.VCToolsVersion.default.txt");
            Plain(versionFile);
            if (new FileInfo(versionFile).Length > 128) throw new InvalidOperationException("MSVC version metadata exceeds fixed bound");
            string version = File.ReadAllText(versionFile).Trim(); Version parsed;
            if (!Version.TryParse(version, out parsed) || version.Any(c => !(c >= '0' && c <= '9') && c != '.'))
                throw new InvalidOperationException("preinstalled MSVC version metadata is invalid");
            string tools = Path.Combine(installs[0], "VC", "Tools", "MSVC", version, "bin", "Hostx64", "x64");
            string cl = Path.Combine(tools, "cl.exe"), link = Path.Combine(tools, "link.exe");
            Plain(cl); Plain(link);
            string sdk;
            using (RegistryKey roots = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Kits\Installed Roots")) {
                sdk = roots == null ? null : roots.GetValue("KitsRoot10") as string;
            }
            if (String.IsNullOrEmpty(sdk) || !Path.IsPathFullyQualified(sdk))
                throw new InvalidOperationException("preinstalled Windows SDK is unavailable");
            string libraries = Path.Combine(sdk, "Lib"); Plain(libraries);
            var candidates = new List<Tuple<Version, string>>(); int scanned = 0;
            foreach (string folder in Directory.EnumerateDirectories(libraries)) {
                if (++scanned > 32) throw new InvalidOperationException("SDK version set exceeds finite discovery bound");
                Plain(folder); Version sdkVersion;
                if (!Version.TryParse(Path.GetFileName(folder), out sdkVersion)) continue;
                string library = Path.Combine(folder, "um", "x64", "kernel32.lib");
                Plain(library, true);
                if (File.Exists(library)) candidates.Add(Tuple.Create(sdkVersion, library));
            }
            if (candidates.Count == 0) throw new InvalidOperationException("preinstalled x64 Kernel32 import library is unavailable");
            string kernel32 = candidates.OrderByDescending(value => value.Item1).First().Item2;
            return Tuple.Create(cl, link, kernel32);
        }
        public static void BuildDebugControlFixed(string runtime, string state)
        {
            Plain(runtime); Plain(state);
            string stateName = Path.GetFileName(Path.TrimEndingDirectorySeparator(state));
            string run = stateName.StartsWith("security-windows-", StringComparison.Ordinal) ? stateName.Substring("security-windows-".Length) : "";
            if (run.Length != 32 || !run.All(c => (c >= 'a' && c <= 'f') || (c >= '0' && c <= '9')) ||
                !String.Equals(Path.GetFullPath(runtime), Path.Combine(Path.GetFullPath(state), "python"), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("fixed debug-control builder requires the owned prepared runtime");
            CheckDebugControlValidation();
            string source = Path.Combine(state, "debug-control-native.c");
            string output = Path.Combine(runtime, "debug-control-native.exe"), obj = Path.Combine(state, "debug-control-native.obj");
            string library = Path.Combine(state, "debug-control-native.lib"), exp = Path.Combine(state, "debug-control-native.exp");
            foreach (string path in new [] { source, output, obj, library, exp }) {
                Plain(path, true);
                try { File.GetAttributes(path); }
                catch (FileNotFoundException) { continue; }
                catch (DirectoryNotFoundException) { continue; }
                throw new InvalidOperationException("fixed debug-control build output collides with an existing entry");
            }
            RequireNoManifest(output);
            const string fixedSource = "/* Fixed hosted debugger control; no CRT or input. */\n" +
                "__declspec(dllimport) void __stdcall ExitProcess(unsigned int code);\n" +
                "__declspec(noinline) unsigned long DebugControlSite(void) { return 0x53444331UL; }\n" +
                "void __stdcall StartupEntry(void) { ExitProcess(DebugControlSite() == 0x53444331UL ? 0 : 1); }\n";
            byte[] bytes = Encoding.UTF8.GetBytes(fixedSource);
            using (var stream = new FileStream(source, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                stream.Write(bytes, 0, bytes.Length); stream.Flush(true);
            }
            Plain(source);
            if (File.ReadAllText(source, Encoding.UTF8) != fixedSource)
                throw new InvalidOperationException("fixed debug-control source readback differs");
            var tools = CompilerTools(state);
            TrustedSetup.Run(tools.Item1, new [] { "/nologo", "/c", "/TC", "/O2", "/Ob0", "/GS-", "/Zl", "/Fo" + obj, source }, state);
            Plain(obj);
            TrustedSetup.Run(tools.Item2, new [] { "/nologo", "/NODEFAULTLIB", "/MANIFEST:NO", "/ENTRY:StartupEntry",
                "/EXPORT:DebugControlSite", "/IMPLIB:" + library, "/SUBSYSTEM:CONSOLE", "/MACHINE:X64", "/OUT:" + output, obj, tools.Item3 }, state);
            DebugControlSiteFromFile(output);
        }
        internal static uint DebugControlSiteFromFile(string path)
        {
            Plain(path); RequireNoManifest(path);
            byte[] bytes;
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                if (stream.Length < 256 || stream.Length > 1048576) throw new InvalidOperationException("fixed debug-control PE exceeds bounds");
                bytes = new byte[(int)stream.Length]; int position = 0;
                while (position < bytes.Length) {
                    int read = stream.Read(bytes, position, bytes.Length - position);
                    if (read == 0) throw new InvalidOperationException("fixed debug-control PE read was truncated");
                    position += read;
                }
            }
            var pe = new Pe(bytes); pe.Validate(); return pe.DebugControlSite();
        }
        internal static void Plain(string path, bool allowMissing = false)
        {
            if (!Path.IsPathFullyQualified(path)) throw new ArgumentException("native fixture inputs require absolute paths");
            var ancestors = new Stack<string>();
            for (string current = Path.GetFullPath(path); !String.IsNullOrEmpty(current); current = Path.GetDirectoryName(current)) {
                if (ancestors.Count >= 64) throw new InvalidOperationException("native fixture path exceeds ancestor bound");
                ancestors.Push(current);
            }
            while (ancestors.Count != 0) {
                try {
                    if ((File.GetAttributes(ancestors.Pop()) & FileAttributes.ReparsePoint) != 0)
                        throw new InvalidOperationException("native fixture selected input/ancestor is a reparse point");
                }
                catch (FileNotFoundException) { if (!allowMissing) throw; }
                catch (DirectoryNotFoundException) { if (!allowMissing) throw; }
            }
        }
        static void RequireNoManifest(string executable)
        {
            foreach (string path in new [] { executable + ".manifest", Path.ChangeExtension(executable, ".manifest") }) {
                Plain(path, true); // Validate existing ancestors/leaf before any existence decision.
                try { File.GetAttributes(path); }
                catch (FileNotFoundException) { continue; }
                catch (DirectoryNotFoundException) { continue; }
                throw new InvalidOperationException("fixed native fixture must not have a manifest sidecar");
            }
        }
        internal static void Validate(string path)
        {
            Plain(path); RequireNoManifest(path);
            byte[] image;
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                if (stream.Length < 256 || stream.Length > 1048576) throw new InvalidOperationException("native fixture PE size exceeds fixed bound");
                image = new byte[(int)stream.Length]; int position = 0;
                while (position < image.Length) {
                    int count = stream.Read(image, position, image.Length - position);
                    if (count == 0) throw new EndOfStreamException("native fixture PE truncated during bounded read");
                    position += count;
                }
            }
            new Pe(image).Validate();
        }
        // Pure managed parser check, shared with real compiler-output validation; no native calls.
        public static void CheckValidation()
        {
            var valid = new byte[1024];
            Put(valid, 0, (ushort)0x5A4D); Put(valid, 0x3C, (uint)0x80);
            Put(valid, 0x80, (uint)0x4550); Put(valid, 0x84, (ushort)0x8664);
            Put(valid, 0x86, (ushort)1); Put(valid, 0x94, (ushort)240); Put(valid, 0x96, (ushort)2);
            const int optional = 0x98, section = 0x188;
            Put(valid, optional, (ushort)0x20B); Put(valid, optional + 16, (uint)0x1000);
            Put(valid, optional + 60, (uint)0x200); Put(valid, optional + 68, (ushort)3);
            Put(valid, optional + 108, (uint)16); Put(valid, optional + 120, (uint)0x1040); Put(valid, optional + 124, (uint)40);
            Put(valid, section + 8, (uint)0x200); Put(valid, section + 12, (uint)0x1000);
            Put(valid, section + 16, (uint)0x200); Put(valid, section + 20, (uint)0x200); Put(valid, section + 36, (uint)0x60000020);
            Put(valid, 0x240, (uint)0x1080); Put(valid, 0x24C, (uint)0x10A0); Put(valid, 0x250, (uint)0x1090);
            Put(valid, 0x280, (ulong)0x10C0); Put(valid, 0x290, (ulong)0x10C0);
            Encoding.ASCII.GetBytes("KERNEL32.dll\0").CopyTo(valid, 0x2A0);
            Encoding.ASCII.GetBytes("ExitProcess\0").CopyTo(valid, 0x2C2);
            new Pe(valid).Validate();
            var changes = new Action<byte[]>[] {
                bytes => Put(bytes, optional + 16, UInt32.MaxValue),
                bytes => Put(bytes, optional + 120, UInt32.MaxValue),
                bytes => Put(bytes, 0x254, (uint)1), // extra nonzero import descriptor.
                bytes => { Put(bytes, optional + 112 + 2 * 8, (uint)0x1000); Put(bytes, optional + 116 + 2 * 8, (uint)16); },
                bytes => Put(bytes, optional + 116 + 2 * 8, (uint)8), // resource size alone is not an absent directory.
                bytes => Put(bytes, optional + 112 + 14 * 8, (uint)0x1000),
                bytes => Put(bytes, optional + 112 + 9 * 8, (uint)0x1000),
                bytes => Put(bytes, optional + 112 + 13 * 8, (uint)0x1000),
                bytes => Put(bytes, 0x290, (ulong)0x10C1), // IAT must equal validated INT.
                bytes => { Put(bytes, 0x86, (ushort)2); Array.Copy(bytes, section, bytes, section + 40, 40); },
                bytes => bytes[0x2C2] = (byte)'X'
            };
            foreach (var change in changes) {
                byte[] invalid = (byte[])valid.Clone(); change(invalid);
                bool rejected = false;
                try { new Pe(invalid).Validate(); } catch (InvalidOperationException) { rejected = true; }
                if (!rejected) throw new InvalidOperationException("native fixture malformed-PE regression was accepted");
            }
        }
        public static void CheckDebugControlValidation()
        {
            byte[] bytes = DebugControlFixture();
            var pe = new Pe(bytes); pe.Validate();
            if (pe.DebugControlSite() != 0x1010) throw new InvalidOperationException("debug-control site fixture failed");
            foreach (Action<byte[]> change in new Action<byte[]>[] {
                b => b[0x210] = 0x90, b => b[0x215] = 0x90,
                b => Put(b, 0x300 + 20, (uint)2), b => Put(b, 0x340, (uint)0x1100),
                b => Put(b, 0x34C, UInt32.MaxValue), b => Put(b, 0x188 + 36, (uint)0x40000040)
            }) {
                byte[] bad = (byte[])bytes.Clone(); change(bad); bool rejected = false;
                try { new Pe(bad).DebugControlSite(); } catch (InvalidOperationException) { rejected = true; }
                if (!rejected) throw new InvalidOperationException("malformed fixed debug-control PE was accepted");
            }
        }
        static byte[] DebugControlFixture()
        {
            // Same single-section/import fixture used above, with exactly one fixed export/site.
            byte[] b = new byte[1024]; Put(b, 0, (ushort)0x5A4D); Put(b, 0x3C, (uint)0x80);
            Put(b, 0x80, (uint)0x4550); Put(b, 0x84, (ushort)0x8664); Put(b, 0x86, (ushort)1);
            Put(b, 0x94, (ushort)240); Put(b, 0x96, (ushort)2); const int optional = 0x98, section = 0x188;
            Put(b, optional, (ushort)0x20B); Put(b, optional + 16, (uint)0x1000); Put(b, optional + 60, (uint)0x200);
            Put(b, optional + 68, (ushort)3); Put(b, optional + 108, (uint)16);
            Put(b, optional + 112, (uint)0x1100); Put(b, optional + 116, (uint)0x100);
            Put(b, optional + 120, (uint)0x1040); Put(b, optional + 124, (uint)40);
            Put(b, section + 8, (uint)0x200); Put(b, section + 12, (uint)0x1000);
            Put(b, section + 16, (uint)0x200); Put(b, section + 20, (uint)0x200); Put(b, section + 36, (uint)0x60000020);
            Put(b, 0x240, (uint)0x1080); Put(b, 0x24C, (uint)0x10A0); Put(b, 0x250, (uint)0x1090);
            Put(b, 0x280, (ulong)0x10C0); Put(b, 0x290, (ulong)0x10C0);
            Encoding.ASCII.GetBytes("KERNEL32.dll\0").CopyTo(b, 0x2A0); Encoding.ASCII.GetBytes("ExitProcess\0").CopyTo(b, 0x2C2);
            Put(b, 0x300 + 20, (uint)1); Put(b, 0x300 + 24, (uint)1); Put(b, 0x300 + 28, (uint)0x1140);
            Put(b, 0x300 + 32, (uint)0x114C); Put(b, 0x300 + 36, (uint)0x1150); Put(b, 0x340, (uint)0x1010);
            Put(b, 0x34C, (uint)0x1160); Encoding.ASCII.GetBytes("DebugControlSite\0").CopyTo(b, 0x360);
            new byte[] { 0xB8, 0x31, 0x43, 0x44, 0x53, 0xC3 }.CopyTo(b, 0x210); return b;
        }
        static void Put(byte[] bytes, int offset, ushort value) { BitConverter.GetBytes(value).CopyTo(bytes, offset); }
        static void Put(byte[] bytes, int offset, uint value) { BitConverter.GetBytes(value).CopyTo(bytes, offset); }
        static void Put(byte[] bytes, int offset, ulong value) { BitConverter.GetBytes(value).CopyTo(bytes, offset); }
        sealed class Pe
        {
            readonly byte[] data;
            struct Section { internal uint address, virtualSize, raw, rawSize, flags; }
            readonly List<Section> sections = new List<Section>();
            uint headers;
            bool validated;
            internal Pe(byte[] bytes) { data = bytes; }
            void Require(bool value) { if (!value) throw new InvalidOperationException("native fixture PE does not match the fixed no-CRT contract"); }
            void Range(ulong offset, ulong count) { Require(offset <= (ulong)data.Length && count <= (ulong)data.Length - offset); }
            ushort U16(ulong offset) { Range(offset, 2); return BitConverter.ToUInt16(data, checked((int)offset)); }
            uint U32(ulong offset) { Range(offset, 4); return BitConverter.ToUInt32(data, checked((int)offset)); }
            ulong U64(ulong offset) { Range(offset, 8); return BitConverter.ToUInt64(data, checked((int)offset)); }
            int Map(uint rva, uint size)
            {
                int matches = 0, found = 0; ulong end = (ulong)rva + size;
                if (end <= headers) { Range(rva, size); found = checked((int)rva); matches++; }
                foreach (Section section in sections) {
                    if (rva >= section.address && end <= (ulong)section.address + section.rawSize) {
                        ulong offset = (ulong)section.raw + rva - section.address; Range(offset, size);
                        found = checked((int)offset); matches++;
                    }
                }
                Require(matches == 1); return found;
            }
            string Text(uint rva)
            {
                var value = new StringBuilder();
                for (uint index = 0; index < 128; index++) {
                    Require((ulong)rva + index <= UInt32.MaxValue);
                    byte item = data[Map(rva + index, 1)];
                    if (item == 0) return value.ToString();
                    Require(item >= 32 && item <= 126); value.Append((char)item);
                }
                throw new InvalidOperationException("native fixture import name exceeds finite bound");
            }
            internal uint DebugControlSite()
            {
                Validate(); uint nt = U32(0x3C); ulong optional = (ulong)nt + 24;
                uint export = U32(optional + 112), exportBytes = U32(optional + 116);
                Require(export != 0 && exportBytes >= 40 && (ulong)export + exportBytes <= UInt32.MaxValue);
                int table = Map(export, exportBytes);
                Require(U32((ulong)table + 20) == 1 && U32((ulong)table + 24) == 1);
                uint function = U32((ulong)Map(U32((ulong)table + 28), 4));
                uint name = U32((ulong)Map(U32((ulong)table + 32), 4));
                Require(U16((ulong)Map(U32((ulong)table + 36), 2)) == 0 && Text(name) == "DebugControlSite");
                Require(function < export || (ulong)function >= (ulong)export + exportBytes);
                bool executable = false;
                foreach (Section section in sections)
                    executable |= (section.flags & 0x20000000) != 0 && function >= section.address &&
                        (ulong)function + 6 <= (ulong)section.address + section.rawSize;
                Require(executable); int code = Map(function, 6);
                Require(data.Skip(code).Take(6).SequenceEqual(new byte[] { 0xB8, 0x31, 0x43, 0x44, 0x53, 0xC3 }));
                return function;
            }
            internal void Validate()
            {
                if (validated) return;
                Require(U16(0) == 0x5A4D); ulong pe = U32(0x3C);
                Require(pe >= 64 && U32(pe) == 0x4550 && U16(pe + 4) == 0x8664);
                ushort count = U16(pe + 6), optionalSize = U16(pe + 20);
                Require(count > 0 && count <= 16 && optionalSize >= 240 && (U16(pe + 22) & 0x2002) == 2);
                ulong optional = pe + 24; Range(optional, optionalSize);
                Require(U16(optional) == 0x20B && U16(optional + 68) == 3 && U32(optional + 108) == 16);
                headers = U32(optional + 60); Require(headers > 0 && headers <= data.Length);
                ulong table = optional + optionalSize; Range(table, (ulong)count * 40);
                Require(table + (ulong)count * 40 <= headers);
                for (int index = 0; index < count; index++) {
                    ulong row = table + (ulong)index * 40;
                    var section = new Section { virtualSize = U32(row + 8), address = U32(row + 12), rawSize = U32(row + 16),
                        raw = U32(row + 20), flags = U32(row + 36) };
                    Require(section.rawSize > 0 && section.raw >= headers && section.address >= headers);
                    Range(section.raw, section.rawSize);
                    Require((ulong)section.address + Math.Max(section.virtualSize, section.rawSize) <= (ulong)UInt32.MaxValue + 1);
                    foreach (Section prior in sections) {
                        Require((ulong)section.raw >= (ulong)prior.raw + prior.rawSize || (ulong)prior.raw >= (ulong)section.raw + section.rawSize);
                        Require((ulong)section.address >= (ulong)prior.address + Math.Max(prior.virtualSize, prior.rawSize) ||
                            (ulong)prior.address >= (ulong)section.address + Math.Max(section.virtualSize, section.rawSize));
                    }
                    sections.Add(section);
                }
                uint entry = U32(optional + 16); Require(entry != 0); Map(entry, 1);
                Require(sections.Count(section => entry >= section.address && (ulong)entry < (ulong)section.address + section.rawSize
                    && (section.flags & 0x20000000) != 0) == 1);
                foreach (int directory in new [] { 2, 9, 13, 14 })
                    Require(U64(optional + 112 + (ulong)directory * 8) == 0); // no resources/manifest, TLS, delay imports or CLR.
                uint importRva = U32(optional + 120), importSize = U32(optional + 124);
                Require(importRva != 0 && importSize >= 40); int descriptor = Map(importRva, importSize);
                uint thunk = U32((uint)descriptor), name = U32((uint)descriptor + 12), iat = U32((uint)descriptor + 16);
                Require(thunk != 0 && name != 0 && iat != 0 && U32((uint)descriptor + 4) == 0 && U32((uint)descriptor + 8) == 0
                    && String.Equals(Text(name), "KERNEL32.dll", StringComparison.OrdinalIgnoreCase));
                for (uint offset = 20; offset < 40; offset += 4) Require(U32((uint)descriptor + offset) == 0);
                int lookup = Map(thunk, 16); ulong symbol = U64((uint)lookup);
                Require(symbol > 0 && symbol <= UInt32.MaxValue && U64((uint)lookup + 8) == 0);
                Require(Text(checked((uint)symbol + 2)) == "ExitProcess"); Map((uint)symbol, 2);
                int address = Map(iat, 16); Require(U64((uint)address) == symbol && U64((uint)address + 8) == 0);
                validated = true;
            }
        }
    }
}
