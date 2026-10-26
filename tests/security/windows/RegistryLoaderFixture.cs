using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace ScientificSecurity
{
    // Fixed build and held-byte identity only; no local or host-side helper execution.
    public static class RegistryLoaderFixture
    {
        static string prepared;
        static string[] hashes;
        static int[] lengths;
        static readonly string[] Names = { "_registry_loader.pyd", "_ctypes.pyd", "libffi-8.dll" };
        static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
        static void Need(bool value)
        { if (!value) throw new InvalidOperationException("fixed registry loader prerequisite differs"); }
        static byte[] Read(string path, int maximum)
        {
            using (var stream = ModuleActivationFixture.Open(path)) return ModuleActivationFixture.Read(stream, maximum);
        }
        static string Header(string path)
        {
            Need(Path.IsPathFullyQualified(path) && path == Path.GetFullPath(path) && path.Length < 512 && !path.Contains('\0'));
            return "static const wchar_t registry_loader_path[] = {" + String.Join(",", path.Select(c => ((uint)c).ToString(System.Globalization.CultureInfo.InvariantCulture))) + ",0};\n";
        }
        static string[] Includes(Tuple<string, string, string> tools, string home)
        {
            string msvc = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(tools.Item1), "..", "..", "..", "include"));
            string libraryVersion = Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(tools.Item3)));
            string sdk = Path.GetDirectoryName(Path.GetDirectoryName(libraryVersion));
            string include = Path.Combine(sdk, "Include", Path.GetFileName(libraryVersion));
            var paths = new [] { Path.Combine(home, "include"), msvc, Path.Combine(include, "ucrt"), Path.Combine(include, "shared"), Path.Combine(include, "um") };
            foreach (string path in paths) { NativeFixture.Plain(path); Need(Directory.Exists(path)); }
            foreach (string name in new [] { "Python.h", "pyconfig.h", "patchlevel.h" }) NativeFixture.Plain(Path.Combine(paths[0], name));
            string patch = Utf8.GetString(Read(Path.Combine(paths[0], "patchlevel.h"), 65536));
            Need(Regex.IsMatch(patch, @"(?m)^#define\s+PY_MAJOR_VERSION\s+3\s*$", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)) &&
                Regex.IsMatch(patch, @"(?m)^#define\s+PY_MINOR_VERSION\s+11\s*$", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)));
            return paths;
        }
        public static void Build(string windowsSource, string originalPython, string python, string state)
        {
            Need(prepared == null); PythonCsrDispatch.PreparedImage(python);
            string runtime = Path.GetDirectoryName(python), home = Path.GetDirectoryName(originalPython);
            NativeFixture.Plain(home); Need(Path.GetFileName(originalPython) == "python.exe");
            var version = FileVersionInfo.GetVersionInfo(originalPython);
            Need(version.FileMajorPart == 3 && version.FileMinorPart == 11 && !version.IsDebug);
            string library = Path.Combine(home, "libs", "python311.lib"); NativeFixture.Plain(library);
            using (var held = ModuleActivationFixture.Open(originalPython)) {
                byte[] bytes = ModuleActivationFixture.Read(held, 16777216);
                try { PythonCsrDispatch.RequireImage(python, bytes); } finally { Array.Clear(bytes, 0, bytes.Length); }
            }
            string source = Path.Combine(windowsSource, "RegistryLoader.c"), header = Path.Combine(state, "registry-loader-path.h");
            string obj = Path.Combine(state, "registry-loader.obj"), output = Path.Combine(runtime, "DLLs", Names[0]);
            string implib = Path.Combine(state, "registry-loader.lib"), exp = Path.Combine(state, "registry-loader.exp");
            foreach (string path in new [] { header, obj, output, implib, exp }) DefaultActivationFixture.Missing(path);
            DefaultActivationFixture.NoOverrides(output);
            byte[] sourceBytes = Read(source, 16384);
            string text = Utf8.GetString(sourceBytes).Replace("\r\n", "\n");
            Array.Clear(sourceBytes, 0, sourceBytes.Length);
            Need(ModuleActivationFixture.Digest(Utf8.GetBytes(text)) == "178ed6fdbfb8e3b67cd148bee642db97c5772d128f56ec7df1f8e683c747f362");
            byte[] generated = Utf8.GetBytes(Header(Path.Combine(runtime, "DLLs", "_ctypes.pyd")));
            using (ModuleActivationFixture.Create(header, generated)) { }
            var tools = NativeFixture.CompilerTools(state);
            string[] includes = Includes(tools, home);
            var arguments = new List<string> { "/nologo", "/c", "/TC", "/O2", "/GS-", "/Zl", "/Fo" + obj, "/I" + state };
            arguments.AddRange(includes.Select(path => "/I" + path)); arguments.Add(source);
            using (var heldSource = ModuleActivationFixture.Open(source))
            using (var heldHeader = ModuleActivationFixture.Open(header))
            using (var heldLibrary = ModuleActivationFixture.Open(library)) {
                byte[] actualSource = ModuleActivationFixture.Read(heldSource, 16384);
                byte[] actualHeader = ModuleActivationFixture.Read(heldHeader, 16384);
                try {
                    Need(Utf8.GetString(actualSource).Replace("\r\n", "\n") == text && actualHeader.SequenceEqual(generated));
                    TrustedSetup.Run(tools.Item1, arguments.ToArray(), state); NativeFixture.Plain(obj);
                    TrustedSetup.Run(tools.Item2, new [] { "/nologo", "/DLL", "/NOENTRY", "/NODEFAULTLIB", "/MANIFEST:NO", "/MACHINE:X64",
                        "/OUT:" + output, "/IMPLIB:" + implib, obj, tools.Item3, library }, state);
                } finally { Array.Clear(actualSource, 0, actualSource.Length); Array.Clear(actualHeader, 0, actualHeader.Length); }
            }
            var candidateHashes = new string[3]; var candidateLengths = new int[3];
            for (int index = 0; index < Names.Length; index++) {
                byte[] bytes = Read(Path.Combine(runtime, "DLLs", Names[index]), 16777216);
                try {
                    if (index == 0) KernelImage.QualifyRegistryLoader(bytes);
                    candidateHashes[index] = ModuleActivationFixture.Digest(bytes); candidateLengths[index] = bytes.Length;
                } finally { Array.Clear(bytes, 0, bytes.Length); }
            }
            prepared = python; hashes = candidateHashes; lengths = candidateLengths;
            Console.Out.WriteLine("WINDOWS_REGISTRY_LOADER prepared=True selected_images=3 helper_executed=False cause_claimed=False"); Console.Out.Flush();
        }
        internal static IDisposable Hold(string python)
        {
            Need(prepared != null && python == prepared); string runtime = Path.GetDirectoryName(python);
            var opens = new List<Func<IDisposable>> { () => PythonCsrDispatch.Hold(python) };
            opens.AddRange(Names.Select(name => (Func<IDisposable>)(() => ModuleActivationFixture.Open(Path.Combine(runtime, "DLLs", name)))));
            return ModuleActivationFixture.Acquire(opens.ToArray(), values => {
                for (int index = 0; index < Names.Length; index++) {
                    byte[] bytes = ModuleActivationFixture.Read((FileStream)values[index + 1], 16777216);
                    try {
                        Need(bytes.Length == lengths[index] && ModuleActivationFixture.Digest(bytes) == hashes[index]);
                        if (index == 0) KernelImage.QualifyRegistryLoader(bytes);
                    } finally { Array.Clear(bytes, 0, bytes.Length); }
                }
            });
        }
        public static void CheckValidation()
        {
            KernelImage.CheckRegistryLoaderValidation();
            Need(Header(@"C:\owned space\python\DLLs\_ctypes.pyd").StartsWith("static const wchar_t registry_loader_path[] = {67,58,92,111,119,110,101,100,32", StringComparison.Ordinal));
            Need(prepared == null && hashes == null && lengths == null);
        }
    }
}
