using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace ScientificSecurity
{
    public static partial class ChildActivationFixture
    {
        const string DllImage = "startup-dll-resource.exe";
        const string DllLabel = "WINDOWS_DLL_RESOURCE_ACTIVATION";
        const string DllSuccess = "WINDOWS_DLL_RESOURCE_ACTIVATION created=True win32_error=0x00000000 cause_claimed=False child_equivalence_claimed=False";
        sealed class DllIdentity {
            internal string python, dll, image, source, header, dllHash, payloadHash, imageHash, sourceHash, headerHash;
            internal long dllLength, payloadLength;
            internal ushort language;
        }
        static DllIdentity dllPrepared;
        static bool dllHostPositive;
        static void DllNeed(bool value)
        { if (!value) throw new InvalidOperationException("fixed DLL resource request contract failed"); }
        static void DllRefused(Action action)
        { bool refused = false; try { action(); } catch (InvalidOperationException) { refused = true; } DllNeed(refused); }

        public static void CheckDllValidation(string windowsSource)
        {
            const string denied = "WINDOWS_DLL_RESOURCE_ACTIVATION created=False win32_error=0x00000005 cause_claimed=False child_equivalence_claimed=False\n";
            string good = DllSuccess + "\n";
            DllNeed(DllResult(0, good, "") == DllSuccess && DllResult(0, denied, "") == denied.TrimEnd('\n'));
            foreach (string bad in new [] { "", good + good, good.TrimEnd('\n'), good.Replace("00000000", "00000005"),
                denied.Replace("00000005", "00000000"), denied.Replace("00000005", "ffffffff"), good.Replace("DLL_RESOURCE", "CHILD"),
                good.Replace("\n", "\r\n"), "private-sentinel", new string('x', 257) }) DllRefused(() => DllResult(0, bad, ""));
            foreach (uint exit in new uint[] { 1, 120, 121, 0xC0000022, UInt32.MaxValue }) DllRefused(() => DllResult(exit, good, ""));
            DllRefused(() => DllResult(0, good, "private-sentinel"));
            DllRefused(() => RequireResult(good)); DllRefused(() => DllResult(0,
                "WINDOWS_CHILD_ACTIVATION created=True win32_error=0x00000000 cause_claimed=False child_equivalence_claimed=False\n", ""));
            DllNeed(DllCondition("original", DllSuccess) == "WINDOWS_DLL_RESOURCE_ACTIVATION_CONDITION condition=original " + DllSuccess +
                " python_equivalence_claimed=False cause_claimed=False production_grant=False");
            DllRefused(() => DllCondition("private-sentinel", DllSuccess)); DllRefused(() => DllCondition("original", "private-sentinel"));
            string path = Path.Combine(Path.GetFullPath("."), "python", "python311.dll");
            string header = DllHeader(path, 1033);
            DllNeed(header == "static const unsigned short fixed_python[]={" + Numeric(path) + "};\n" +
                "static const unsigned short fixed_directory[]={" + Numeric(Path.GetDirectoryName(path)) + "};\n" +
                "static const unsigned short fixed_language=1033;\n");
            bool rejected = false; try { DllHeader(Path.ChangeExtension(path, ".exe"), 1033); } catch (ArgumentException) { rejected = true; } DllNeed(rejected);
            using (FileStream held = ModuleActivationFixture.Open(Path.Combine(Path.GetFullPath(windowsSource), "StartupActivationNative.c"))) {
                byte[] original = Read(held, 65536), generated = null;
                try {
                    string text = Utf8.GetString(original).Replace("\r\n", "\n"); generated = DllSource(text);
                    string source = Utf8.GetString(generated);
                    DllNeed(source == text.Replace("context.resource = (const WORD *)1;", "context.resource = (const WORD *)2;")
                        .Replace("WINDOWS_CHILD_ACTIVATION", "WINDOWS_DLL_RESOURCE_ACTIVATION"));
                    DllNeed(source.Contains("context.flags = 0x2E;") && source.Contains("context.source = fixed_python;") &&
                        source.Contains("context.application = fixed_python;") && source.Contains("context.module = 0;") &&
                        source.Contains("sizeof(FixedActCtx) == 56") && source.Contains("OFFSET(module) == 48"));
                    DllRefused(() => DllSource(text + " "));
                    foreach (string literal in new [] { "context.resource = (const WORD *)1;", "WINDOWS_CHILD_ACTIVATION" }) {
                        DllRefused(() => DllReplace("unrelated", literal, "fixed"));
                        DllRefused(() => DllReplace(literal + literal, literal, "fixed"));
                    }
                } finally { Array.Clear(original, 0, original.Length); if (generated != null) Array.Clear(generated, 0, generated.Length); }
            }
            foreach (int mode in new [] { 0, 1, 2, 3, 4 }) {
                int runs = 0, closes = 0, accepts = 0; Exception caught = null;
                var operation = new IOException("fixed DLL operation"); var close = new IOException("fixed DLL close");
                try { CompleteDllHost(() => { runs++; if (mode == 1 || mode == 4) throw operation; return mode == 2 ? denied.TrimEnd('\n') : DllSuccess; },
                    () => { closes++; if (mode == 3 || mode == 4) throw close; }, () => accepts++); }
                catch (Exception failure) { caught = failure; }
                DllNeed(runs == 1 && closes == 1 && accepts == (mode == 0 ? 1 : 0) && (mode == 0 ? caught == null : caught != null));
                if (mode == 1) DllNeed(Object.ReferenceEquals(caught, operation));
                if (mode == 3) DllNeed(Object.ReferenceEquals(caught, close));
                if (mode == 4) { var group = caught as AggregateException; DllNeed(group != null && group.InnerExceptions.Count == 2 &&
                    Object.ReferenceEquals(group.InnerExceptions[0], operation) && Object.ReferenceEquals(group.InnerExceptions[1], close)); }
            }
            DllRefused(() => RequireDllPositive(false)); RequireDllPositive(true);
            DllRefused(() => RequireDllRole(true, true)); DllRefused(() => RequireDllRole(false, false)); RequireDllRole(true, false);
        }
        static string DllReplace(string text, string before, string after)
        {
            int at = text.IndexOf(before, StringComparison.Ordinal);
            DllNeed(at >= 0 && text.IndexOf(before, at + before.Length, StringComparison.Ordinal) < 0);
            return text.Substring(0, at) + after + text.Substring(at + before.Length);
        }
        static byte[] DllSource(string text)
        {
            DllNeed(text.IndexOf('\r') < 0 && Digest(Utf8.GetBytes(text)) == SourceDigest);
            text = DllReplace(text, "context.resource = (const WORD *)1;", "context.resource = (const WORD *)2;");
            return Utf8.GetBytes(DllReplace(text, "WINDOWS_CHILD_ACTIVATION", DllLabel));
        }
        static string DllHeader(string dll, ushort language)
        {
            if (!Path.IsPathFullyQualified(dll) || Path.GetFullPath(dll) != dll || Path.GetFileName(dll) != "python311.dll")
                throw new ArgumentException("DLL request requires canonical prepared sibling DLL");
            return "static const unsigned short fixed_python[]={" + Numeric(dll) + "};\n" +
                "static const unsigned short fixed_directory[]={" + Numeric(Path.GetDirectoryName(dll)) + "};\n" +
                "static const unsigned short fixed_language=" + language.ToString(CultureInfo.InvariantCulture) + ";\n";
        }
        internal static void RequireDllRole(bool preflight, params bool[] others)
        { DllNeed(preflight && !others.Any(value => value)); }
        internal static string DllResult(uint exit, string text, string errors)
        {
            DllNeed(exit == 0 && text != null && text.Length <= 256 && errors != null && errors.Length == 0);
            var match = Regex.Match(text, "\\AWINDOWS_DLL_RESOURCE_ACTIVATION created=(True|False) win32_error=0x([0-9A-F]{8}) cause_claimed=False child_equivalence_claimed=False\\n\\z",
                RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
            DllNeed(match.Success);
            uint error = UInt32.Parse(match.Groups[2].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            DllNeed((match.Groups[1].Value == "True") == (error == 0));
            return text.TrimEnd('\n');
        }
        internal static string DllCondition(string condition, string result)
        {
            DllNeed(condition == "original" || condition == "modified" || condition == "restored");
            DllNeed(result != null && result.Length < 256 && DllResult(0, result + "\n", "") == result);
            return DllLabel + "_CONDITION condition=" + condition + " " + result +
                " python_equivalence_claimed=False cause_claimed=False production_grant=False";
        }
        public static void BuildDllRequest(string windowsSource, string python, string state)
        {
            DllNeed(dllPrepared == null); python = Path.GetFullPath(python); state = Path.GetFullPath(state);
            DllNeed(Path.GetFileName(python) == "python.exe" && Path.GetDirectoryName(python) == Path.Combine(state, "python"));
            string dll = Path.Combine(Path.GetDirectoryName(python), "python311.dll"), image = Path.Combine(Path.GetDirectoryName(python), DllImage);
            string original = Path.Combine(Path.GetFullPath(windowsSource), "StartupActivationNative.c");
            NativeFixture.Plain(state); NoOverrides(dll); NoOverrides(image);
            // The unchanged include name needs a separate exclusive build directory for this role.
            string directory = Path.Combine(state, "dll-resource-build"); RequireMissing(directory); Directory.CreateDirectory(directory);
            string generated = Path.Combine(directory, "startup-dll-resource.c"), header = Path.Combine(directory, "startup-activation-input.h"), obj = Path.Combine(directory, "startup-dll-resource.obj");
            foreach (string path in new [] { generated, header, obj, image }) RequireMissing(path);
            var held = new List<IDisposable>(); var buffers = new List<byte[]>(); Exception primary = null; DllIdentity candidate = null;
            try {
                FileStream source = ModuleActivationFixture.Open(original); held.Add(source); byte[] originalBytes = Read(source, 65536); buffers.Add(originalBytes);
                byte[] generatedBytes = DllSource(Utf8.GetString(originalBytes).Replace("\r\n", "\n")); buffers.Add(generatedBytes);
                FileStream input = ModuleActivationFixture.Open(dll); held.Add(input); byte[] dllBytes = Read(input, 16777216); buffers.Add(dllBytes);
                var manifest = KernelImage.ModuleManifest(dllBytes, false); byte[] payload = manifest.Item2; buffers.Add(payload);
                byte[] headerBytes = Utf8.GetBytes(DllHeader(dll, manifest.Item1)); buffers.Add(headerBytes);
                FileStream fixedSource = New(generated, generatedBytes); held.Add(fixedSource); FileStream fixedHeader = New(header, headerBytes); held.Add(fixedHeader);
                var tools = NativeFixture.CompilerTools(state);
                TrustedSetup.Run(tools.Item1, new [] { "/nologo", "/c", "/TC", "/Od", "/Oi", "/GS-", "/Zl", "/Fo" + obj, generated }, directory);
                FileStream objectFile = ModuleActivationFixture.Open(obj); held.Add(objectFile); byte[] objectBytes = Read(objectFile, 1048576); buffers.Add(objectBytes);
                TrustedSetup.Run(tools.Item2, new [] { "/nologo", "/NODEFAULTLIB", "/MANIFEST:NO", "/ENTRY:StartupEntry", "/SUBSYSTEM:CONSOLE", "/MACHINE:X64", "/OUT:" + image, obj, tools.Item3 }, directory);
                FileStream output = ModuleActivationFixture.Open(image); held.Add(output); byte[] executable = Read(output, 1048576); buffers.Add(executable);
                KernelImage.QualifyChildActivation(executable); NoOverrides(dll); NoOverrides(image);
                ModuleActivationFixture.Same(source, originalBytes); ModuleActivationFixture.Same(fixedSource, generatedBytes);
                ModuleActivationFixture.Same(fixedHeader, headerBytes); ModuleActivationFixture.Same(objectFile, objectBytes);
                byte[] after = Read(input, 16777216); buffers.Add(after); DllNeed(after.SequenceEqual(dllBytes));
                candidate = new DllIdentity { python = python, dll = dll, image = image, source = generated, header = header,
                    dllHash = Digest(dllBytes), dllLength = dllBytes.Length, language = manifest.Item1, payloadHash = Digest(payload), payloadLength = payload.Length,
                    imageHash = Digest(executable), sourceHash = Digest(generatedBytes), headerHash = Digest(headerBytes) };
            } catch (Exception error) { primary = error; throw; }
            finally { ModuleActivationFixture.Finish(primary, held, buffers); }
            DllNeed(candidate != null); dllPrepared = candidate;
        }
        internal static string DllPreparedImage(string python)
        { DllNeed(dllPrepared != null && python == dllPrepared.python); return dllPrepared.image; }
        internal static IDisposable HoldDllRequest(string python)
        {
            DllPreparedImage(python); NoOverrides(dllPrepared.dll); NoOverrides(dllPrepared.image);
            var paths = new [] { dllPrepared.dll, dllPrepared.source, dllPrepared.header, dllPrepared.image };
            return ModuleActivationFixture.Acquire(paths.Select(path => (Func<IDisposable>)(() => ModuleActivationFixture.Open(path))).ToArray(), resources => {
                var buffers = new List<byte[]>();
                try {
                    for (int index = 0; index < 4; index++) buffers.Add(Read((FileStream)resources[index], index == 0 ? 16777216 : index == 3 ? 1048576 : 65536));
                    RequireIdentity(buffers[0], dllPrepared.dllLength, dllPrepared.dllHash);
                    var manifest = KernelImage.ModuleManifest(buffers[0], false); buffers.Add(manifest.Item2);
                    DllNeed(manifest.Item1 == dllPrepared.language && manifest.Item2.Length == dllPrepared.payloadLength && Digest(manifest.Item2) == dllPrepared.payloadHash);
                    DllNeed(Digest(buffers[1]) == dllPrepared.sourceHash && Digest(buffers[2]) == dllPrepared.headerHash && Digest(buffers[3]) == dllPrepared.imageHash);
                    KernelImage.QualifyChildActivation(buffers[3]); NoOverrides(dllPrepared.dll); NoOverrides(dllPrepared.image);
                } finally { foreach (byte[] buffer in buffers) Array.Clear(buffer, 0, buffer.Length); }
            });
        }
        static void CompleteDllHost(Func<string> run, Action close, Action accept)
        {
            Exception primary = null;
            try { DllNeed(run() == DllSuccess); }
            catch (Exception error) { primary = error; throw; }
            finally { try { close(); } catch (Exception cleanup) {
                if (primary != null) throw new AggregateException("fixed DLL host operation/lease cleanup failed", primary, cleanup); throw;
            } }
            accept();
        }
        static void RequireDllPositive(bool value) { DllNeed(value); }
        internal static void RequireDllHostPositive(string python)
        { DllPreparedImage(python); RequireDllPositive(dllHostPositive); }
        public static void RunDllHost(string python)
        {
            DllNeed(!dllHostPositive); IDisposable lease = HoldDllRequest(python);
            CompleteDllHost(() => TrustedSetup.RunDllRequest(python), lease.Dispose, () => {
                Console.Out.WriteLine("WINDOWS_DLL_RESOURCE_HOST positive=True cleanup_complete=True python_equivalence_claimed=False cause_claimed=False");
                Console.Out.Flush(); dllHostPositive = true;
            });
        }
    }
}
