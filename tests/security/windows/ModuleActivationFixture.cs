using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace ScientificSecurity
{
    // Two fixed immutable pairs; module association is not active-at-entry or Python causality.
    public static class ModuleActivationFixture
    {
        const string Host = "startup-module.exe", Dll = "startup-module.dll";
        const string SourceHash = "71c149943424c9ebe482b40b75b785a2eec85bcdca0870f8ac3f0e2154193f74";
        static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
        sealed class Identity {
            internal string python, sourceDll, sourceHash, payloadHash;
            internal long sourceLength, payloadLength;
            internal ushort language;
            internal string[] hosts, dlls, hashes;
        }
        static Identity prepared;
        static void Need(bool value)
        { if (!value) throw new InvalidOperationException("fixed module activation contract failed"); }
        internal static void RequireRole(bool preflight, params bool[] others)
        { if (!preflight || others.Length != 8 || others.Any(value => value)) throw new ArgumentException("module activation is a separate fixed trusted diagnostic"); }
        static string Label(bool manifest) { return manifest ? "module-id2" : "module-plain"; }
        static string Script(ushort language)
        { return "LANGUAGE " + (language & 1023).ToString(CultureInfo.InvariantCulture) + "," + (language >> 10).ToString(CultureInfo.InvariantCulture) + "\n2 24 \"module-activation-payload.bin\"\n"; }
        internal static string Result(bool manifest, uint exit, string text, string errors)
        {
            Need(text != null && errors != null && errors.Length == 0);
            if (exit != 0) {
                Need(manifest && (exit & 0x80000000) != 0 && text.Length == 0);
                return "entry_observed=False association_proved=False exit=0x" + exit.ToString("X8", CultureInfo.InvariantCulture);
            }
            Match match = Regex.Match(text, @"\AWINDOWS_MODULE_ACTIVATION attach=1 query_succeeded=([01]) root_evaluated=([01]) root_is_module=([01]) win32_error=0x([0-9A-F]{8}) returned_bytes=0x([0-9A-F]{8}) assembly_count=0x([0-9A-F]{8})\n\z", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
            Need(match.Success);
            bool query = match.Groups[1].Value == "1", evaluated = match.Groups[2].Value == "1", own = match.Groups[3].Value == "1";
            uint error = UInt32.Parse(match.Groups[4].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            uint returned = UInt32.Parse(match.Groups[5].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            uint assemblies = UInt32.Parse(match.Groups[6].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            Need(returned <= 65536 && assemblies <= 16 && (!own || evaluated) && (!evaluated || query && assemblies >= 1));
            Need(query ? error == 0 && returned >= 64 : error != 0 && !evaluated && !own && assemblies == 0);
            Need(!manifest || query && evaluated && own);
            return "entry_observed=True association_proved=" + own + " exit=0x00000000 " + text.TrimEnd('\n');
        }
        internal static string Condition(string condition, bool manifest, string result)
        {
            Need(condition == "original" || condition == "modified" || condition == "restored");
            const string success = "entry_observed=True association_proved=";
            const string absent = "entry_observed=False association_proved=False exit=0x";
            Need(result != null && result.Length <= 512);
            bool qualified = false;
            if (result.StartsWith(success, StringComparison.Ordinal)) {
                foreach (string value in new [] { "True", "False" }) {
                    string prefix = success + value + " exit=0x00000000 ";
                    if (result.StartsWith(prefix, StringComparison.Ordinal)) qualified = Result(manifest, 0, result.Substring(prefix.Length) + "\n", "") == result;
                }
            } else if (result.StartsWith(absent, StringComparison.Ordinal) && result.Length == absent.Length + 8) {
                uint exit; qualified = UInt32.TryParse(result.Substring(absent.Length), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out exit) && Result(manifest, exit, "", "") == result;
            }
            Need(qualified);
            return "WINDOWS_MODULE_CONDITION condition=" + condition + " pair=" + Label(manifest) + " " + result +
                " active_at_entry_claimed=False python_equivalence_claimed=False cause_claimed=False";
        }
        static void Refused(Action action)
        { bool refused = false; try { action(); } catch (InvalidOperationException) { refused = true; } Need(refused); }
        public static void CheckValidation(string work)
        {
            RequireRole(true, new bool[8]);
            for (int index = 0; index < 9; index++) {
                bool[] flags = new bool[8]; if (index != 8) flags[index] = true; bool refused = false;
                try { RequireRole(index != 8, flags); } catch (ArgumentException) { refused = true; } Need(refused);
            }
            Need(Script(1033) == "LANGUAGE 9,1\n2 24 \"module-activation-payload.bin\"\n");
            const string good = "WINDOWS_MODULE_ACTIVATION attach=1 query_succeeded=1 root_evaluated=1 root_is_module=1 win32_error=0x00000000 returned_bytes=0x00000080 assembly_count=0x00000003\n";
            const string failure = "WINDOWS_MODULE_ACTIVATION attach=1 query_succeeded=0 root_evaluated=0 root_is_module=0 win32_error=0x00000057 returned_bytes=0x00000000 assembly_count=0x00000000\n";
            Need(Result(true, 0, good, "").Contains("association_proved=True"));
            Need(Result(false, 0, failure, "").Contains("association_proved=False"));
            Need(Result(true, 0xC0150002, "", "") == "entry_observed=False association_proved=False exit=0xC0150002");
            Need(RequireUnentered(Result(true, 0xC0150002, "", "")) == 0xC0150002);
            Need(CompareCallback(0xC0150002, 0xC0150002, "", "") == "WINDOWS_MODULE_CALLBACK returned_exit_equal=True observation_only=True cause_claimed=False");
            Refused(() => RequireUnentered(Result(true, 0, good, "")));
            foreach (uint code in new uint[] { 0, 1, 0xC0000022 })
                Refused(() => CompareCallback(0xC0150002, code, "", ""));
            Refused(() => CompareCallback(0xC0150002, 0xC0150002, good, ""));
            Refused(() => CompareCallback(0xC0150002, 0xC0150002, "", "private-sentinel"));
            Refused(() => Result(false, 0xC0150002, "", "")); Refused(() => Result(true, 0, failure, ""));
            foreach (string bad in new [] { good + good, good.TrimEnd('\n'), good.Replace("attach=1", "attach=0"), good.Replace("root_is_module=1", "root_is_module=0"),
                good.Replace("00000080", "00010001"), good.Replace("00000003", "00000011"), good.Replace("00000000", "00000005"),
                good.Replace("query_succeeded=1", "query_succeeded=0"), good.Replace("root_evaluated=1", "root_evaluated=0"), "private-sentinel" })
                Refused(() => Result(true, 0, bad, ""));
            foreach (uint code in new uint[] { 1, 121, 0x7FFFFFFF, 0xC0000022 }) Refused(() => Result(true, code, good, ""));
            Refused(() => Result(true, 0, good, "private-sentinel"));
            Refused(() => Condition("private-sentinel", true, Result(true, 0, good, "")));
            Need(Condition("original", true, Result(true, 0, good, "")).EndsWith("active_at_entry_claimed=False python_equivalence_claimed=False cause_claimed=False", StringComparison.Ordinal));
            CheckLease();
            string directory = Path.Combine(Path.GetFullPath(work), "module-activation-validation-" + Guid.NewGuid().ToString("N"));
            DefaultActivationFixture.Missing(directory); Directory.CreateDirectory(directory);
            try {
                string path = Path.Combine(directory, "owned.bin"); byte[] original = { 1, 2, 3 };
                using (Create(path, original)) { }
                Refused(() => { using (Create(path, new byte[] { 9 })) { } }); Need(File.ReadAllBytes(path).SequenceEqual(original));
                string image = Path.Combine(directory, Host), sidecar = image + ".config";
                File.WriteAllText(sidecar, "unchanged", Utf8); Refused(() => DefaultActivationFixture.NoOverrides(image));
                Need(File.ReadAllText(sidecar, Utf8) == "unchanged"); File.Delete(sidecar);
                Directory.CreateSymbolicLink(sidecar, Path.Combine(directory, "absent"));
                Refused(() => DefaultActivationFixture.NoOverrides(image)); Need((File.GetAttributes(sidecar) & FileAttributes.ReparsePoint) != 0); Directory.Delete(sidecar);
            } finally { Directory.Delete(directory, true); }
        }
        static void CheckLease()
        {
            var order = new List<string>(); var operation = new IOException("fixed acquisition");
            var cleanup = new IOException("fixed close");
            var first = new CheckResource("first", order, cleanup); var last = new CheckResource("last", order, cleanup);
            AggregateException caught = null;
            try { Acquire(new Func<IDisposable>[] { () => first, () => last, () => { throw operation; } }, _ => { }); }
            catch (AggregateException error) { caught = error; }
            Need(caught != null && Object.ReferenceEquals(caught.InnerExceptions[0], operation) && caught.InnerExceptions.Count == 3 && String.Join(",", order) == "last,first");
            order.Clear(); var a = new CheckResource("a", order, null); var b = new CheckResource("b", order, null);
            IDisposable lease = Acquire(new Func<IDisposable>[] { () => a, () => b }, values => Need(values.Count == 2));
            Need(order.Count == 0); lease.Dispose(); lease.Dispose(); Need(String.Join(",", order) == "b,a");
            order.Clear(); caught = null;
            try { Acquire(new Func<IDisposable>[] { () => new CheckResource("qualified", order, cleanup) }, _ => { throw operation; }); }
            catch (AggregateException error) { caught = error; }
            Need(caught != null && caught.InnerExceptions.Count == 2 && Object.ReferenceEquals(caught.InnerExceptions[0], operation) && String.Join(",", order) == "qualified");
        }
        sealed class CheckResource : IDisposable {
            readonly string name; readonly List<string> order; readonly Exception failure;
            internal CheckResource(string name, List<string> order, Exception failure) { this.name = name; this.order = order; this.failure = failure; }
            public void Dispose() { order.Add(name); if (failure != null) throw failure; }
        }
        internal static byte[] Read(FileStream stream, int maximum)
        {
            Need(stream.Length > 0 && stream.Length <= maximum); stream.Position = 0;
            byte[] bytes = new byte[(int)stream.Length]; int position = 0;
            try {
                while (position < bytes.Length) { int count = stream.Read(bytes, position, bytes.Length - position); Need(count > 0); position += count; }
                Need(stream.ReadByte() == -1); return bytes;
            } catch { Array.Clear(bytes, 0, bytes.Length); throw; }
        }
        internal static string Digest(byte[] bytes)
        { using (var hash = SHA256.Create()) return BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant(); }
        internal static void Same(FileStream stream, byte[] expected)
        { byte[] actual = Read(stream, 1048576); try { Need(actual.SequenceEqual(expected)); } finally { Array.Clear(actual, 0, actual.Length); } }
        internal static FileStream Open(string path) { NativeFixture.Plain(path); return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read); }
        internal static FileStream Create(string path, byte[] bytes)
        {
            DefaultActivationFixture.Missing(path);
            using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None)) { output.Write(bytes, 0, bytes.Length); output.Flush(true); Same(output, bytes); }
            FileStream held = Open(path); try { Same(held, bytes); return held; } catch { held.Dispose(); throw; }
        }
        public static void Build(string windowsSource, string python, string state)
        {
            Need(prepared == null); python = Path.GetFullPath(python); state = Path.GetFullPath(state); windowsSource = Path.GetFullPath(windowsSource);
            Need(Path.GetFileName(python) == "python.exe" && Path.GetDirectoryName(python) == Path.Combine(state, "python"));
            string runtime = Path.GetDirectoryName(python), sourceDll = Path.Combine(runtime, "python311.dll");
            string sourcePath = Path.Combine(windowsSource, "StartupModuleActivation.c"), source = Path.Combine(state, "module-activation.c");
            string hostObject = Path.Combine(state, "module-host.obj"), dllObject = Path.Combine(state, "module-dll.obj");
            string payloadPath = Path.Combine(state, "module-activation-payload.bin"), script = Path.Combine(state, "module-activation.rc"), resource = Path.Combine(state, "module-activation.res");
            string[] hosts = new string[2], dlls = new string[2], libraries = new string[2];
            NativeFixture.Plain(runtime); NativeFixture.Plain(state); DefaultActivationFixture.NoOverrides(sourceDll);
            foreach (string path in new [] { source, hostObject, dllObject, payloadPath, script, resource }) DefaultActivationFixture.Missing(path);
            for (int index = 0; index < 2; index++) {
                string directory = Path.Combine(runtime, Label(index == 1)); DefaultActivationFixture.Missing(directory);
                hosts[index] = Path.Combine(directory, Host); dlls[index] = Path.Combine(directory, Dll); libraries[index] = Path.Combine(state, "module-" + index + ".lib");
                foreach (string path in new [] { hosts[index], dlls[index], libraries[index], Path.ChangeExtension(libraries[index], ".exp") }) DefaultActivationFixture.Missing(path);
                DefaultActivationFixture.NoOverrides(hosts[index]); DefaultActivationFixture.NoOverrides(dlls[index]);
            }
            var held = new List<IDisposable>(); var buffers = new List<byte[]>(); Exception primary = null; Identity candidate = null;
            try {
                FileStream originalSource = Open(sourcePath); held.Add(originalSource); byte[] originalSourceBytes = Read(originalSource, 65536); buffers.Add(originalSourceBytes);
                string sourceText = Utf8.GetString(originalSourceBytes).Replace("\r\n", "\n"); Need(sourceText.IndexOf('\r') < 0);
                byte[] sourceBytes = Utf8.GetBytes(sourceText); buffers.Add(sourceBytes); Need(Digest(sourceBytes) == SourceHash);
                FileStream originalDll = Open(sourceDll); held.Add(originalDll); byte[] dllBytes = Read(originalDll, 16777216); buffers.Add(dllBytes);
                var manifest = KernelImage.ModuleManifest(dllBytes, false); byte[] payload = manifest.Item2; buffers.Add(payload);
                FileStream heldSource = Create(source, sourceBytes); held.Add(heldSource);
                FileStream heldPayload = Create(payloadPath, payload); held.Add(heldPayload);
                byte[] scriptBytes = Utf8.GetBytes(Script(manifest.Item1)); buffers.Add(scriptBytes); FileStream heldScript = Create(script, scriptBytes); held.Add(heldScript);
                for (int index = 0; index < 2; index++) Directory.CreateDirectory(Path.GetDirectoryName(hosts[index]));
                var tools = NativeFixture.CompilerTools(state); string rc = DefaultActivationFixture.ResourceCompiler(tools.Item3); NativeFixture.Plain(rc);
                TrustedSetup.Run(tools.Item1, new [] { "/nologo", "/c", "/TC", "/Od", "/Oi-", "/GS-", "/Zl", "/Fo" + hostObject, source }, state);
                TrustedSetup.Run(tools.Item1, new [] { "/nologo", "/c", "/TC", "/Od", "/Oi-", "/GS-", "/Zl", "/DMODULE_DLL", "/Fo" + dllObject, source }, state);
                NativeFixture.Plain(hostObject); NativeFixture.Plain(dllObject);
                FileStream heldHostObject = Open(hostObject); held.Add(heldHostObject); byte[] hostObjectBytes = Read(heldHostObject, 1048576); buffers.Add(hostObjectBytes);
                FileStream heldDllObject = Open(dllObject); held.Add(heldDllObject); byte[] dllObjectBytes = Read(heldDllObject, 1048576); buffers.Add(dllObjectBytes);
                TrustedSetup.Run(rc, new [] { "/nologo", "/x", "/fo", resource, script }, state);
                FileStream heldResource = Open(resource); held.Add(heldResource); byte[] resourceBytes = Read(heldResource, 131072); buffers.Add(resourceBytes);
                for (int index = 0; index < 2; index++) {
                    var args = new List<string> { "/nologo", "/DLL", "/NODEFAULTLIB", "/MANIFEST:NO", "/ENTRY:ModuleEntry", "/SUBSYSTEM:CONSOLE", "/MACHINE:X64", "/OUT:" + dlls[index], "/IMPLIB:" + libraries[index], dllObject };
                    if (index == 1) args.Add(resource); args.Add(tools.Item3); TrustedSetup.Run(tools.Item2, args.ToArray(), state);
                }
                FileStream heldLibrary = Open(libraries[0]); held.Add(heldLibrary); byte[] libraryBytes = Read(heldLibrary, 131072); buffers.Add(libraryBytes);
                TrustedSetup.Run(tools.Item2, new [] { "/nologo", "/NODEFAULTLIB", "/MANIFEST:NO", "/ENTRY:StartupEntry", "/SUBSYSTEM:CONSOLE", "/MACHINE:X64", "/OUT:" + hosts[0], hostObject, libraries[0], tools.Item3 }, state);
                FileStream firstHost = Open(hosts[0]); held.Add(firstHost); byte[] hostBytes = Read(firstHost, 1048576); buffers.Add(hostBytes);
                held.Add(Create(hosts[1], hostBytes));
                var hashes = new List<string>();
                for (int index = 0; index < 2; index++) {
                    DefaultActivationFixture.NoOverrides(hosts[index]); DefaultActivationFixture.NoOverrides(dlls[index]);
                    FileStream host = Open(hosts[index]); held.Add(host); FileStream dll = Open(dlls[index]); held.Add(dll);
                    byte[] actualHost = Read(host, 1048576); buffers.Add(actualHost); byte[] actualDll = Read(dll, 1048576); buffers.Add(actualDll);
                    Need(actualHost.SequenceEqual(hostBytes)); KernelImage.QualifyModuleActivation(actualHost, false, false, manifest.Item1, payload);
                    KernelImage.QualifyModuleActivation(actualDll, true, index == 1, manifest.Item1, payload); hashes.Add(Digest(actualHost)); hashes.Add(Digest(actualDll));
                }
                Same(originalSource, originalSourceBytes); Same(heldSource, sourceBytes); Same(heldPayload, payload); Same(heldScript, scriptBytes);
                Same(heldHostObject, hostObjectBytes); Same(heldDllObject, dllObjectBytes); Same(heldResource, resourceBytes); Same(heldLibrary, libraryBytes);
                byte[] sourceAfter = Read(originalDll, 16777216); buffers.Add(sourceAfter); Need(sourceAfter.SequenceEqual(dllBytes));
                candidate = new Identity { python = python, sourceDll = sourceDll, sourceHash = Digest(dllBytes), sourceLength = dllBytes.Length,
                    payloadHash = Digest(payload), payloadLength = payload.Length, language = manifest.Item1, hosts = hosts, dlls = dlls, hashes = hashes.ToArray() };
            } catch (Exception error) { primary = error; throw; }
            finally { Finish(primary, held, buffers); }
            Need(candidate != null); prepared = candidate;
        }
        internal static string PreparedImage(string python, bool manifest)
        { Need(prepared != null && python == prepared.python); return prepared.hosts[manifest ? 1 : 0]; }
        internal static uint RequireUnentered(string result)
        {
            Condition("modified", true, result);
            const string prefix = "entry_observed=False association_proved=False exit=0x";
            Need(result.StartsWith(prefix, StringComparison.Ordinal) && result.Length == prefix.Length + 8);
            uint code = UInt32.Parse(result.Substring(prefix.Length), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            Need((code & 0x80000000) != 0); return code;
        }
        internal static string CompareCallback(uint expected, uint actual, string text, string errors)
        {
            Need((expected & 0x80000000) != 0 && expected == actual);
            string result = Result(true, actual, text, errors); RequireUnentered(result);
            return "WINDOWS_MODULE_CALLBACK returned_exit_equal=True observation_only=True cause_claimed=False";
        }
        internal static ActivationBoundaryTrace Observer(Native.ProcessInfo child, Action<string> emit)
        {
            Need(prepared != null);
            return new ActivationBoundaryTrace(child.process, child.thread, child.pid, child.tid,
                prepared.hosts[1], prepared.hashes[2], emit, true);
        }
        internal static IDisposable Hold(string python, bool manifest)
        {
            string image = PreparedImage(python, manifest); int index = manifest ? 1 : 0;
            var paths = new [] { prepared.sourceDll, image, prepared.dlls[index] };
            foreach (string path in paths) { NativeFixture.Plain(path); DefaultActivationFixture.NoOverrides(path); }
            return Acquire(paths.Select(path => (Func<IDisposable>)(() => Open(path))).ToArray(), resources => {
                byte[] source = null, payload = null, host = null, dll = null;
                try {
                    source = Read((FileStream)resources[0], 16777216); Need(source.Length == prepared.sourceLength && Digest(source) == prepared.sourceHash);
                    var metadata = KernelImage.ModuleManifest(source, false); payload = metadata.Item2;
                    Need(metadata.Item1 == prepared.language && payload.Length == prepared.payloadLength && Digest(payload) == prepared.payloadHash);
                    host = Read((FileStream)resources[1], 1048576); dll = Read((FileStream)resources[2], 1048576);
                    Need(Digest(host) == prepared.hashes[index * 2] && Digest(dll) == prepared.hashes[index * 2 + 1]);
                    KernelImage.QualifyModuleActivation(host, false, false, prepared.language, payload); KernelImage.QualifyModuleActivation(dll, true, manifest, prepared.language, payload);
                } finally { foreach (byte[] bytes in new [] { source, payload, host, dll }) if (bytes != null) Array.Clear(bytes, 0, bytes.Length); }
            });
        }
        internal static IDisposable Acquire(Func<IDisposable>[] opens, Action<List<IDisposable>> qualify)
        {
            var held = new List<IDisposable>(); Exception primary = null;
            try { foreach (var open in opens) held.Add(open()); qualify(held); var lease = new Lease(held); held = null; return lease; }
            catch (Exception error) { primary = error; throw; }
            finally { if (held != null) Finish(primary, held, new List<byte[]>()); }
        }
        internal static void Finish(Exception primary, List<IDisposable> held, List<byte[]> buffers)
        {
            var failures = new List<Exception>();
            for (int index = held.Count - 1; index >= 0; index--) try { held[index].Dispose(); } catch (Exception error) { failures.Add(error); }
            foreach (byte[] bytes in buffers) try { Array.Clear(bytes, 0, bytes.Length); } catch (Exception error) { failures.Add(error); }
            if (failures.Count != 0) { if (primary != null) failures.Insert(0, primary); throw new AggregateException("fixed module activation operation/cleanup failed", failures); }
        }
        sealed class Lease : IDisposable {
            List<IDisposable> held;
            internal Lease(List<IDisposable> held) { this.held = held; }
            public void Dispose() { var owned = held; held = null; if (owned != null) Finish(null, owned, new List<byte[]>()); }
        }
    }
}
