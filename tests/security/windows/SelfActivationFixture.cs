using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using static ScientificSecurity.ModuleActivationFixture;

namespace ScientificSecurity
{
    // A documented own-EXE call, not an equivalent of the automatic DLL callback.
    public static class SelfActivationFixture
    {
        const string Image = "startup-self-activation.exe";
        const string SourceHash = "d6a12cdd2c9ef78e29c5c43af7527f4d74260a01ca15475b3ad83e6bcc49ca3e";
        const string Success = "WINDOWS_SELF_ACTIVATION entry_reached=True created=True win32_error=0x00000000\n";
        static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
        sealed class Identity {
            internal string python, source, sourceHash, dll, dllHash, payloadHash, image, imageHash;
            internal long sourceLength, dllLength, payloadLength, imageLength;
            internal ushort language;
            internal bool hostPositive;
        }
        static Identity prepared;
        static void Need(bool value)
        { if (!value) throw new InvalidOperationException("fixed self activation contract failed"); }
        internal static void RequireRole(bool preflight, params bool[] others)
        { if (!preflight || others.Length != 9 || others.Any(value => value)) throw new ArgumentException("self activation is a separate fixed undebugged trusted diagnostic"); }
        static string Script(ushort language)
        { return "LANGUAGE " + (language & 1023).ToString(CultureInfo.InvariantCulture) + "," + (language >> 10).ToString(CultureInfo.InvariantCulture) + "\n2 24 \"self-activation-payload.bin\"\n"; }
        internal static string Result(uint exit, string text, string errors)
        { return Result(exit, text, errors, line => { Console.Out.WriteLine(line); Console.Out.Flush(); }); }
        static void RequireResult(bool valid, string stage, uint exit, string text, string errors, Action<string> emit)
        {
            if (valid) return;
            var primary = new InvalidOperationException("fixed self activation contract failed");
            try {
                emit("WINDOWS_SELF_ACTIVATION_REFUSAL stage=" + stage + " raw_process_exit=0x" + exit.ToString("X8", CultureInfo.InvariantCulture) +
                    " stdout_chars=" + (text == null ? -1 : text.Length).ToString(CultureInfo.InvariantCulture) + " stderr_present=" + (errors != null && errors.Length != 0));
            } catch (Exception reporting) { throw new AggregateException("fixed self activation refusal/reporting failed", primary, reporting); }
            throw primary;
        }
        static string Result(uint exit, string text, string errors, Action<string> emit)
        {
            RequireResult(exit == 0 && text != null && text.Length <= 128 && errors != null && errors.Length == 0, "transport", exit, text, errors, emit);
            var match = Regex.Match(text, @"\AWINDOWS_SELF_ACTIVATION entry_reached=True created=(True|False) win32_error=0x([0-9A-F]{8})\n\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
            RequireResult(match.Success, "grammar", exit, text, errors, emit);
            uint error = UInt32.Parse(match.Groups[2].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            RequireResult((match.Groups[1].Value == "True") == (error == 0), "consistency", exit, text, errors, emit);
            return text.TrimEnd('\n');
        }
        static void CheckResultRefusal()
        {
            int reports = 0;
            Need(Result(0, Success, "", _ => reports++) == Success.TrimEnd('\n') && reports == 0);
            foreach (var item in new [] {
                Tuple.Create(0xC0000022U, "", "", "transport", "0xC0000022", "0", "False"),
                Tuple.Create(UInt32.MaxValue, "private-sentinel", "private-sentinel", "transport", "0xFFFFFFFF", "16", "True"),
                Tuple.Create(0U, new string('x', 128), "", "grammar", "0x00000000", "128", "False"),
                Tuple.Create(0U, new string('x', 129), "", "transport", "0x00000000", "129", "False"),
                Tuple.Create(0U, Success.Replace("00000000", "00000005"), "", "consistency", "0x00000000", "79", "False")
            }) {
                string line = null; int count = 0; Exception caught = null;
                try { Result(item.Item1, item.Item2, item.Item3, value => { line = value; count++; }); }
                catch (Exception failure) { caught = failure; }
                Need(caught is InvalidOperationException && caught.Message == "fixed self activation contract failed" && count == 1 &&
                    line == "WINDOWS_SELF_ACTIVATION_REFUSAL stage=" + item.Item4 + " raw_process_exit=" + item.Item5 +
                        " stdout_chars=" + item.Item6 + " stderr_present=" + item.Item7);
            }
            var reporting = new IOException("fixed reporting fixture"); AggregateException group = null;
            try { Result(1, "private-sentinel", "", _ => { throw reporting; }); }
            catch (AggregateException failure) { group = failure; }
            Need(group != null && group.InnerExceptions.Count == 2 && group.InnerExceptions[0] is InvalidOperationException &&
                group.InnerExceptions[0].Message == "fixed self activation contract failed" && Object.ReferenceEquals(group.InnerExceptions[1], reporting));
        }
        static void RequireHost(string result)
        { Need(result == Success.TrimEnd('\n')); }
        static void CompleteHost(Func<string> run, Action close, Action accept)
        {
            Exception primary = null;
            try { RequireHost(run()); }
            catch (Exception failure) { primary = failure; throw; }
            finally {
                try { close(); }
                catch (Exception cleanup) {
                    if (primary != null) throw new AggregateException("fixed host activation operation/lease cleanup failed", primary, cleanup);
                    throw;
                }
            }
            accept();
        }
        static void RequirePositive(bool positive) { Need(positive); }
        internal static string Condition(string condition, string result)
        {
            Need(condition == "original" || condition == "modified" || condition == "restored");
            Need(Result(0, result + "\n", "") == result);
            return "WINDOWS_SELF_ACTIVATION_CONDITION condition=" + condition + " " + result +
                " python_equivalence_claimed=False cause_claimed=False production_grant=False";
        }
        static void RequireIdentity(byte[] bytes, long length, string hash)
        { Need(bytes.LongLength == length && Digest(bytes) == hash); }
        static void Refused(Action action)
        { bool refused = false; try { action(); } catch (InvalidOperationException) { refused = true; } Need(refused); }
        public static void CheckSourceValidation(string windowsSource)
        {
            string path = Path.Combine(Path.GetFullPath(windowsSource), "StartupSelfActivation.c");
            using (FileStream held = Open(path)) {
                byte[] bytes = Read(held, 65536), normalized = null;
                try {
                    string text = Utf8.GetString(bytes).Replace("\r\n", "\n"); Need(text.IndexOf('\r') < 0);
                    normalized = Utf8.GetBytes(text); Need(Digest(normalized) == SourceHash);
                    Need(text.Contains("sizeof(FixedActCtx) == 56") && text.Contains("OFFSET(module) == 48") &&
                        text.Contains("context.flags = 0x88;") && text.Contains("context.resource = (const WORD *)2;") &&
                        text.Contains("HANDLE own = GetModuleHandleW(0)") && text.Contains("context.source = 0;") &&
                        text.Contains("error = result == (HANDLE)-1 ? GetLastError() : 0;") &&
                        text.IndexOf("if (success) ReleaseActCtx(result);", StringComparison.Ordinal) < text.IndexOf("part = \"WINDOWS_SELF_ACTIVATION", StringComparison.Ordinal));
                } finally { Array.Clear(bytes, 0, bytes.Length); if (normalized != null) Array.Clear(normalized, 0, normalized.Length); }
            }
        }
        public static void CheckValidation(string work)
        {
            RequireRole(true, new bool[9]);
            for (int index = 0; index < 10; index++) {
                bool[] others = new bool[9]; if (index < 9) others[index] = true; bool refused = false;
                try { RequireRole(index < 9, others); } catch (ArgumentException) { refused = true; } Need(refused);
            }
            CheckResultRefusal();
            Need(Script(1033) == "LANGUAGE 9,1\n2 24 \"self-activation-payload.bin\"\n");
            const string denied = "WINDOWS_SELF_ACTIVATION entry_reached=True created=False win32_error=0x00000005\n";
            Need(Result(0, Success, "") == Success.TrimEnd('\n') && Result(0, denied, "") == denied.TrimEnd('\n'));
            RequireHost(Result(0, Success, "")); Refused(() => RequireHost(Result(0, denied, "")));
            RequirePositive(true); Refused(() => RequirePositive(false));
            foreach (int mode in new [] { 0, 1, 2, 3 }) {
                var order = new List<string>(); var operation = new IOException("fixed host operation");
                Exception cleanup = Capture.CheckStrictCleanup(); Need(cleanup != null); Exception caught = null;
                try { CompleteHost(() => { order.Add("run"); if (mode == 1 || mode == 3) throw operation; return Success.TrimEnd('\n'); },
                    () => { order.Add("close"); if (mode == 2 || mode == 3) throw cleanup; }, () => order.Add("accept")); }
                catch (Exception failure) { caught = failure; }
                Need(String.Join(",", order) == (mode == 0 ? "run,close,accept" : "run,close"));
                if (mode == 0) Need(caught == null);
                if (mode == 1 || mode == 2) Need(Object.ReferenceEquals(caught, mode == 1 ? operation : cleanup));
                if (mode == 3) {
                    var group = caught as AggregateException;
                    Need(group != null && group.InnerExceptions.Count == 2 && Object.ReferenceEquals(group.InnerExceptions[0], operation) &&
                        Object.ReferenceEquals(group.InnerExceptions[1], cleanup));
                }
            }
            foreach (uint exit in new uint[] { 1, 120, 121, 0xC0000022, 0xC0150002, UInt32.MaxValue }) {
                Refused(() => Result(exit, Success, "")); Refused(() => Result(exit, "", ""));
            }
            foreach (string text in new [] { "", Success + Success, Success.TrimEnd('\n'), Success.Replace("\n", "\r\n"),
                Success.Replace("00000000", "00000005"), denied.Replace("00000005", "00000000"),
                Success.Replace("entry_reached=True", "entry_reached=False"), denied.Replace("False", "false"),
                "private-sentinel", new string('x', 129) }) Refused(() => Result(0, text, ""));
            Refused(() => Result(0, Success, "private-sentinel")); Refused(() => Result(0, Success, " "));
            Need(Condition("original", Result(0, denied, "")).EndsWith("python_equivalence_claimed=False cause_claimed=False production_grant=False", StringComparison.Ordinal));
            Refused(() => Condition("private-sentinel", Result(0, Success, ""))); Refused(() => Condition("modified", "private-sentinel"));
            byte[] abc = { 97, 98, 99 };
            const string hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
            RequireIdentity(abc, 3, hash); Refused(() => RequireIdentity(abc, 4, hash));
            Refused(() => RequireIdentity(new byte[] { 97, 98, 100 }, 3, hash));
            string directory = Path.Combine(Path.GetFullPath(work), "self-activation-validation-" + Guid.NewGuid().ToString("N"));
            DefaultActivationFixture.Missing(directory); Directory.CreateDirectory(directory);
            try {
                string path = Path.Combine(directory, "owned.bin");
                using (Create(path, abc)) { }
                Refused(() => { using (Create(path, new byte[] { 9 })) { } }); Need(File.ReadAllBytes(path).SequenceEqual(abc));
                string sidecar = Path.Combine(directory, Image + ".manifest");
                File.WriteAllText(sidecar, "unchanged", Utf8); Refused(() => DefaultActivationFixture.NoOverrides(Path.Combine(directory, Image)));
                Need(File.ReadAllText(sidecar, Utf8) == "unchanged"); File.Delete(sidecar);
                Directory.CreateSymbolicLink(sidecar, Path.Combine(directory, "absent"));
                Refused(() => DefaultActivationFixture.NoOverrides(Path.Combine(directory, Image)));
                Need((File.GetAttributes(sidecar) & FileAttributes.ReparsePoint) != 0); Directory.Delete(sidecar);
            } finally { Directory.Delete(directory, true); }
            KernelImage.CheckSelfActivationValidation();
        }
        public static void Build(string windowsSource, string python, string state)
        {
            Need(prepared == null); python = Path.GetFullPath(python); state = Path.GetFullPath(state);
            Need(Path.GetFileName(python) == "python.exe" && Path.GetDirectoryName(python) == Path.Combine(state, "python"));
            string dll = Path.Combine(Path.GetDirectoryName(python), "python311.dll");
            string original = Path.Combine(Path.GetFullPath(windowsSource), "StartupSelfActivation.c");
            string source = Path.Combine(state, "self-activation.c"), obj = Path.Combine(state, "self-activation.obj");
            string payloadPath = Path.Combine(state, "self-activation-payload.bin"), script = Path.Combine(state, "self-activation.rc"), resource = Path.Combine(state, "self-activation.res");
            string image = Path.Combine(Path.GetDirectoryName(python), Image);
            NativeFixture.Plain(state); NativeFixture.Plain(python); DefaultActivationFixture.NoOverrides(python); DefaultActivationFixture.NoOverrides(dll);
            foreach (string path in new [] { source, obj, payloadPath, script, resource, image }) DefaultActivationFixture.Missing(path);
            DefaultActivationFixture.NoOverrides(image);
            var held = new List<IDisposable>(); var buffers = new List<byte[]>(); Exception primary = null; Identity candidate = null;
            try {
                FileStream originalSource = Open(original); held.Add(originalSource); byte[] originalBytes = Read(originalSource, 65536); buffers.Add(originalBytes);
                string sourceText = Utf8.GetString(originalBytes).Replace("\r\n", "\n"); Need(sourceText.IndexOf('\r') < 0);
                byte[] sourceBytes = Utf8.GetBytes(sourceText); buffers.Add(sourceBytes); Need(Digest(sourceBytes) == SourceHash);
                FileStream originalDll = Open(dll); held.Add(originalDll); byte[] dllBytes = Read(originalDll, 16777216); buffers.Add(dllBytes);
                var manifest = KernelImage.ModuleManifest(dllBytes, false); byte[] payload = manifest.Item2; buffers.Add(payload);
                FileStream heldSource = Create(source, sourceBytes); held.Add(heldSource);
                FileStream heldPayload = Create(payloadPath, payload); held.Add(heldPayload);
                byte[] scriptBytes = Utf8.GetBytes(Script(manifest.Item1)); buffers.Add(scriptBytes);
                FileStream heldScript = Create(script, scriptBytes); held.Add(heldScript);
                var tools = NativeFixture.CompilerTools(state); string rc = DefaultActivationFixture.ResourceCompiler(tools.Item3); NativeFixture.Plain(rc);
                TrustedSetup.Run(tools.Item1, new [] { "/nologo", "/c", "/TC", "/Od", "/Oi-", "/GS-", "/Zl", "/Fo" + obj, source }, state);
                FileStream heldObject = Open(obj); held.Add(heldObject); byte[] objectBytes = Read(heldObject, 1048576); buffers.Add(objectBytes);
                TrustedSetup.Run(rc, new [] { "/nologo", "/x", "/fo", resource, script }, state);
                FileStream heldResource = Open(resource); held.Add(heldResource); byte[] resourceBytes = Read(heldResource, 131072); buffers.Add(resourceBytes);
                TrustedSetup.Run(tools.Item2, new [] { "/nologo", "/NODEFAULTLIB", "/MANIFEST:NO", "/ENTRY:StartupEntry", "/SUBSYSTEM:CONSOLE", "/MACHINE:X64", "/OUT:" + image, obj, resource, tools.Item3 }, state);
                FileStream heldImage = Open(image); held.Add(heldImage); byte[] imageBytes = Read(heldImage, 1048576); buffers.Add(imageBytes);
                DefaultActivationFixture.NoOverrides(image); KernelImage.QualifySelfActivation(imageBytes, manifest.Item1, payload);
                Same(originalSource, originalBytes); Same(heldSource, sourceBytes); Same(heldPayload, payload); Same(heldScript, scriptBytes);
                Same(heldObject, objectBytes); Same(heldResource, resourceBytes);
                byte[] after = Read(originalDll, 16777216); buffers.Add(after); Need(after.SequenceEqual(dllBytes));
                candidate = new Identity { python = python, source = original, sourceHash = Digest(originalBytes), sourceLength = originalBytes.Length,
                    dll = dll, dllHash = Digest(dllBytes), dllLength = dllBytes.Length, payloadHash = Digest(payload), payloadLength = payload.Length,
                    image = image, imageHash = Digest(imageBytes), imageLength = imageBytes.Length, language = manifest.Item1 };
            } catch (Exception failure) { primary = failure; throw; }
            finally { Finish(primary, held, buffers); }
            Need(candidate != null); prepared = candidate;
        }
        internal static string PreparedImage(string python)
        { Need(prepared != null && python == prepared.python); return prepared.image; }
        internal static void RequireHostPositive(string python)
        { PreparedImage(python); RequirePositive(prepared.hostPositive); }
        public static void RunHost(string python)
        {
            PreparedImage(python); Need(!prepared.hostPositive);
            IDisposable held = Hold(python);
            CompleteHost(() => TrustedSetup.RunSelfActivation(python), held.Dispose, () => prepared.hostPositive = true);
            Console.Out.WriteLine("WINDOWS_SELF_ACTIVATION_HOST positive=True cleanup_complete=True cause_claimed=False"); Console.Out.Flush();
        }
        internal static IDisposable Hold(string python)
        {
            string image = PreparedImage(python);
            foreach (string path in new [] { prepared.source, prepared.dll, image }) NativeFixture.Plain(path);
            DefaultActivationFixture.NoOverrides(python); DefaultActivationFixture.NoOverrides(prepared.dll); DefaultActivationFixture.NoOverrides(image);
            return Acquire(new Func<IDisposable>[] { () => Open(prepared.source), () => Open(prepared.dll), () => Open(image) }, values => {
                byte[] source = null, dll = null, payload = null, executable = null;
                try {
                    source = Read((FileStream)values[0], 65536); RequireIdentity(source, prepared.sourceLength, prepared.sourceHash);
                    dll = Read((FileStream)values[1], 16777216); RequireIdentity(dll, prepared.dllLength, prepared.dllHash);
                    var manifest = KernelImage.ModuleManifest(dll, false); payload = manifest.Item2;
                    Need(manifest.Item1 == prepared.language); RequireIdentity(payload, prepared.payloadLength, prepared.payloadHash);
                    executable = Read((FileStream)values[2], 1048576); RequireIdentity(executable, prepared.imageLength, prepared.imageHash);
                    KernelImage.QualifySelfActivation(executable, prepared.language, payload);
                } finally { foreach (byte[] bytes in new [] { source, dll, payload, executable }) if (bytes != null) Array.Clear(bytes, 0, bytes.Length); }
            });
        }
    }
}
