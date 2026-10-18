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
    internal enum SelfActivationRole { Original, Manual, ExplicitId2 }
    // A documented own-EXE call, not an equivalent of the automatic DLL callback.
    public static class SelfActivationFixture
    {
        const string Image = "startup-self-activation.exe";
        const string SourceHash = "d6a12cdd2c9ef78e29c5c43af7527f4d74260a01ca15475b3ad83e6bcc49ca3e";
        const string Success = "WINDOWS_SELF_ACTIVATION entry_reached=True created=True win32_error=0x00000000\n";
        static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
        sealed class Identity {
            internal string python, source, sourceHash, generated, generatedHash, dll, dllHash, payloadHash, image, imageHash;
            internal long sourceLength, generatedLength, dllLength, payloadLength, imageLength;
            internal ushort language;
            internal bool hostPositive;
        }
        static Identity prepared, manualPrepared, explicitPrepared;
        internal static void RequireKnownRole(SelfActivationRole role)
        {
            if (role != SelfActivationRole.Original && role != SelfActivationRole.Manual && role != SelfActivationRole.ExplicitId2)
                throw new ArgumentException("unsupported fixed self activation role");
        }
        internal static string Label(SelfActivationRole role)
        {
            RequireKnownRole(role);
            return role == SelfActivationRole.Original ? "WINDOWS_SELF_ACTIVATION" :
                role == SelfActivationRole.Manual ? "WINDOWS_MANUAL_ACTIVATION" : "WINDOWS_EXPLICIT_ID2_ACTIVATION";
        }
        internal static string Stem(SelfActivationRole role)
        {
            RequireKnownRole(role);
            return role == SelfActivationRole.Original ? "self-activation" : role == SelfActivationRole.Manual ? "manual-activation" : "explicit-id2";
        }
        internal static string ImageName(SelfActivationRole role) { return "startup-" + Stem(role) + ".exe"; }
        static Identity Prepared(string python, SelfActivationRole role)
        {
            RequireKnownRole(role);
            Identity value = role == SelfActivationRole.Original ? prepared : role == SelfActivationRole.Manual ? manualPrepared : explicitPrepared;
            Need(value != null && python == value.python); return value;
        }
        static string ReplaceOnce(string text, string before, string after)
        {
            int position = text.IndexOf(before, StringComparison.Ordinal);
            Need(position >= 0 && text.IndexOf(before, position + before.Length, StringComparison.Ordinal) < 0);
            return text.Substring(0, position) + after + text.Substring(position + before.Length);
        }
        static byte[] SourceBytes(string text, SelfActivationRole role)
        {
            RequireKnownRole(role);
            Need(text.IndexOf('\r') < 0 && Digest(Utf8.GetBytes(text)) == SourceHash);
            if (role == SelfActivationRole.Original) return Utf8.GetBytes(text);
            if (role == SelfActivationRole.Manual)
                text = ReplaceOnce(text, "context.resource = (const WORD *)2;", "context.resource = (const WORD *)101;");
            text = ReplaceOnce(text, "WINDOWS_SELF_ACTIVATION", Label(role));
            byte[] bytes = Utf8.GetBytes(text);
            Need(Digest(bytes) == (role == SelfActivationRole.Manual ?
                "23c0950197918b9f6e34fe5910d7fedae7c33ad34d38b3b90758bcf815413303" :
                "7941d72073d3795d637118360ed8da67ea83c606c19450c06825114b879d1d51"));
            return bytes;
        }
        static void Need(bool value)
        { if (!value) throw new InvalidOperationException("fixed self activation contract failed"); }
        internal static void RequireRole(bool preflight, params bool[] others)
        { if (!preflight || others.Length != 9 || others.Any(value => value)) throw new ArgumentException("self activation is a separate fixed undebugged trusted diagnostic"); }
        static string Script(ushort language, SelfActivationRole role = SelfActivationRole.Original)
        { return "LANGUAGE " + (language & 1023).ToString(CultureInfo.InvariantCulture) + "," + (language >> 10).ToString(CultureInfo.InvariantCulture) + "\n" + (role == SelfActivationRole.Manual ? "101" : "2") + " 24 \"" + Stem(role) + "-payload.bin\"\n"; }
        internal static string Result(uint exit, string text, string errors, SelfActivationRole role = SelfActivationRole.Original)
        { return Result(exit, text, errors, line => { Console.Out.WriteLine(line); Console.Out.Flush(); }, role); }
        static void RequireResult(bool valid, string stage, uint exit, string text, string errors, Action<string> emit, SelfActivationRole role)
        {
            if (valid) return;
            var primary = new InvalidOperationException("fixed self activation contract failed");
            try {
                emit(Label(role) + "_REFUSAL stage=" + stage + " raw_process_exit=0x" + exit.ToString("X8", CultureInfo.InvariantCulture) +
                    " stdout_chars=" + (text == null ? -1 : text.Length).ToString(CultureInfo.InvariantCulture) + " stderr_present=" + (errors != null && errors.Length != 0));
            } catch (Exception reporting) { throw new AggregateException("fixed self activation refusal/reporting failed", primary, reporting); }
            throw primary;
        }
        static string Result(uint exit, string text, string errors, Action<string> emit, SelfActivationRole role = SelfActivationRole.Original)
        {
            RequireKnownRole(role);
            RequireResult(exit == 0 && text != null && text.Length <= 128 && errors != null && errors.Length == 0, "transport", exit, text, errors, emit, role);
            var match = Regex.Match(text, @"\A" + Label(role) + @" entry_reached=True created=(True|False) win32_error=0x([0-9A-F]{8})\n\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
            RequireResult(match.Success, "grammar", exit, text, errors, emit, role);
            uint error = UInt32.Parse(match.Groups[2].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            RequireResult((match.Groups[1].Value == "True") == (error == 0), "consistency", exit, text, errors, emit, role);
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
        static void RequireHost(string result, SelfActivationRole role = SelfActivationRole.Original)
        { Need(result == Success.Replace("WINDOWS_SELF_ACTIVATION", Label(role)).TrimEnd('\n')); }
        static void CompleteHost(Func<string> run, Action close, Action accept, SelfActivationRole role = SelfActivationRole.Original)
        {
            RequireKnownRole(role);
            Exception primary = null;
            try { RequireHost(run(), role); }
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
        internal static string Condition(string condition, string result, SelfActivationRole role = SelfActivationRole.Original)
        {
            Need(condition == "original" || condition == "modified" || condition == "restored");
            Need(Result(0, result + "\n", "", role) == result);
            return Label(role) + "_CONDITION condition=" + condition + " " + result +
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
                    normalized = SourceBytes(text, SelfActivationRole.Manual);
                    Need(Utf8.GetString(normalized) == text.Replace("context.resource = (const WORD *)2;", "context.resource = (const WORD *)101;")
                        .Replace("WINDOWS_SELF_ACTIVATION", "WINDOWS_MANUAL_ACTIVATION"));
                    Array.Clear(normalized, 0, normalized.Length);
                    normalized = SourceBytes(text, SelfActivationRole.ExplicitId2);
                    Need(Utf8.GetString(normalized) == text.Replace("WINDOWS_SELF_ACTIVATION", "WINDOWS_EXPLICIT_ID2_ACTIVATION"));
                    Refused(() => SourceBytes(text + " ", SelfActivationRole.ExplicitId2));
                    Refused(() => SourceBytes(text.Replace("(const WORD *)2", "(const WORD *)101"), SelfActivationRole.ExplicitId2));
                    Refused(() => SourceBytes(text + " ", SelfActivationRole.Manual));
                    Refused(() => SourceBytes(text.Replace("(const WORD *)2", "(const WORD *)3"), SelfActivationRole.Manual));
                    Need(text.Contains("sizeof(FixedActCtx) == 56") && text.Contains("OFFSET(module) == 48") &&
                        text.Contains("context.flags = 0x88;") && text.Contains("context.resource = (const WORD *)2;") &&
                        text.Contains("HANDLE own = GetModuleHandleW(0)") && text.Contains("context.source = 0;") &&
                        text.Contains("error = result == (HANDLE)-1 ? GetLastError() : 0;") &&
                        text.IndexOf("if (success) ReleaseActCtx(result);", StringComparison.Ordinal) < text.IndexOf("part = \"WINDOWS_SELF_ACTIVATION", StringComparison.Ordinal));
                } finally { Array.Clear(bytes, 0, bytes.Length); if (normalized != null) Array.Clear(normalized, 0, normalized.Length); }
            }
        }
        static void CheckExplicitId2Validation()
        {
            const SelfActivationRole role = SelfActivationRole.ExplicitId2;
            const string success = "WINDOWS_EXPLICIT_ID2_ACTIVATION entry_reached=True created=True win32_error=0x00000000\n";
            const string denied = "WINDOWS_EXPLICIT_ID2_ACTIVATION entry_reached=True created=False win32_error=0x00000005\n";
            Need(Script(1033, role) == "LANGUAGE 9,1\n2 24 \"explicit-id2-payload.bin\"\n");
            Need(Stem(role) == "explicit-id2" && ImageName(role) == "startup-explicit-id2.exe");
            Need(Result(0, success, "", role) == success.TrimEnd('\n') && Result(0, denied, "", role) == denied.TrimEnd('\n'));
            foreach (SelfActivationRole other in new [] { SelfActivationRole.Original, SelfActivationRole.Manual }) {
                Refused(() => Result(0, success, "", other));
                Refused(() => Result(0, Success.Replace("WINDOWS_SELF_ACTIVATION", Label(other)), "", role));
            }
            foreach (string text in new [] { "", success + success, success.TrimEnd('\n'), success.Replace("\n", "\r\n"),
                success.Replace("00000000", "00000005"), denied.Replace("00000005", "00000000"), "private-sentinel", new string('x', 129) })
                Refused(() => Result(0, text, "", role));
            foreach (uint exit in new uint[] { 1, 120, 121, 0xC0000022, UInt32.MaxValue }) Refused(() => Result(exit, success, "", role));
            Refused(() => Result(0, success, "private-sentinel", role));
            int reports = 0; Need(Result(0, success, "", _ => reports++, role) == success.TrimEnd('\n') && reports == 0);
            string refusal = null;
            Refused(() => Result(0xC0000022, "", "", line => refusal = line, role));
            Need(refusal == "WINDOWS_EXPLICIT_ID2_ACTIVATION_REFUSAL stage=transport raw_process_exit=0xC0000022 stdout_chars=0 stderr_present=False");
            var reporting = new IOException("fixed explicit ID2 reporting"); AggregateException reportingFailure = null;
            try { Result(1, "private-sentinel", "", _ => { throw reporting; }, role); }
            catch (AggregateException failure) { reportingFailure = failure; }
            Need(reportingFailure != null && reportingFailure.InnerExceptions.Count == 2 &&
                reportingFailure.InnerExceptions[0].Message == "fixed self activation contract failed" && Object.ReferenceEquals(reportingFailure.InnerExceptions[1], reporting));
            Need(Condition("original", success.TrimEnd('\n'), role) ==
                "WINDOWS_EXPLICIT_ID2_ACTIVATION_CONDITION condition=original WINDOWS_EXPLICIT_ID2_ACTIVATION entry_reached=True created=True win32_error=0x00000000 python_equivalence_claimed=False cause_claimed=False production_grant=False");
            Refused(() => Condition("original", Success.TrimEnd('\n'), role));
            RequireHost(success.TrimEnd('\n'), role); Refused(() => RequireHost(denied.TrimEnd('\n'), role));
            var close = Capture.CheckStrictCleanup(); bool accepted = false; Exception caught = null;
            try { CompleteHost(() => success.TrimEnd('\n'), () => { throw close; }, () => accepted = true, role); }
            catch (Exception failure) { caught = failure; }
            Need(!accepted && Object.ReferenceEquals(caught, close));
            foreach (int invalid in new [] { -1, 3, Int32.MaxValue }) {
                foreach (Action action in new Action[] { () => Stem((SelfActivationRole)invalid), () => Label((SelfActivationRole)invalid),
                    () => ImageName((SelfActivationRole)invalid), () => Prepared(null, (SelfActivationRole)invalid),
                    () => SourceBytes("private-sentinel", (SelfActivationRole)invalid), () => Result(0, success, "", (SelfActivationRole)invalid),
                    () => Hold(null, (SelfActivationRole)invalid), () => BuildFixed(null, null, null, (SelfActivationRole)invalid) }) {
                    bool refused = false; try { action(); } catch (ArgumentException) { refused = true; } Need(refused);
                }
            }
        }
        static void CheckManualValidation()
        {
            const string success = "WINDOWS_MANUAL_ACTIVATION entry_reached=True created=True win32_error=0x00000000\n";
            const string denied = "WINDOWS_MANUAL_ACTIVATION entry_reached=True created=False win32_error=0x00000005\n";
            Need(Script(1033, SelfActivationRole.Manual) == "LANGUAGE 9,1\n101 24 \"manual-activation-payload.bin\"\n");
            Need(Result(0, success, "", SelfActivationRole.Manual) == success.TrimEnd('\n') && Result(0, denied, "", SelfActivationRole.Manual) == denied.TrimEnd('\n'));
            Refused(() => Result(0, success, "")); Refused(() => Result(0, Success, "", SelfActivationRole.Manual));
            foreach (string text in new [] { "", success + success, success.TrimEnd('\n'), success.Replace("\n", "\r\n"),
                success.Replace("00000000", "00000005"), denied.Replace("00000005", "00000000"), "private-sentinel", new string('x', 129) })
                Refused(() => Result(0, text, "", SelfActivationRole.Manual));
            foreach (uint exit in new uint[] { 1, 120, 121, 0xC0000022, UInt32.MaxValue }) Refused(() => Result(exit, success, "", SelfActivationRole.Manual));
            Refused(() => Result(0, success, "private-sentinel", SelfActivationRole.Manual));
            int reports = 0; Need(Result(0, success, "", _ => reports++, SelfActivationRole.Manual) == success.TrimEnd('\n') && reports == 0);
            string refusal = null;
            Refused(() => Result(0xC0000022, "", "", line => refusal = line, SelfActivationRole.Manual));
            Need(refusal == "WINDOWS_MANUAL_ACTIVATION_REFUSAL stage=transport raw_process_exit=0xC0000022 stdout_chars=0 stderr_present=False");
            var reporting = new IOException("fixed manual reporting"); AggregateException reportingFailure = null;
            try { Result(1, "private-sentinel", "", _ => { throw reporting; }, SelfActivationRole.Manual); }
            catch (AggregateException reportingError) { reportingFailure = reportingError; }
            Need(reportingFailure != null && reportingFailure.InnerExceptions.Count == 2 &&
                reportingFailure.InnerExceptions[0].Message == "fixed self activation contract failed" && Object.ReferenceEquals(reportingFailure.InnerExceptions[1], reporting));
            RequireHost(success.TrimEnd('\n'), SelfActivationRole.Manual); Refused(() => RequireHost(denied.TrimEnd('\n'), SelfActivationRole.Manual));
            Refused(() => RequireHost(Success.TrimEnd('\n'), SelfActivationRole.Manual));
            Need(Condition("original", success.TrimEnd('\n'), SelfActivationRole.Manual) ==
                "WINDOWS_MANUAL_ACTIVATION_CONDITION condition=original WINDOWS_MANUAL_ACTIVATION entry_reached=True created=True win32_error=0x00000000 python_equivalence_claimed=False cause_claimed=False production_grant=False");
            Refused(() => Condition("original", Success.TrimEnd('\n'), SelfActivationRole.Manual));
            const string resource = "context.resource = (const WORD *)2;", label = "WINDOWS_SELF_ACTIVATION";
            Refused(() => ReplaceOnce("unrelated", resource, "fixed"));
            Refused(() => ReplaceOnce(resource + resource, resource, "fixed"));
            Need(ReplaceOnce(resource, resource, "context.resource = (const WORD *)101;") == "context.resource = (const WORD *)101;");
            Refused(() => ReplaceOnce(label + label, label, "WINDOWS_MANUAL_ACTIVATION"));
            var failure = Capture.CheckStrictCleanup(); Exception caught = null; bool accepted = false;
            try { CompleteHost(() => success.TrimEnd('\n'), () => { throw failure; }, () => accepted = true, SelfActivationRole.Manual); }
            catch (Exception error) { caught = error; }
            Need(!accepted && Object.ReferenceEquals(caught, failure));
        }
        public static void CheckValidation(string work)
        {
            CheckExplicitId2Validation();
            CheckManualValidation();
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
            foreach (SelfActivationRole hostRole in new [] { SelfActivationRole.Original, SelfActivationRole.Manual, SelfActivationRole.ExplicitId2 })
            foreach (int mode in new [] { 0, 1, 2, 3 }) {
                var order = new List<string>(); var operation = new IOException("fixed host operation");
                Exception cleanup = Capture.CheckStrictCleanup(); Need(cleanup != null); Exception caught = null;
                try { CompleteHost(() => { order.Add("run"); if (mode == 1 || mode == 3) throw operation; return Success.Replace("WINDOWS_SELF_ACTIVATION", Label(hostRole)).TrimEnd('\n'); },
                    () => { order.Add("close"); if (mode == 2 || mode == 3) throw cleanup; }, () => order.Add("accept"), hostRole); }
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
            BuildFixed(windowsSource, python, state, SelfActivationRole.Original);
            BuildFixed(windowsSource, python, state, SelfActivationRole.Manual);
            BuildFixed(windowsSource, python, state, SelfActivationRole.ExplicitId2);
        }
        static void BuildFixed(string windowsSource, string python, string state, SelfActivationRole role)
        {
            RequireKnownRole(role);
            Need((role == SelfActivationRole.Original ? prepared : role == SelfActivationRole.Manual ? manualPrepared : explicitPrepared) == null); python = Path.GetFullPath(python); state = Path.GetFullPath(state);
            Need(Path.GetFileName(python) == "python.exe" && Path.GetDirectoryName(python) == Path.Combine(state, "python"));
            string dll = Path.Combine(Path.GetDirectoryName(python), "python311.dll");
            string original = Path.Combine(Path.GetFullPath(windowsSource), "StartupSelfActivation.c");
            string stem = Stem(role), source = Path.Combine(state, stem + ".c"), obj = Path.Combine(state, stem + ".obj");
            string payloadPath = Path.Combine(state, stem + "-payload.bin"), script = Path.Combine(state, stem + ".rc"), resource = Path.Combine(state, stem + ".res");
            string image = Path.Combine(Path.GetDirectoryName(python), ImageName(role));
            NativeFixture.Plain(state); NativeFixture.Plain(python); DefaultActivationFixture.NoOverrides(python); DefaultActivationFixture.NoOverrides(dll);
            foreach (string path in new [] { source, obj, payloadPath, script, resource, image }) DefaultActivationFixture.Missing(path);
            DefaultActivationFixture.NoOverrides(image);
            var held = new List<IDisposable>(); var buffers = new List<byte[]>(); Exception primary = null; Identity candidate = null;
            try {
                FileStream originalSource = Open(original); held.Add(originalSource); byte[] originalBytes = Read(originalSource, 65536); buffers.Add(originalBytes);
                string sourceText = Utf8.GetString(originalBytes).Replace("\r\n", "\n"); Need(sourceText.IndexOf('\r') < 0);
                byte[] sourceBytes = SourceBytes(sourceText, role); buffers.Add(sourceBytes);
                FileStream originalDll = Open(dll); held.Add(originalDll); byte[] dllBytes = Read(originalDll, 16777216); buffers.Add(dllBytes);
                var manifest = KernelImage.ModuleManifest(dllBytes, false); byte[] payload = manifest.Item2; buffers.Add(payload);
                FileStream heldSource = Create(source, sourceBytes); held.Add(heldSource);
                FileStream heldPayload = Create(payloadPath, payload); held.Add(heldPayload);
                byte[] scriptBytes = Utf8.GetBytes(Script(manifest.Item1, role)); buffers.Add(scriptBytes);
                FileStream heldScript = Create(script, scriptBytes); held.Add(heldScript);
                var tools = NativeFixture.CompilerTools(state); string rc = DefaultActivationFixture.ResourceCompiler(tools.Item3); NativeFixture.Plain(rc);
                TrustedSetup.Run(tools.Item1, new [] { "/nologo", "/c", "/TC", "/Od", "/Oi-", "/GS-", "/Zl", "/Fo" + obj, source }, state);
                FileStream heldObject = Open(obj); held.Add(heldObject); byte[] objectBytes = Read(heldObject, 1048576); buffers.Add(objectBytes);
                TrustedSetup.Run(rc, new [] { "/nologo", "/x", "/fo", resource, script }, state);
                FileStream heldResource = Open(resource); held.Add(heldResource); byte[] resourceBytes = Read(heldResource, 131072); buffers.Add(resourceBytes);
                var link = new List<string> { "/nologo", "/NODEFAULTLIB", "/MANIFEST:NO", "/ENTRY:StartupEntry", "/SUBSYSTEM:CONSOLE", "/MACHINE:X64", "/OUT:" + image, obj, resource, tools.Item3 };
                if (role == SelfActivationRole.ExplicitId2) link.Add("/ALLOWISOLATION:NO");
                TrustedSetup.Run(tools.Item2, link.ToArray(), state);
                FileStream heldImage = Open(image); held.Add(heldImage); byte[] imageBytes = Read(heldImage, 1048576); buffers.Add(imageBytes);
                DefaultActivationFixture.NoOverrides(image); KernelImage.QualifySelfActivation(imageBytes, manifest.Item1, payload, role);
                Same(originalSource, originalBytes); Same(heldSource, sourceBytes); Same(heldPayload, payload); Same(heldScript, scriptBytes);
                Same(heldObject, objectBytes); Same(heldResource, resourceBytes);
                byte[] after = Read(originalDll, 16777216); buffers.Add(after); Need(after.SequenceEqual(dllBytes));
                candidate = new Identity { python = python, source = original, sourceHash = Digest(originalBytes), sourceLength = originalBytes.Length,
                    generated = source, generatedHash = Digest(sourceBytes), generatedLength = sourceBytes.Length, dll = dll, dllHash = Digest(dllBytes), dllLength = dllBytes.Length, payloadHash = Digest(payload), payloadLength = payload.Length,
                    image = image, imageHash = Digest(imageBytes), imageLength = imageBytes.Length, language = manifest.Item1 };
            } catch (Exception failure) { primary = failure; throw; }
            finally { Finish(primary, held, buffers); }
            Need(candidate != null);
            if (role == SelfActivationRole.Original) prepared = candidate;
            else if (role == SelfActivationRole.Manual) manualPrepared = candidate;
            else explicitPrepared = candidate;
        }
        internal static string PreparedImage(string python, SelfActivationRole role = SelfActivationRole.Original)
        { return Prepared(python, role).image; }
        internal static void RequireHostPositive(string python, SelfActivationRole role = SelfActivationRole.Original)
        { RequirePositive(Prepared(python, role).hostPositive); }
        public static void RunHost(string python)
        {
            RunHostFixed(python, SelfActivationRole.Original);
            RunHostFixed(python, SelfActivationRole.Manual);
            RunHostFixed(python, SelfActivationRole.ExplicitId2);
        }
        static void RunHostFixed(string python, SelfActivationRole role)
        {
            Identity value = Prepared(python, role); Need(!value.hostPositive);
            IDisposable held = Hold(python, role);
            CompleteHost(() => TrustedSetup.RunSelfActivation(python, role), held.Dispose, () => value.hostPositive = true, role);
            Console.Out.WriteLine(Label(role) + "_HOST positive=True cleanup_complete=True cause_claimed=False"); Console.Out.Flush();
        }
        internal static IDisposable Hold(string python, SelfActivationRole role = SelfActivationRole.Original)
        {
            Identity prepared = Prepared(python, role);
            string image = prepared.image;
            foreach (string path in new [] { prepared.source, prepared.dll, image, prepared.generated }) NativeFixture.Plain(path);
            DefaultActivationFixture.NoOverrides(python); DefaultActivationFixture.NoOverrides(prepared.dll); DefaultActivationFixture.NoOverrides(image);
            return Acquire(new Func<IDisposable>[] { () => Open(prepared.source), () => Open(prepared.dll), () => Open(image), () => Open(prepared.generated) }, values => {
                byte[] source = null, dll = null, payload = null, executable = null, generated = null, expected = null;
                try {
                    source = Read((FileStream)values[0], 65536); RequireIdentity(source, prepared.sourceLength, prepared.sourceHash);
                    dll = Read((FileStream)values[1], 16777216); RequireIdentity(dll, prepared.dllLength, prepared.dllHash);
                    var manifest = KernelImage.ModuleManifest(dll, false); payload = manifest.Item2;
                    Need(manifest.Item1 == prepared.language); RequireIdentity(payload, prepared.payloadLength, prepared.payloadHash);
                    executable = Read((FileStream)values[2], 1048576); RequireIdentity(executable, prepared.imageLength, prepared.imageHash);
                    KernelImage.QualifySelfActivation(executable, prepared.language, payload, role);
                    generated = Read((FileStream)values[3], 65536); RequireIdentity(generated, prepared.generatedLength, prepared.generatedHash);
                    expected = SourceBytes(Utf8.GetString(source).Replace("\r\n", "\n"), role); Need(generated.SequenceEqual(expected));
                } finally { foreach (byte[] bytes in new [] { source, dll, payload, executable, generated, expected }) if (bytes != null) Array.Clear(bytes, 0, bytes.Length); }
            });
        }
    }
}
