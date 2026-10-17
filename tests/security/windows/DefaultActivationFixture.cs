using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ScientificSecurity
{
    // Separate automatic-startup control; never changes the original Python or native controls.
    public static class DefaultActivationFixture
    {
        const string Image = "startup-default-activation.exe";
        const string Entry = "WINDOWS_DEFAULT_ACTIVATION_ENTRY reached=True\n";
        static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
        const string Source = "/* Fixed automatic activation control; no CRT or input. */\n" +
            "__declspec(dllimport) void * __stdcall GetStdHandle(unsigned long kind);\n" +
            "__declspec(dllimport) int __stdcall WriteFile(void *,const void *,unsigned long,unsigned long *,void *);\n" +
            "__declspec(dllimport) void __stdcall ExitProcess(unsigned long code);\n" +
            "void __stdcall StartupEntry(void) {\n" +
            "  static const char line[]=\"WINDOWS_DEFAULT_ACTIVATION_ENTRY reached=True\\n\";\n" +
            "  unsigned long written=0; void *output=GetStdHandle((unsigned long)-11);\n" +
            "  if (!output || output==(void *)-1 || !WriteFile(output,line,sizeof(line)-1,&written,0) || written!=sizeof(line)-1) ExitProcess(121);\n" +
            "  ExitProcess(0);\n}\n";
        sealed class Identity
        {
            internal string python, image, pythonDigest, imageDigest, payloadDigest;
            internal long pythonLength, payloadLength;
            internal ushort language;
        }
        static Identity prepared;
        static void Need(bool value)
        { if (!value) throw new InvalidOperationException("fixed default activation contract failed"); }
        internal static void RequireRole(bool preflight, bool wall, bool loader, bool native, bool clone, bool probe, bool trace, bool observe)
        {
            if (!preflight || wall || loader || native || clone || probe || trace || observe)
                throw new ArgumentException("default activation is a separate fixed undebugged trusted diagnostic");
        }
        static void Refused(Action action)
        { bool refused = false; try { action(); } catch (InvalidOperationException) { refused = true; } Need(refused); }
        public static void CheckValidation(string work)
        {
            RequireRole(true, false, false, false, false, false, false, false);
            for (int index = 0; index < 8; index++) {
                var role = new bool[8]; role[0] = true; role[index] = index != 0; bool refused = false;
                try { RequireRole(role[0], role[1], role[2], role[3], role[4], role[5], role[6], role[7]); }
                catch (ArgumentException) { refused = true; }
                Need(refused);
            }
            Need(ResourceScript(1033) == "LANGUAGE 9,1\n1 24 \"default-activation-payload.bin\"\n");
            Need(ResourceScript(0) == "LANGUAGE 0,0\n1 24 \"default-activation-payload.bin\"\n");
            string sdk = Path.Combine(Path.GetFullPath(work), "fixed-sdk");
            string library = Path.Combine(sdk, "Lib", "10.0.1.0", "um", "x64", "kernel32.lib");
            Need(ResourceCompiler(library) == Path.Combine(sdk, "bin", "10.0.1.0", "x64", "rc.exe"));
            Refused(() => ResourceCompiler(library.Replace("kernel32.lib", "other.lib")));
            Refused(() => ResourceCompiler(library.Replace("x64", "x86")));
            Refused(() => ResourceCompiler(library.Replace("10.0.1.0", "unknown")));
            byte[] abc = { 97, 98, 99 };
            const string abcHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
            RequireIdentity(abc, 3, abcHash);
            Refused(() => RequireIdentity(abc, 4, abcHash));
            Refused(() => RequireIdentity(new byte[] { 97, 98, 100 }, 3, abcHash));
            Need(Result(0, Entry, "") == "entry_observed=True exit=0x00000000");
            Need(Result(0xC0150002, "", "") == "entry_observed=False exit=0xC0150002");
            foreach (uint exit in new uint[] { 0, 1, 121, 0x7FFFFFFF, 0xC0000022 }) {
                foreach (string text in new [] { "", Entry, "private-sentinel", Entry + Entry }) {
                    if (exit == 0 && text == Entry || (exit & 0x80000000) != 0 && text == "") continue;
                    Refused(() => Result(exit, text, ""));
                }
            }
            Refused(() => Result(0, Entry, " ")); Refused(() => Result(0xC0000022, "", "private-sentinel"));
            Need(Condition("modified", Result(0, Entry, "")).Contains("condition=modified entry_observed=True"));
            Need(Condition("original", Result(0xC0000022, "", "")).Contains("entry_observed=False exit=0xC0000022"));
            Refused(() => Condition("private-sentinel", Result(0, Entry, "")));
            Refused(() => Condition("original", "private-sentinel"));
            Refused(() => Condition("original", "entry_observed=False exit=0xc0000022"));
            Refused(() => Condition("original", "entry_observed=False exit=0x00000079"));
            Refused(() => Condition("original", "entry_observed=False exit=0xC0000022\n"));
            CheckLeaseValidation();
            var primary = new IOException("fixed operation"); var cleanup = new IOException("fixed cleanup");
            int attempts = 0; AggregateException failure = null;
            try { Finish(primary, () => { attempts++; throw cleanup; }, () => attempts++); }
            catch (AggregateException error) { failure = error; }
            Need(attempts == 2 && failure != null && failure.InnerExceptions.Count == 2 &&
                Object.ReferenceEquals(failure.InnerExceptions[0], primary) && Object.ReferenceEquals(failure.InnerExceptions[1], cleanup));
            string directory = Path.Combine(Path.GetFullPath(work), "default-activation-validation-" + Guid.NewGuid().ToString("N"));
            Missing(directory); Directory.CreateDirectory(directory);
            try {
                string path = Path.Combine(directory, "owned.txt"); byte[] original = Utf8.GetBytes("unchanged");
                using (Create(path, original)) { }
                Refused(() => { using (Create(path, Utf8.GetBytes("replacement"))) { } });
                Need(File.ReadAllBytes(path).SequenceEqual(original));
                string image = Path.Combine(directory, Image), sidecar = image + ".manifest";
                File.WriteAllText(sidecar, "unchanged", Utf8); Refused(() => NoOverrides(image));
                Need(File.ReadAllText(sidecar, Utf8) == "unchanged"); File.Delete(sidecar);
                Directory.CreateSymbolicLink(sidecar, Path.Combine(directory, "absent"));
                Refused(() => NoOverrides(image)); Need((File.GetAttributes(sidecar) & FileAttributes.ReparsePoint) != 0);
                Directory.Delete(sidecar);
            }
            finally { Directory.Delete(directory, true); }
        }
        static void CheckLeaseValidation()
        {
            var closed = new List<string>();
            var heldSource = new FixtureLease("source", closed); var heldImage = new FixtureLease("image", closed);
            var held = Acquire(() => heldSource, () => heldImage, (first, second) => Need(first == heldSource && second == heldImage));
            Need(closed.Count == 0); held.Dispose(); held.Dispose();
            Need(heldSource.closes == 1 && heldImage.closes == 1 && String.Join(",", closed) == "image,source");
            foreach (bool openingFails in new [] { true, false }) {
                var order = new List<string>();
                var primary = new IOException("fixed acquisition");
                var source = new FixtureLease("source", order); var image = new FixtureLease("image", order);
                Exception caught = null;
                try {
                    Acquire(() => source, () => { if (openingFails) throw primary; return image; },
                        (first, second) => { Need(first == source && second == image); throw primary; });
                }
                catch (Exception error) { caught = error; }
                Need(Object.ReferenceEquals(caught, primary) && source.closes == 1 &&
                    image.closes == (openingFails ? 0 : 1) && String.Join(",", order) == (openingFails ? "source" : "image,source"));
            }
            foreach (bool qualifyFails in new [] { false, true }) {
                var order = new List<string>(); var primary = new IOException("fixed qualification");
                var firstFailure = new IOException("fixed image close"); var secondFailure = new IOException("fixed source close");
                var source = new FixtureLease("source", order) { failure = secondFailure };
                var image = new FixtureLease("image", order) { failure = firstFailure };
                IDisposable lease = null; AggregateException caught = null;
                try {
                    lease = Acquire(() => source, () => image, (first, second) => {
                        Need(first == source && second == image); if (qualifyFails) throw primary;
                    });
                    Need(source.closes == 0 && image.closes == 0); lease.Dispose();
                }
                catch (AggregateException error) { caught = error; }
                Need(caught != null && caught.InnerExceptions.Count == (qualifyFails ? 3 : 2) &&
                    (!qualifyFails || Object.ReferenceEquals(caught.InnerExceptions[0], primary)) &&
                    Object.ReferenceEquals(caught.InnerExceptions[qualifyFails ? 1 : 0], firstFailure) &&
                    Object.ReferenceEquals(caught.InnerExceptions[qualifyFails ? 2 : 1], secondFailure) &&
                    source.closes == 1 && image.closes == 1 && String.Join(",", order) == "image,source");
                if (lease != null) { lease.Dispose(); Need(source.closes == 1 && image.closes == 1); }
            }
        }
        sealed class FixtureLease : IDisposable
        {
            readonly string name; readonly List<string> order;
            internal IOException failure; internal int closes;
            internal FixtureLease(string name, List<string> order) { this.name = name; this.order = order; }
            public void Dispose() { closes++; order.Add(name); if (failure != null) throw failure; }
        }
        static string ResourceScript(ushort language)
        { return "LANGUAGE " + (language & 1023).ToString(CultureInfo.InvariantCulture) + "," +
            (language >> 10).ToString(CultureInfo.InvariantCulture) + "\n1 24 \"default-activation-payload.bin\"\n"; }
        static string ResourceCompiler(string library)
        {
            Need(Path.IsPathFullyQualified(library) && Path.GetFileName(library) == "kernel32.lib");
            string x64 = Path.GetDirectoryName(library), um = Path.GetDirectoryName(x64), version = Path.GetDirectoryName(um);
            string lib = Path.GetDirectoryName(version), sdk = Path.GetDirectoryName(lib); Version parsed;
            Need(Path.GetFileName(x64) == "x64" && Path.GetFileName(um) == "um" && Path.GetFileName(lib) == "Lib" &&
                Version.TryParse(Path.GetFileName(version), out parsed));
            return Path.Combine(sdk, "bin", Path.GetFileName(version), "x64", "rc.exe");
        }
        internal static string Result(uint exit, string text, string errors)
        {
            Need(text != null && errors != null && errors.Length == 0);
            if (exit == 0) { Need(text == Entry); return "entry_observed=True exit=0x00000000"; }
            Need((exit & 0x80000000) != 0 && text.Length == 0);
            return "entry_observed=False exit=0x" + exit.ToString("X8", CultureInfo.InvariantCulture);
        }
        internal static string Condition(string condition, string result)
        {
            Need(condition == "original" || condition == "modified" || condition == "restored");
            uint exit;
            Need(result == "entry_observed=True exit=0x00000000" ||
                result != null && result.Length == 36 && result.StartsWith("entry_observed=False exit=0x", StringComparison.Ordinal) &&
                UInt32.TryParse(result.Substring(28), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out exit) &&
                (exit & 0x80000000) != 0 && result == Result(exit, "", ""));
            return "WINDOWS_DEFAULT_ACTIVATION condition=" + condition + " " + result + " cause_claimed=False python_equivalence_claimed=False";
        }
        static void Missing(string path)
        {
            NativeFixture.Plain(path, true);
            try { File.GetAttributes(path); }
            catch (FileNotFoundException) { return; }
            catch (DirectoryNotFoundException) { return; }
            throw new InvalidOperationException("fixed default activation output or override already exists");
        }
        static void NoOverrides(string image)
        {
            foreach (string path in new [] { image + ".manifest", Path.ChangeExtension(image, ".manifest"),
                image + ".config", Path.ChangeExtension(image, ".config") }) Missing(path);
        }
        static byte[] Read(FileStream stream, int maximum)
        {
            Need(stream.Length >= 1 && stream.Length <= maximum); stream.Position = 0;
            byte[] bytes = new byte[(int)stream.Length]; int position = 0;
            try {
                while (position < bytes.Length) {
                    int count = stream.Read(bytes, position, bytes.Length - position);
                    if (count == 0) throw new EndOfStreamException("fixed default activation input is truncated");
                    position += count;
                }
                Need(stream.ReadByte() == -1); return bytes;
            }
            catch { Array.Clear(bytes, 0, bytes.Length); throw; }
        }
        static FileStream Create(string path, byte[] bytes)
        {
            Missing(path);
            using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None)) {
                stream.Write(bytes, 0, bytes.Length); stream.Flush(true); Same(stream, bytes);
            }
            NativeFixture.Plain(path); var held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            try { Same(held, bytes); return held; }
            catch { held.Dispose(); throw; }
        }
        static string Digest(byte[] bytes)
        { using (var hash = SHA256.Create()) return BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant(); }
        static void RequireIdentity(byte[] bytes, long length, string digest)
        { Need(bytes.LongLength == length && Digest(bytes) == digest); }
        static void Same(FileStream stream, byte[] expected)
        {
            byte[] actual = Read(stream, 65536);
            try { Need(actual.SequenceEqual(expected)); }
            finally { Array.Clear(actual, 0, actual.Length); }
        }
        static string HeldDigest(FileStream stream)
        {
            byte[] bytes = Read(stream, 131072);
            try { return Digest(bytes); }
            finally { Array.Clear(bytes, 0, bytes.Length); }
        }
        static void Finish(Exception primary, params Action[] actions)
        {
            var failures = new List<Exception>();
            foreach (Action action in actions) try { action(); } catch (Exception error) { failures.Add(error); }
            if (failures.Count == 0) return;
            if (primary != null) failures.Insert(0, primary);
            throw new AggregateException("fixed default activation operation/cleanup failed", failures);
        }
        public static void Build(string python, string state)
        {
            Need(prepared == null); python = Path.GetFullPath(python); state = Path.GetFullPath(state);
            Need(Path.GetDirectoryName(python) == Path.Combine(state, "python") && Path.GetFileName(python) == "python.exe");
            NativeFixture.Plain(state); NativeFixture.Plain(python); NoOverrides(python);
            string image = Path.Combine(Path.GetDirectoryName(python), Image);
            string source = Path.Combine(state, "default-activation.c"), payloadPath = Path.Combine(state, "default-activation-payload.bin");
            string script = Path.Combine(state, "default-activation.rc"), resource = Path.Combine(state, "default-activation.res");
            string obj = Path.Combine(state, "default-activation.obj");
            foreach (string path in new [] { image, source, payloadPath, script, resource, obj }) Missing(path);
            NoOverrides(image);
            FileStream heldPython = null, heldSource = null, heldPayload = null, heldScript = null, heldResource = null;
            byte[] pythonBytes = null, payload = null; Exception primary = null; Identity candidate = null;
            try {
                heldPython = new FileStream(python, FileMode.Open, FileAccess.Read, FileShare.Read);
                pythonBytes = Read(heldPython, 16777216); var manifest = KernelImage.DefaultManifest(pythonBytes, false); payload = manifest.Item2;
                byte[] sourceBytes = Utf8.GetBytes(Source), scriptBytes = Utf8.GetBytes(ResourceScript(manifest.Item1));
                heldSource = Create(source, sourceBytes); heldPayload = Create(payloadPath, payload); heldScript = Create(script, scriptBytes);
                var tools = NativeFixture.CompilerTools(state); string rc = ResourceCompiler(tools.Item3); NativeFixture.Plain(rc);
                TrustedSetup.Run(tools.Item1, new [] { "/nologo", "/c", "/TC", "/Od", "/GS-", "/Zl", "/Fo" + obj, source }, state);
                TrustedSetup.Run(rc, new [] { "/nologo", "/x", "/fo", resource, script }, state);
                NativeFixture.Plain(obj); NativeFixture.Plain(resource);
                heldResource = new FileStream(resource, FileMode.Open, FileAccess.Read, FileShare.Read);
                string resourceDigest = HeldDigest(heldResource);
                TrustedSetup.Run(tools.Item2, new [] { "/nologo", "/NODEFAULTLIB", "/MANIFEST:NO", "/ENTRY:StartupEntry", "/SUBSYSTEM:CONSOLE",
                    "/MACHINE:X64", "/OUT:" + image, obj, resource, tools.Item3 }, state);
                Same(heldSource, sourceBytes); Same(heldPayload, payload); Same(heldScript, scriptBytes);
                Need(HeldDigest(heldResource) == resourceDigest);
                NativeFixture.Plain(image); NoOverrides(image);
                using (var held = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                    byte[] bytes = Read(held, 1048576);
                    try {
                        KernelImage.QualifyDefaultActivation(bytes, manifest.Item1, payload);
                        candidate = new Identity { python = python, image = image, pythonLength = pythonBytes.Length,
                            pythonDigest = Digest(pythonBytes), imageDigest = Digest(bytes), payloadLength = payload.Length, payloadDigest = Digest(payload), language = manifest.Item1 };
                    }
                    finally { Array.Clear(bytes, 0, bytes.Length); }
                }
            }
            catch (Exception failure) { primary = failure; throw; }
            finally {
                Finish(primary, () => { if (heldResource != null) heldResource.Dispose(); }, () => { if (heldScript != null) heldScript.Dispose(); },
                    () => { if (heldPayload != null) heldPayload.Dispose(); }, () => { if (heldSource != null) heldSource.Dispose(); },
                    () => { if (heldPython != null) heldPython.Dispose(); }, () => { if (pythonBytes != null) Array.Clear(pythonBytes, 0, pythonBytes.Length); },
                    () => { if (payload != null) Array.Clear(payload, 0, payload.Length); });
            }
            Need(candidate != null); prepared = candidate;
        }
        internal static string PreparedImage(string python)
        { Need(prepared != null && python == prepared.python); return prepared.image; }
        internal static IDisposable Hold(string python)
        {
            string path = PreparedImage(python); NativeFixture.Plain(python); NativeFixture.Plain(path); NoOverrides(python); NoOverrides(path);
            return Acquire(
                () => new FileStream(python, FileMode.Open, FileAccess.Read, FileShare.Read),
                () => new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read),
                (source, image) => {
                byte[] bytes = Read(source, 16777216), executable = null, payload = null;
                try {
                    RequireIdentity(bytes, prepared.pythonLength, prepared.pythonDigest);
                    var manifest = KernelImage.DefaultManifest(bytes, false); payload = manifest.Item2;
                    Need(manifest.Item1 == prepared.language); RequireIdentity(payload, prepared.payloadLength, prepared.payloadDigest);
                    executable = Read(image, 1048576); Need(Digest(executable) == prepared.imageDigest);
                    KernelImage.QualifyDefaultActivation(executable, prepared.language, payload);
                }
                finally {
                    Array.Clear(bytes, 0, bytes.Length); if (executable != null) Array.Clear(executable, 0, executable.Length);
                    if (payload != null) Array.Clear(payload, 0, payload.Length);
                }
                });
        }
        static IDisposable Acquire<T>(Func<T> openSource, Func<T> openImage, Action<T, T> qualify) where T : class, IDisposable
        {
            T source = null, image = null; Exception primary = null;
            try {
                source = openSource(); image = openImage(); qualify(source, image);
                var lease = new Lease(source, image); source = image = null; return lease;
            }
            catch (Exception error) { primary = error; throw; }
            finally { Finish(primary, () => { if (image != null) image.Dispose(); }, () => { if (source != null) source.Dispose(); }); }
        }
        sealed class Lease : IDisposable
        {
            IDisposable python, image;
            internal Lease(IDisposable python, IDisposable image) { this.python = python; this.image = image; }
            public void Dispose()
            {
                var first = python; var second = image; python = image = null;
                Finish(null, () => { if (second != null) second.Dispose(); }, () => { if (first != null) first.Dispose(); });
            }
        }
    }
}
