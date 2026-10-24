using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace ScientificSecurity
{
    // Byte-identical fixed diagnostic clone, never an ordinary Python admission substitute.
    public static class PythonStartupFixture
    {
        const long Maximum = 16L * 1024 * 1024;
        internal static string Runtime(string run, string state)
        {
            if (run == null || run.Length != 32 || !run.All(c => (c >= 'a' && c <= 'f') || (c >= '0' && c <= '9')) ||
                !Path.IsPathFullyQualified(state) || Path.GetFileName(Path.TrimEndingDirectorySeparator(state)) != "security-windows-" + run)
                throw new InvalidOperationException("Python clone requires the fixed owned run directory");
            NativeFixture.Plain(state);
            return Path.Combine(Path.GetFullPath(state), "python");
        }
        static void Absent(string path)
        {
            NativeFixture.Plain(path, true);
            try { File.GetAttributes(path); }
            catch (FileNotFoundException) { return; }
            catch (DirectoryNotFoundException) { return; }
            throw new InvalidOperationException("fixed Python diagnostic collides with existing state or override");
        }
        internal static void Overrides(string runtime)
        {
            foreach (string image in new [] { "python.exe", "startup-python.exe" }) {
                string path = Path.Combine(runtime, image);
                foreach (string sidecar in new [] { path + ".manifest", Path.ChangeExtension(path, ".manifest"),
                    path + ".config", Path.ChangeExtension(path, ".config"), Path.ChangeExtension(path, "._pth"),
                    Path.ChangeExtension(path, ".zip") }) Absent(sidecar);
            }
            foreach (string name in new [] { "pyvenv.cfg", "pybuilddir.txt" }) Absent(Path.Combine(runtime, name));
        }
        internal static FileStream Open(string path)
        {
            NativeFixture.Plain(path);
            var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length < 1 || stream.Length > Maximum) {
                stream.Dispose(); throw new InvalidOperationException("fixed Python clone image exceeds finite size bound");
            }
            return stream;
        }
        static void Equal(FileStream source, FileStream clone)
        {
            if (source.Length != clone.Length) throw new InvalidOperationException("fixed Python clone length differs");
            source.Position = clone.Position = 0;
            using (SHA256 hash = SHA256.Create()) {
                byte[] expected = hash.ComputeHash(source), actual = hash.ComputeHash(clone);
                if (!expected.SequenceEqual(actual)) throw new InvalidOperationException("fixed Python clone bytes differ");
            }
        }
        public static void Prepare(string run, string state)
        {
            string runtime = Runtime(run, state), destination = Path.Combine(runtime, "startup-python.exe");
            Overrides(runtime); Absent(destination);
            using (var source = Open(Path.Combine(runtime, "python.exe"))) {
                using (var clone = new FileStream(destination, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None)) {
                    source.CopyTo(clone, 4096); clone.Flush(true); Equal(source, clone);
                }
                using (var clone = Open(destination)) Equal(source, clone);
            }
        }
        public static IDisposable Hold(string run, string state)
        {
            string runtime = Runtime(run, state); Overrides(runtime);
            FileStream source = null, clone = null;
            try {
                source = Open(Path.Combine(runtime, "python.exe")); clone = Open(Path.Combine(runtime, "startup-python.exe"));
                Equal(source, clone);
                return new Lease(source, clone);
            }
            catch { try { if (clone != null) clone.Dispose(); } finally { if (source != null) source.Dispose(); } throw; }
        }
        sealed class Lease : IDisposable
        {
            readonly FileStream source, clone;
            internal Lease(FileStream original, FileStream diagnostic) { source = original; clone = diagnostic; }
            public void Dispose() { try { clone.Dispose(); } finally { source.Dispose(); } }
        }
        // Authored tiny filesystem checks only; neither fixture bytes nor native APIs execute.
        public static void CheckValidation(string work)
        {
            string run = new string('d', 32), state = Path.Combine(work, "security-windows-" + run);
            Absent(state);
            string runtime = Path.Combine(state, "python"), original = Path.Combine(runtime, "python.exe");
            Directory.CreateDirectory(runtime);
            try {
                byte[] bytes = { 0, 1, 2, 127, 128, 255 };
                File.WriteAllBytes(original, bytes); Prepare(run, state);
                string clone = Path.Combine(runtime, "startup-python.exe");
                using (Hold(run, state)) {
                    if (!File.ReadAllBytes(original).SequenceEqual(bytes) || !File.ReadAllBytes(clone).SequenceEqual(bytes))
                        throw new InvalidOperationException("Python clone changed original or copied bytes");
                }
                Refuse(() => Prepare(run, state));
                File.WriteAllBytes(clone, new byte[] { 0, 1, 2, 127, 128, 254 }); Refuse(() => { using (Hold(run, state)) { } });
                File.WriteAllBytes(clone, bytes);
                string sidecar = Path.Combine(runtime, "startup-python._pth"); File.WriteAllText(sidecar, "fixture", new System.Text.UTF8Encoding(false));
                Refuse(() => { using (Hold(run, state)) { } });
                if (File.ReadAllText(sidecar, System.Text.Encoding.UTF8) != "fixture")
                    throw new InvalidOperationException("Python clone deleted an existing override");
                Refuse(() => Hold(new string('e', 32), state));
                File.Delete(sidecar); File.Delete(clone);
                Directory.CreateSymbolicLink(clone, Path.Combine(runtime, "absent-owned-fixture"));
                Refuse(() => Prepare(run, state));
                if ((File.GetAttributes(clone) & FileAttributes.ReparsePoint) == 0)
                    throw new InvalidOperationException("Python clone did not preserve dangling-link collision");
                Directory.Delete(clone);
            }
            finally { Directory.Delete(state, true); }
        }
        static void Refuse(Action action)
        {
            bool refused = false;
            try { action(); } catch (InvalidOperationException) { refused = true; }
            if (!refused) throw new InvalidOperationException("fixed Python clone refusal fixture was accepted");
        }
    }
}
