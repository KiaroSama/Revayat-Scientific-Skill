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
    public static class ChildActivationFixture
    {
        static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
        static readonly UnicodeEncoding Unicode = new UnicodeEncoding(false, false, true);
        const string SourceDigest = "7aab129d14cde43907137227b5056fe7b77bddbe6f035d9b9621c06d48934391";
        sealed class Identity {
            internal string python, image, digest, imageDigest;
            internal long length;
        }
        static Identity prepared;

        internal static void RequireRole(bool preflight, bool wall, bool loader, bool native, bool clone)
        {
            if (!preflight || wall || loader || native || clone)
                throw new ArgumentException("child activation is a separate fixed trusted preflight diagnostic");
        }
        static void RequireIdentity(byte[] bytes, long length, string digest)
        {
            if (bytes.LongLength != length || Digest(bytes) != digest)
                throw new InvalidOperationException("activation prepared identity differs");
        }
        static string Numeric(string value)
        {
            if (String.IsNullOrEmpty(value) || value.Length > 1024 || value.IndexOf('\0') >= 0)
                throw new ArgumentException("activation build input exceeds fixed text contract");
            byte[] bytes = Unicode.GetBytes(value);
            try { return String.Join(",", value.Select(c => ((ushort)c).ToString(CultureInfo.InvariantCulture))) + ",0"; }
            finally { Array.Clear(bytes, 0, bytes.Length); }
        }
        static string Header(string python, ushort language)
        {
            if (!Path.IsPathFullyQualified(python) || Path.GetFullPath(python) != python ||
                !String.Equals(Path.GetFileName(python), "python.exe", StringComparison.Ordinal))
                throw new ArgumentException("activation build requires canonical prepared Python");
            return "static const unsigned short fixed_python[]={" + Numeric(python) + "};\n" +
                "static const unsigned short fixed_directory[]={" + Numeric(Path.GetDirectoryName(python)) + "};\n" +
                "static const unsigned short fixed_language=" + language.ToString(CultureInfo.InvariantCulture) + ";\n";
        }
        static void RequireMissing(string path)
        {
            NativeFixture.Plain(path, true);
            try { File.GetAttributes(path); }
            catch (FileNotFoundException) { return; }
            catch (DirectoryNotFoundException) { return; }
            throw new InvalidOperationException("fixed child activation output or override already exists");
        }
        static void NoOverrides(string image)
        {
            foreach (string path in new [] { image + ".manifest", Path.ChangeExtension(image, ".manifest"),
                image + ".config", Path.ChangeExtension(image, ".config") }) RequireMissing(path);
        }
        static FileStream New(string path, byte[] bytes)
        {
            RequireMissing(path);
            using (var created = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None)) {
                created.Write(bytes, 0, bytes.Length); created.Flush(true);
                if (!Read(created, 65536).SequenceEqual(bytes)) throw new InvalidOperationException("activation build input readback differs");
            }
            NativeFixture.Plain(path);
            var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            try {
                if (!Read(stream, 65536).SequenceEqual(bytes)) throw new InvalidOperationException("activation reopened build input differs");
                return stream;
            }
            catch { stream.Dispose(); throw; }
        }
        static byte[] Read(FileStream stream, int maximum)
        {
            if (stream.Length < 1 || stream.Length > maximum) throw new InvalidOperationException("activation held input exceeds fixed bound");
            stream.Position = 0;
            byte[] bytes = new byte[(int)stream.Length]; int position = 0;
            while (position < bytes.Length) {
                int count = stream.Read(bytes, position, bytes.Length - position);
                if (count == 0) throw new EndOfStreamException("activation held input is truncated");
                position += count;
            }
            if (stream.ReadByte() != -1) throw new InvalidOperationException("activation held input grew");
            return bytes;
        }
        static string Digest(byte[] bytes)
        { using (var hash = SHA256.Create()) return BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant(); }
        public static void Build(string windowsSource, string python, string state)
        {
            if (prepared != null) throw new InvalidOperationException("fixed child activation fixture was already prepared");
            python = Path.GetFullPath(python); state = Path.GetFullPath(state);
            if (!String.Equals(Path.GetDirectoryName(python), Path.Combine(state, "python"), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("activation fixture is outside owned prepared runtime");
            string source = Path.Combine(Path.GetFullPath(windowsSource), "StartupActivationNative.c");
            string generated = Path.Combine(state, "startup-activation.c"), header = Path.Combine(state, "startup-activation-input.h");
            string obj = Path.Combine(state, "startup-activation.obj"), image = Path.Combine(Path.GetDirectoryName(python), "startup-activation.exe");
            foreach (string path in new [] { source, python, state }) NativeFixture.Plain(path);
            foreach (string path in new [] { generated, header, obj, image }) RequireMissing(path);
            NoOverrides(image); NoOverrides(python);
            using (var heldPython = new FileStream(python, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var heldSource = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                byte[] pythonBytes = Read(heldPython, 16777216), sourceBytes = Read(heldSource, 65536);
                try {
                    byte[] normalized = Utf8.GetBytes(Utf8.GetString(sourceBytes).Replace("\r\n", "\n"));
                    Array.Clear(sourceBytes, 0, sourceBytes.Length); sourceBytes = normalized;
                    if (Digest(sourceBytes) != SourceDigest) throw new InvalidOperationException("fixed activation native source differs");
                    ushort language = KernelImage.PythonManifest(pythonBytes).Item1;
                    byte[] headerBytes = Utf8.GetBytes(Header(python, language));
                    using (var heldHeader = New(header, headerBytes))
                    using (var heldGenerated = New(generated, sourceBytes)) {
                        var tools = NativeFixture.CompilerTools(state);
                        TrustedSetup.Run(tools.Item1, new [] { "/nologo", "/c", "/TC", "/Od", "/Oi", "/GS-", "/Zl", "/Fo" + obj, generated }, state);
                        NativeFixture.Plain(obj);
                        TrustedSetup.Run(tools.Item2, new [] { "/nologo", "/NODEFAULTLIB", "/MANIFEST:NO", "/ENTRY:StartupEntry",
                            "/SUBSYSTEM:CONSOLE", "/MACHINE:X64", "/OUT:" + image, obj, tools.Item3 }, state);
                        if (!Read(heldHeader, 65536).SequenceEqual(headerBytes) || !Read(heldGenerated, 65536).SequenceEqual(sourceBytes))
                            throw new InvalidOperationException("activation compiler input changed");
                    }
                    NativeFixture.Plain(image); NoOverrides(image);
                    using (var heldImage = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                        byte[] imageBytes = Read(heldImage, 1048576);
                        try {
                            KernelImage.QualifyChildActivation(imageBytes);
                            prepared = new Identity { python = python, image = image, length = pythonBytes.Length,
                                digest = Digest(pythonBytes), imageDigest = Digest(imageBytes) };
                        }
                        finally { Array.Clear(imageBytes, 0, imageBytes.Length); }
                    }
                }
                finally { Array.Clear(pythonBytes, 0, pythonBytes.Length); Array.Clear(sourceBytes, 0, sourceBytes.Length); }
            }
        }
        public static IDisposable Hold(string python)
        {
            if (prepared == null || !String.Equals(python, prepared.python, StringComparison.Ordinal))
                throw new InvalidOperationException("activation fixture identity was not prepared");
            NativeFixture.Plain(python); NativeFixture.Plain(prepared.image); NoOverrides(python); NoOverrides(prepared.image);
            FileStream source = null, image = null;
            try {
                source = new FileStream(python, FileMode.Open, FileAccess.Read, FileShare.Read);
                image = new FileStream(prepared.image, FileMode.Open, FileAccess.Read, FileShare.Read);
                byte[] bytes = Read(source, 16777216), executable = null;
                try {
                    RequireIdentity(bytes, prepared.length, prepared.digest);
                    KernelImage.PythonManifest(bytes);
                    executable = Read(image, 1048576); KernelImage.QualifyChildActivation(executable);
                    RequireIdentity(executable, executable.Length, prepared.imageDigest);
                }
                finally { Array.Clear(bytes, 0, bytes.Length); if (executable != null) Array.Clear(executable, 0, executable.Length); }
                var result = new Lease(source, image); source = image = null; return result;
            }
            finally { try { if (source != null) source.Dispose(); } finally { if (image != null) image.Dispose(); } }
        }
        sealed class Lease : IDisposable {
            FileStream python, image;
            internal Lease(FileStream source, FileStream executable) { python = source; image = executable; }
            public void Dispose() {
                var first = python; var second = image; python = image = null;
                try { if (first != null) first.Dispose(); } finally { if (second != null) second.Dispose(); }
            }
        }
        internal static string RequireTransport(uint exit, string text, string errors)
        {
            if (exit != 0 || errors == null || errors.Length != 0)
                throw new InvalidOperationException("fixed child activation transport failed");
            return RequireResult(text);
        }
        public static string RequireResult(string text)
        {
            if (text == null || text.Length > 256) throw new InvalidOperationException("child activation result exceeds bound");
            var match = Regex.Match(text, "\\AWINDOWS_CHILD_ACTIVATION created=(True|False) win32_error=0x([0-9A-F]{8}) cause_claimed=False child_equivalence_claimed=False\\n\\z",
                RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
            if (!match.Success) throw new InvalidOperationException("child activation result is missing or malformed");
            uint error = UInt32.Parse(match.Groups[2].Value, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
            if ((match.Groups[1].Value == "True") != (error == 0))
                throw new InvalidOperationException("child activation result/error is inconsistent");
            return text.TrimEnd('\n');
        }
        public static void CheckValidation(string work)
        {
            RequireRole(true, false, false, false, false);
            foreach (bool[] invalid in new [] {
                new [] { false, false, false, false, false }, new [] { true, true, false, false, false },
                new [] { true, false, true, false, false }, new [] { true, false, false, true, false },
                new [] { true, false, false, false, true }
            }) {
                bool refused = false;
                try { RequireRole(invalid[0], invalid[1], invalid[2], invalid[3], invalid[4]); }
                catch (ArgumentException) { refused = true; }
                if (!refused) throw new InvalidOperationException("activation role overlap was accepted");
            }
            byte[] abc = { 97, 98, 99 };
            const string abcHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
            RequireIdentity(abc, 3, abcHash);
            foreach (Action invalid in new Action[] { () => RequireIdentity(abc, 4, abcHash), () => RequireIdentity(new byte[] {97,98,100}, 3, abcHash) }) {
                bool refused = false;
                try { invalid(); } catch (InvalidOperationException) { refused = true; }
                if (!refused) throw new InvalidOperationException("activation identity drift was accepted");
            }
            if (Numeric("A\"\\ی") != "65,34,92,1740,0")
                throw new InvalidOperationException("activation numeric UTF16 generation differs");
            foreach (string invalid in new [] { "", "a\0b", "\uD800", new string('a', 1025) }) {
                bool refused = false;
                try { Numeric(invalid); } catch (ArgumentException) { refused = true; }
                if (!refused) throw new InvalidOperationException("activation malformed build input accepted");
            }
            string success = "WINDOWS_CHILD_ACTIVATION created=True win32_error=0x00000000 cause_claimed=False child_equivalence_claimed=False\n";
            string denied = "WINDOWS_CHILD_ACTIVATION created=False win32_error=0x00000005 cause_claimed=False child_equivalence_claimed=False\n";
            if (RequireTransport(0, success, "") != success.TrimEnd('\n') || RequireTransport(0, denied, "") != denied.TrimEnd('\n'))
                throw new InvalidOperationException("child activation literal result differs");
            foreach (Action invalid in new Action[] {
                () => RequireTransport(0, success, "\n"), () => RequireTransport(0, success, " "),
                () => RequireTransport(1, success, ""), () => RequireTransport(1, "private-sentinel", "private-sentinel"),
                () => RequireTransport(0, "private-sentinel", ""), () => RequireTransport(0, success, "private-sentinel")
            }) {
                bool refused = false;
                try { invalid(); } catch (InvalidOperationException failure) {
                    if (failure.Message.Contains("private-sentinel")) throw new InvalidOperationException("activation transport leaked capture");
                    refused = true;
                }
                if (!refused) throw new InvalidOperationException("activation invalid transport was accepted");
            }
            foreach (string invalid in new [] { "", success + denied, success.TrimEnd('\n'), success.Replace("00000000", "00000005"),
                denied.Replace("00000005", "00000000"), denied.Replace("False", "false"), denied + "private-sentinel", new string('a', 257) }) {
                bool refused = false;
                try { RequireResult(invalid); } catch (InvalidOperationException failure) {
                    if (failure.Message.Contains("private-sentinel")) throw new InvalidOperationException("activation result refusal leaked payload");
                    refused = true;
                }
                if (!refused) throw new InvalidOperationException("child activation malformed result accepted");
            }
            string fixture = Path.Combine(Path.GetFullPath(work), "activation-collision-" + Guid.NewGuid().ToString("N"));
            NativeFixture.Plain(fixture, true); RequireMissing(fixture);
            Directory.CreateDirectory(fixture);
            string sentinel = Path.Combine(fixture, "owned.txt");
            try {
                using (var stream = New(sentinel, Utf8.GetBytes("unchanged"))) { }
                bool refused = false;
                try { using (var stream = New(sentinel, Utf8.GetBytes("replacement"))) { } }
                catch (InvalidOperationException) { refused = true; }
                if (!refused || File.ReadAllText(sentinel, Utf8) != "unchanged")
                    throw new InvalidOperationException("activation collision did not preserve sentinel");
                string link = Path.Combine(fixture, "dangling");
                Directory.CreateSymbolicLink(link, Path.Combine(fixture, "absent-owned"));
                try {
                    refused = false;
                    try { RequireMissing(link); } catch (InvalidOperationException) { refused = true; }
                    if (!refused || (File.GetAttributes(link) & FileAttributes.ReparsePoint) == 0)
                        throw new InvalidOperationException("activation dangling collision was not preserved");
                }
                finally { Directory.Delete(link); }
            }
            finally { File.Delete(sentinel); Directory.Delete(fixture); }
            KernelImage.CheckChildActivationValidation();
        }
    }
}
