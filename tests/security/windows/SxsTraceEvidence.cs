using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace ScientificSecurity
{
    // Private standard-tool text in, closed public dependency evidence out.
    internal static class SxsTraceEvidence
    {
        const string Begin = "Begin Activation Context Generation.", End = "End Activation Context Generation.";
        const string Unresolved = "ERROR: Cannot resolve reference ";
        static readonly Regex Dependency = new Regex(@"\A(?:Microsoft\.Windows\.Common-Controls|Microsoft\.VC(?:80|90|100|110|120|140)\.CRT)(?:,[A-Za-z]+=""[A-Za-z0-9.*_-]{1,64}""){0,6}\.?\z",
            RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
        enum Predicate { Length, ReadComplete, Bom, Nul, LineCount, LineWidth, Cr, Framing, Nested, BlockCount, End,
            SelectedCount, ManifestCount, Unsupported, Empty, Final, Output }
        static string Label(Predicate predicate)
        {
            switch (predicate) {
                case Predicate.Length: return "length";
                case Predicate.ReadComplete: return "read-complete";
                case Predicate.Bom: return "bom";
                case Predicate.Nul: return "nul";
                case Predicate.LineCount: return "line-count";
                case Predicate.LineWidth: return "line-width";
                case Predicate.Cr: return "cr";
                case Predicate.Framing: return "framing";
                case Predicate.Nested: return "nested";
                case Predicate.BlockCount: return "block-count";
                case Predicate.End: return "end";
                case Predicate.SelectedCount: return "selected-count";
                case Predicate.ManifestCount: return "manifest-count";
                case Predicate.Unsupported: return "unsupported";
                case Predicate.Empty: return "empty";
                case Predicate.Final: return "final";
                case Predicate.Output: return "output";
                default: throw new InvalidOperationException("unsupported fixed SxS evidence predicate");
            }
        }
        static void Check(bool value, Predicate predicate)
        {
            string label = Label(predicate);
            if (!value) throw new SxsTraceSession.PrivateFailure(
                new InvalidOperationException("fixed SxS evidence predicate rejected"), "evidence-" + label);
        }
        static bool KnownDependency(string identity)
        {
            try { return Dependency.IsMatch(identity); }
            catch (RegexMatchTimeoutException error) { throw SxsTraceSession.Safe(error, "evidence-regex"); }
        }
        internal static void RequireLength(string path, int maximum)
        {
            SxsTraceSession.Plain(path);
            using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                Check(file.Length > 0 && file.Length <= maximum, Predicate.Length);
        }
        internal static string Read(string path, string manifest)
        {
            RequireLength(path, 1048576);
            using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                Check(file.Length >= 2 && file.Length <= 1048576 && file.Length % 2 == 0, Predicate.Length);
                byte[] bytes = new byte[(int)file.Length]; int offset = 0;
                while (offset < bytes.Length) { int n = file.Read(bytes, offset, bytes.Length - offset); Check(n > 0, Predicate.ReadComplete); offset += n; }
                return Parse(bytes, manifest);
            }
        }
        internal static string Parse(byte[] bytes, string manifest)
        {
            Check(bytes != null && bytes.Length >= 2 && bytes.Length <= 1048576 && bytes.Length % 2 == 0, Predicate.Length);
            Check(bytes[0] == 255 && bytes[1] == 254, Predicate.Bom);
            string text;
            try { text = new UnicodeEncoding(false, false, true).GetString(bytes, 2, bytes.Length - 2); }
            catch (DecoderFallbackException error) { throw SxsTraceSession.Safe(error, "evidence-utf16"); }
            Check(!text.Contains('\0'), Predicate.Nul);
            string[] lines = text.Replace("\r\n", "\n").Split('\n');
            Check(lines.Length <= 4096, Predicate.LineCount);
            foreach (string line in lines) { Check(line.Length <= 2048, Predicate.LineWidth); Check(!line.Contains('\r'), Predicate.Cr); }
            bool inside = false, selected = false, unresolved = false, denied = false, malformed = false, failed = false;
            bool common = false, crt = false, unsupported = false; int blocks = 0, matches = 0, manifestFields = 0;
            string result = null;
            foreach (string raw in lines) {
                string line = raw.Trim(' ', '\t');
                if (line == Begin) {
                    Check(!inside, Predicate.Nested); Check(++blocks <= 64, Predicate.BlockCount); inside = true; selected = false; manifestFields = 0;
                    unresolved = denied = malformed = failed = common = crt = unsupported = false; continue;
                }
                if (line == End) {
                    Check(inside, Predicate.End); inside = false;
                    if (selected) {
                        Check(++matches == 1, Predicate.SelectedCount); Check(manifestFields == 1, Predicate.ManifestCount);
                        Check(!unsupported, Predicate.Unsupported); Check(unresolved || denied || malformed || failed, Predicate.Empty);
                        result = "unresolved_reference=" + unresolved + " access_denied=" + denied + " manifest_parse=" + malformed +
                            " activation_failed=" + failed + " common_controls=" + common + " vc_crt=" + crt;
                    }
                    continue;
                }
                if (!inside) { Check(line.Length == 0 || line.All(c => c == '='), Predicate.Framing); continue; }
                const string marker = "ManifestPath = ";
                if (line.StartsWith(marker, StringComparison.Ordinal)) {
                    Check(++manifestFields == 1, Predicate.ManifestCount);
                    selected = String.Equals(line.Substring(marker.Length), manifest, StringComparison.OrdinalIgnoreCase);
                }
                if (line.StartsWith(Unresolved, StringComparison.Ordinal)) {
                    string identity = line.Substring(Unresolved.Length);
                    if (KnownDependency(identity)) {
                        unresolved = true; common |= identity.StartsWith("Microsoft.Windows.Common-Controls", StringComparison.Ordinal);
                        crt |= identity.StartsWith("Microsoft.VC", StringComparison.Ordinal);
                    }
                    else unsupported = true;
                }
                bool knownDenied = line == "ERROR: Access is denied.";
                bool knownMalformed = line.StartsWith("ERROR: Manifest Parse Error", StringComparison.Ordinal);
                bool knownFailed = line == "ERROR: Activation Context generation failed.";
                if (line.StartsWith("ERROR:", StringComparison.Ordinal) && !line.StartsWith(Unresolved, StringComparison.Ordinal) &&
                    !knownDenied && !knownMalformed && !knownFailed) unsupported = true;
                const string reference = "INFO: Reference: ";
                if (line.StartsWith(reference, StringComparison.Ordinal) && !KnownDependency(line.Substring(reference.Length))) unsupported = true;
                denied |= knownDenied; malformed |= knownMalformed; failed |= knownFailed;
            }
            Check(!inside && matches == 1 && result != null, Predicate.Final);
            string output = "WINDOWS_SXS_EVIDENCE phase=registry-authority manifest=ctypes blocks=" + matches + " " + result +
                " original_call_attributed=False cause_claimed=False target_admitted=False";
            Check(output.Length <= 4096, Predicate.Output); return output;
        }
        internal static void CheckReportingValidation()
        {
            Exception caught = null;
            try { Parse(new byte[0], "private-manifest-sentinel"); }
            catch (Exception error) { caught = error; }
            SxsTraceSession.Need(caught is SxsTraceSession.PrivateFailure && caught.InnerException == null &&
                caught.Message == "fixed SxS trace failed stage=evidence-length raw_error_withheld=True" &&
                !caught.ToString().Contains("sentinel"));
            const string manifest = "F:\\private-manifest-sentinel\\_ctypes.pyd";
            string block = Begin + "\nManifestPath = " + manifest + "\nERROR: Activation Context generation failed.\n" + End + "\n";
            Func<string, byte[]> encode = value => new byte[] { 255, 254 }.Concat(new UnicodeEncoding(false, false, true).GetBytes(value)).ToArray();
            Action<byte[], string> refuse = (bytes, label) => {
                Exception failure = null;
                try { Parse(bytes, manifest); } catch (Exception error) { failure = error; }
                SxsTraceSession.Need(failure is SxsTraceSession.PrivateFailure && failure.InnerException == null &&
                    failure.Message == "fixed SxS trace failed stage=evidence-" + label + " raw_error_withheld=True" &&
                    !failure.ToString().Contains("sentinel"));
            };
            SxsTraceSession.Need(Parse(encode(block), manifest).Contains("activation_failed=True"));
            refuse(null, "length"); refuse(new byte[1048578], "length"); refuse(new byte[3], "length");
            refuse(new byte[2], "bom"); refuse(encode("\0"), "nul");
            refuse(encode(new string('\n', 4096)), "line-count");
            refuse(encode("\r\n" + new string('x', 2049)), "line-width");
            refuse(encode("\r\n\rx\n" + new string('x', 2049)), "cr");
            refuse(encode("private-framing-sentinel"), "framing");
            refuse(encode(Begin + "\n" + block), "nested");
            refuse(encode(String.Concat(Enumerable.Repeat(Begin + "\n" + End + "\n", 65))), "block-count");
            refuse(encode(End), "end"); refuse(encode(block + block), "selected-count");
            refuse(encode(block.Replace("ManifestPath = ", "ManifestPath = " + manifest + "\nManifestPath = ")), "manifest-count");
            refuse(encode(block.Replace("ERROR: Activation Context generation failed.", "ERROR: private-error-sentinel")), "unsupported");
            refuse(encode(block.Replace("ERROR: Activation Context generation failed.", "INFO: benign")), "empty");
            refuse(encode(block.Replace(End, "")), "final");
            refuse(new byte[] { 255, 254, 0, 216 }, "utf16");
            foreach (Predicate predicate in Enum.GetValues(typeof(Predicate))) {
                Check(true, predicate); Exception failure = null;
                try { Check(false, predicate); } catch (Exception error) { failure = error; }
                SxsTraceSession.Need(failure is SxsTraceSession.PrivateFailure && failure.Message ==
                    "fixed SxS trace failed stage=evidence-" + Label(predicate) + " raw_error_withheld=True");
            }
            foreach (int invalid in new [] { -1, 17, Int32.MaxValue }) {
                bool rejected = false;
                try { Check(true, (Predicate)invalid); } catch (InvalidOperationException) { rejected = true; }
                SxsTraceSession.Need(rejected);
            }
        }
        internal static void CheckValidation()
        {
            const string manifest = "F:\\python\\DLLs\\_ctypes.pyd";
            string block = Begin + "\nManifestPath = " + manifest + "\nERROR: Cannot resolve reference Microsoft.Windows.Common-Controls,type=\"win32\",version=\"6.0.0.0\".\nERROR: Activation Context generation failed.\n" + End + "\n";
            Func<string, byte[]> encode = s => new byte[] { 255, 254 }.Concat(new UnicodeEncoding(false, false, true).GetBytes(s)).ToArray();
            string result = Parse(encode(block), manifest);
            SxsTraceSession.Need(result.Contains("unresolved_reference=True") && result.Contains("common_controls=True") && !result.Contains(manifest));
            SxsTraceSession.Need(Parse(encode(block.Replace(End, "INFO: Reference: Microsoft.Windows.Common-Controls,type=\"win32\"\n" + End)), manifest).Contains("common_controls=True"));
            foreach (byte[] invalid in new [] { new byte[0], Encoding.UTF8.GetBytes(block), encode(block.Replace(End, "")),
                encode(block + block), encode(block.Replace(manifest, "private-path-sentinel")),
                encode(block.Replace("Microsoft.Windows.Common-Controls", "private-dependency-sentinel")), encode(new string('x', 2049)),
                encode(block.Replace(Unresolved + "Microsoft.Windows.Common-Controls", "ERROR: private-error-sentinel")),
                encode(block.Replace(End, "INFO: Reference: private-reference-sentinel\n" + End)),
                encode(Begin + "\nManifestPath = " + manifest + "\nINFO: benign observation\n" + End),
                encode(block).Concat(new byte[] { 0, 216 }).ToArray() }) {
                bool rejected = false;
                try { Parse(invalid, manifest); }
                catch (Exception failure) {
                    var retained = failure as SxsTraceSession.PrivateFailure;
                    Exception original = retained == null ? failure : retained.Original;
                    SxsTraceSession.Need(original is InvalidOperationException || original is DecoderFallbackException);
                    var safe = SxsTraceSession.Safe(failure, "parse");
                    SxsTraceSession.Need(!safe.ToString().Contains("sentinel") && safe.InnerException == null);
                    rejected = true;
                }
                SxsTraceSession.Need(rejected);
            }
        }
    }
}
