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
        internal static void RequireLength(string path, int maximum)
        {
            SxsTraceSession.Plain(path);
            using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                SxsTraceSession.Need(file.Length > 0 && file.Length <= maximum);
        }
        internal static string Read(string path, string manifest)
        {
            RequireLength(path, 1048576);
            using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                SxsTraceSession.Need(file.Length >= 2 && file.Length <= 1048576 && file.Length % 2 == 0);
                byte[] bytes = new byte[(int)file.Length]; int offset = 0;
                while (offset < bytes.Length) { int n = file.Read(bytes, offset, bytes.Length - offset); SxsTraceSession.Need(n > 0); offset += n; }
                return Parse(bytes, manifest);
            }
        }
        internal static string Parse(byte[] bytes, string manifest)
        {
            SxsTraceSession.Need(bytes != null && bytes.Length >= 2 && bytes.Length <= 1048576 && bytes.Length % 2 == 0 && bytes[0] == 255 && bytes[1] == 254);
            string text = new UnicodeEncoding(false, false, true).GetString(bytes, 2, bytes.Length - 2);
            SxsTraceSession.Need(!text.Contains('\0'));
            string[] lines = text.Replace("\r\n", "\n").Split('\n');
            SxsTraceSession.Need(lines.Length <= 4096 && lines.All(s => s.Length <= 2048 && !s.Contains('\r')));
            bool inside = false, selected = false, unresolved = false, denied = false, malformed = false, failed = false;
            bool common = false, crt = false, unsupported = false; int blocks = 0, matches = 0, manifestFields = 0;
            string result = null;
            foreach (string raw in lines) {
                string line = raw.Trim(' ', '\t');
                if (line == Begin) {
                    SxsTraceSession.Need(!inside && ++blocks <= 64); inside = true; selected = false; manifestFields = 0;
                    unresolved = denied = malformed = failed = common = crt = unsupported = false; continue;
                }
                if (line == End) {
                    SxsTraceSession.Need(inside); inside = false;
                    if (selected) {
                        SxsTraceSession.Need(++matches == 1 && manifestFields == 1 && !unsupported && (unresolved || denied || malformed || failed));
                        result = "unresolved_reference=" + unresolved + " access_denied=" + denied + " manifest_parse=" + malformed +
                            " activation_failed=" + failed + " common_controls=" + common + " vc_crt=" + crt;
                    }
                    continue;
                }
                if (!inside) { SxsTraceSession.Need(line.Length == 0 || line.All(c => c == '=')); continue; }
                const string marker = "ManifestPath = ";
                if (line.StartsWith(marker, StringComparison.Ordinal)) {
                    SxsTraceSession.Need(++manifestFields == 1);
                    selected = String.Equals(line.Substring(marker.Length), manifest, StringComparison.OrdinalIgnoreCase);
                }
                if (line.StartsWith(Unresolved, StringComparison.Ordinal)) {
                    string identity = line.Substring(Unresolved.Length);
                    if (Dependency.IsMatch(identity)) {
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
                if (line.StartsWith(reference, StringComparison.Ordinal) && !Dependency.IsMatch(line.Substring(reference.Length))) unsupported = true;
                denied |= knownDenied; malformed |= knownMalformed; failed |= knownFailed;
            }
            SxsTraceSession.Need(!inside && matches == 1 && result != null);
            string output = "WINDOWS_SXS_EVIDENCE phase=registry-authority manifest=ctypes blocks=" + matches + " " + result +
                " original_call_attributed=False cause_claimed=False target_admitted=False";
            SxsTraceSession.Need(output.Length <= 4096); return output;
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
                    SxsTraceSession.Need(failure is InvalidOperationException || failure is DecoderFallbackException);
                    var safe = SxsTraceSession.Safe(failure, "parse");
                    SxsTraceSession.Need(!safe.ToString().Contains("sentinel") && safe.InnerException == null);
                    rejected = true;
                }
                SxsTraceSession.Need(rejected);
            }
        }
    }
}
