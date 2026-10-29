using System;
using System.Linq;
using System.Text;

namespace ScientificSecurity
{
    internal static class SxsTraceSuccess
    {
        static void Need(bool value, string stage)
        {
            if (!value) throw new SxsTraceSession.PrivateFailure(
                new InvalidOperationException("fixed collector evidence is inconclusive"), "collector-" + stage);
        }
        internal static string Parse(byte[] bytes, string manifest, string control)
        {
            Need(!String.IsNullOrEmpty(manifest) && !String.IsNullOrEmpty(control) &&
                !String.Equals(manifest, control, StringComparison.OrdinalIgnoreCase), "identity");
            string[] lines = SxsTraceEvidence.DecodeLines(bytes);
            bool inside = false, selectedControl = false, selectedConsumer = false;
            bool error = false, reference = false, unknownReference = false, succeeded = false;
            int blocks = 0, controls = 0, consumers = 0, fields = 0, terminal = 0;
            foreach (string raw in lines) {
                string line = raw.Trim(' ', '\t');
                if (line == "Begin Activation Context Generation.") {
                    Need(!inside && ++blocks <= 64, "begin"); inside = true;
                    selectedControl = selectedConsumer = error = reference = unknownReference = succeeded = false;
                    fields = terminal = 0; continue;
                }
                if (line == "End Activation Context Generation.") {
                    Need(inside, "end"); inside = false;
                    if (selectedControl) {
                        Need(++controls == 1 && fields == 1 && terminal == 1 && error && !reference && !succeeded, "positive");
                    }
                    if (selectedConsumer) {
                        Need(fields == 1 && !error && !unknownReference, "consumer"); consumers++;
                    }
                    continue;
                }
                if (!inside) { Need(line.Length == 0 || line.All(c => c == '='), "framing"); continue; }
                const string marker = "ManifestPath = ";
                if (line.StartsWith(marker, StringComparison.Ordinal)) {
                    Need(++fields == 1, "manifest");
                    string path = line.Substring(marker.Length);
                    selectedControl = String.Equals(path, control, StringComparison.OrdinalIgnoreCase);
                    selectedConsumer = String.Equals(path, manifest, StringComparison.OrdinalIgnoreCase);
                }
                bool failed = line == "ERROR: Activation Context generation failed.";
                // Control prohibitions win over opaque known-negative ERROR details.
                bool unresolved = line.StartsWith("ERROR: Cannot resolve reference ", StringComparison.Ordinal);
                bool referenced = line.StartsWith("INFO: Reference: ", StringComparison.Ordinal);
                reference |= unresolved || referenced;
                if (referenced) unknownReference |= !SxsTraceEvidence.KnownDependency(line.Substring(17));
                succeeded |= line.Contains("Activation Context generation succeeded.");
                error |= line.StartsWith("ERROR:", StringComparison.Ordinal);
                if (failed) terminal++;
            }
            Need(!inside && controls == 1, "final");
            return "WINDOWS_SXS_EVIDENCE phase=registry-authority collector_recording_verified=True consumer_qualified=True consumer_blocks=" +
                consumers + " child_visibility_claimed=False original_call_attributed=False cause_claimed=False target_admitted=False";
        }
        internal static void CheckValidation()
        {
            const string control = @"F:\private-control-sentinel\collector.manifest";
            const string consumer = @"F:\private-python-sentinel\DLLs\_ctypes.pyd";
            const string begin = "Begin Activation Context Generation.\n", end = "End Activation Context Generation.\n";
            string positive = begin + "ManifestPath = " + control + "\nERROR: invalid namespace\nERROR: Activation Context generation failed.\n" + end;
            string benign = begin + "ManifestPath = " + consumer + "\nINFO: Activation Context generation succeeded.\n" + end;
            Func<string, byte[]> utf8 = text => new byte[] { 239, 187, 191 }.Concat(new UTF8Encoding(false, true).GetBytes(text)).ToArray();
            Func<string, byte[]> utf16 = text => new byte[] { 255, 254 }.Concat(new UnicodeEncoding(false, false, true).GetBytes(text)).ToArray();
            for (int count = 0; count < 3; count++) {
                string text = String.Concat(Enumerable.Repeat(benign, count)) + positive;
                string result = Parse(utf8(text), consumer, control);
                SxsTraceSession.Need(result == Parse(utf16(text), consumer, control) &&
                    result.Contains("collector_recording_verified=True consumer_qualified=True consumer_blocks=" + count) &&
                    result.Contains("child_visibility_claimed=False") && !result.Contains("private-"));
            }
            foreach (string invalid in new [] {
                "", benign, positive + positive, positive.Replace(control, "wrong.manifest"),
                positive.Replace("ERROR: Activation Context generation failed.\n", ""),
                positive.Replace("ERROR: Activation Context generation failed.", "INFO: Activation Context generation succeeded."),
                positive.Replace(end, "ERROR: Activation Context generation failed.\n" + end),
                positive.Replace("ERROR: invalid namespace", "ERROR: Cannot resolve reference unknown"),
                positive.Replace("ERROR: invalid namespace", "INFO: Reference: unknown"),
                positive.Replace("ERROR: invalid namespace", "ERROR: Activation Context generation succeeded."),
                positive.Replace("ManifestPath = ", "ManifestPath = " + control + "\nManifestPath = "),
                positive + begin, positive + benign.Replace(end, ""), begin + positive,
                positive + end, positive + "private-outside-sentinel\n", positive + "\0", positive + "\r",
                positive + new string('x', 2049), positive + new string('\n', 4096),
                String.Concat(Enumerable.Repeat(benign, 64)) + positive,
                positive + benign.Replace("INFO: Activation Context generation succeeded.", "ERROR: Access is denied."),
                positive + benign.Replace("INFO: Activation Context generation succeeded.", "INFO: Reference: unknown"),
                positive + benign.Replace("ManifestPath = ", "ManifestPath = " + consumer + "\nManifestPath = ") }) {
                Exception caught = null;
                try { Parse(utf8(invalid), consumer, control); } catch (Exception error) { caught = error; }
                SxsTraceSession.Need(caught != null && !SxsTraceSession.Safe(caught, "collector-evidence").ToString().Contains("private-"));
            }
            foreach (byte[] invalid in new [] { new byte[0], new byte[] { 239, 187, 191 },
                new byte[] { 239, 187, 191, 255 }, new byte[] { 255, 254, 0 },
                new byte[] { 254, 255, 0, 0 }, Encoding.UTF8.GetBytes(positive), new byte[1048577] }) {
                bool refused = false; try { Parse(invalid, consumer, control); } catch (Exception) { refused = true; }
                SxsTraceSession.Need(refused);
            }
            bool aliased = false;
            try { Parse(utf8(positive), control, control); } catch (Exception) { aliased = true; }
            SxsTraceSession.Need(aliased);
            // A collector-positive block never satisfies the old failed-consumer classifier.
            bool oldRefused = false;
            try { SxsTraceEvidence.Parse(utf8(positive), consumer); } catch (Exception) { oldRefused = true; }
            SxsTraceSession.Need(oldRefused);
        }
    }
}
