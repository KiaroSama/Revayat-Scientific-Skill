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
        enum Predicate { ReadComplete, Bom, Nul, LineCount, LineWidth, Cr, Framing, Nested, BlockCount, End,
            SelectedCount, ManifestCount, Unsupported, Empty, Final, Output }
        static string Label(Predicate predicate)
        {
            switch (predicate) {
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
        enum LengthPhase { FileBound, ReadShape, InputShape }
        static string LengthLabel(LengthPhase phase)
        {
            switch (phase) {
                case LengthPhase.FileBound: return "file-bound";
                case LengthPhase.ReadShape: return "read-shape";
                case LengthPhase.InputShape: return "input-shape";
                default: throw new InvalidOperationException("unsupported fixed SxS length phase");
            }
        }
        static SxsTraceSession.PrivateFailure LengthFailure(string phase, string comparison, long? observed, int maximum, bool? even)
        {
            return new SxsTraceSession.PrivateFailure(new InvalidOperationException("fixed SxS evidence length rejected"),
                "evidence-length-" + phase + " comparison=" + comparison + " observed_bytes=" +
                (observed.HasValue ? observed.Value.ToString(System.Globalization.CultureInfo.InvariantCulture) : "absent") +
                " maximum_bytes=" + maximum.ToString(System.Globalization.CultureInfo.InvariantCulture) +
                " even=" + (even.HasValue ? even.Value.ToString() : "not-evaluated"));
        }
        sealed class PrefixObservation
        {
            internal readonly SxsTraceSession.PrivateFailure Report;
            internal PrefixObservation(SxsTraceSession.PrivateFailure report) { Report = report; }
        }
        static SxsTraceSession.PrivateFailure CombinePrivate(Exception first, Exception second, string secondStage)
        {
            var left = (SxsTraceSession.PrivateFailure)SxsTraceSession.Safe(first, "text-read");
            var right = (SxsTraceSession.PrivateFailure)SxsTraceSession.Safe(second, secondStage);
            return new SxsTraceSession.PrivateFailure(new AggregateException("fixed SxS rejected evidence", left, right),
                left.SafeStage + " " + right.SafeStage);
        }
        static SxsTraceSession.PrivateFailure Supplement(SxsTraceSession.PrivateFailure original, Func<PrefixObservation> inspect)
        {
            PrefixObservation observation;
            try { observation = inspect(); }
            catch (Exception error) { observation = PrefixReport("unavailable", "unavailable", null, error); }
            if (observation == null || observation.Report == null)
                observation = PrefixReport("unavailable", "unavailable", null);
            return CombinePrivate(original, observation.Report, "evidence-prefix");
        }
        static void RequireSize(Func<long> length, int maximum, LengthPhase phase, Func<PrefixObservation> inspectThree = null)
        {
            string label = LengthLabel(phase);
            if (phase == LengthPhase.InputShape && length == null) throw LengthFailure(label, "present", null, maximum, null);
            // Retain each short-circuited observation; a changing file has no single snapshot length.
            long observed = length();
            if (phase == LengthPhase.FileBound ? observed <= 0 : observed < 2) throw LengthFailure(label, "minimum", observed, maximum, null);
            observed = length();
            if (observed > maximum) throw LengthFailure(label, "maximum", observed, maximum, null);
            if (phase != LengthPhase.FileBound) {
                observed = length();
                if (observed % 2 != 0) {
                    var original = LengthFailure(label, "even", observed, maximum, false);
                    if (phase == LengthPhase.ReadShape && observed >= 2 && observed <= maximum && inspectThree != null) throw Supplement(original, inspectThree);
                    throw original;
                }
            }
        }
        static string Signature(byte[] bytes, int count)
        {
            SxsTraceSession.Need(count >= 0 && count <= 3 && (bytes == null ? count == 0 : count <= bytes.Length));
            if (count == 0) return "absent";
            if (count >= 3 && bytes[0] == 239 && bytes[1] == 187 && bytes[2] == 191) return "utf8-bom";
            if (count >= 2 && bytes[0] == 255 && bytes[1] == 254) return "utf16le-prefix";
            return "other";
        }
        static PrefixObservation PrefixReport(string status, string signature, int? transferred, Exception original = null)
        {
            return new PrefixObservation(new SxsTraceSession.PrivateFailure(original ?? new InvalidOperationException("fixed SxS prefix observation"),
                "evidence-prefix status=" + status + " signature=" + signature + " transferred_bytes=" +
                (transferred.HasValue ? transferred.Value.ToString(System.Globalization.CultureInfo.InvariantCulture) : "unavailable")));
        }
        static PrefixObservation InspectThree(Stream stream)
        {
            var bytes = new byte[3]; int transferred = 0;
            try {
                try {
                    while (transferred < 3) {
                        int count = stream.Read(bytes, transferred, 3 - transferred);
                        SxsTraceSession.Need(count >= 0 && count <= 3 - transferred);
                        if (count == 0) return PrefixReport("short", Signature(bytes, transferred), transferred);
                        transferred += count;
                    }
                }
                catch (Exception error) { return PrefixReport("read-error", "unavailable", transferred, error); }
                return PrefixReport("complete", Signature(bytes, transferred), transferred);
            }
            finally { Array.Clear(bytes, 0, bytes.Length); }
        }
        static PrefixObservation InspectArray(byte[] bytes)
        {
            int count = bytes == null ? 0 : Math.Min(3, bytes.Length);
            return PrefixReport("array", Signature(bytes, count), count);
        }
        internal static void RequireLength(string path, int maximum)
        {
            SxsTraceSession.Plain(path);
            using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                RequireSize(() => file.Length, maximum, LengthPhase.FileBound);
        }
        internal static string Read(string path, string manifest)
        {
            RequireLength(path, 1048576);
            return ReadOwned(() => new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read), manifest);
        }
        static string ReadOwned(Func<Stream> open, string manifest)
        {
            Stream file = null; Exception primary = null;
            try {
                file = open();
                RequireSize(() => file.Length, 1048576, LengthPhase.ReadShape, () => InspectThree(file));
                byte[] bytes = new byte[(int)file.Length]; int offset = 0;
                while (offset < bytes.Length) { int n = file.Read(bytes, offset, bytes.Length - offset); Check(n > 0, Predicate.ReadComplete); offset += n; }
                return Parse(bytes, manifest);
            }
            catch (Exception error) { primary = error; throw; }
            finally {
                try { if (file != null) file.Dispose(); }
                catch (Exception error) {
                    var safe = new SxsTraceSession.PrivateFailure(error, "evidence-close");
                    if (primary != null) throw CombinePrivate(primary, safe, "evidence-close");
                    throw safe;
                }
            }
        }
        internal static string Parse(byte[] bytes, string manifest)
        {
            Func<long> length = bytes == null ? (Func<long>)null : () => bytes.Length;
            try { RequireSize(length, 1048576, LengthPhase.InputShape); }
            catch (SxsTraceSession.PrivateFailure original) { throw Supplement(original, () => InspectArray(bytes)); }
            try { Check(bytes[0] == 255 && bytes[1] == 254, Predicate.Bom); }
            catch (SxsTraceSession.PrivateFailure original) { throw Supplement(original, () => InspectArray(bytes)); }
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
        static void CheckLengthValidation()
        {
            long[][] observations = { new long[] { 0 }, new long[] { 1, 9 }, new long[] { 8, 0 },
                new long[] { 1 }, new long[] { 2, 9 }, new long[] { 2, 8, 3 }, new long[] { 2, 8, 8 },
                new long[] { Int64.MinValue }, new long[] { 1, Int64.MaxValue } };
            LengthPhase[] phases = { LengthPhase.FileBound, LengthPhase.FileBound, LengthPhase.FileBound,
                LengthPhase.ReadShape, LengthPhase.ReadShape, LengthPhase.ReadShape, LengthPhase.ReadShape,
                LengthPhase.FileBound, LengthPhase.FileBound };
            string[] failures = {
                "file-bound comparison=minimum observed_bytes=0 maximum_bytes=8 even=not-evaluated",
                "file-bound comparison=maximum observed_bytes=9 maximum_bytes=8 even=not-evaluated", null,
                "read-shape comparison=minimum observed_bytes=1 maximum_bytes=8 even=not-evaluated",
                "read-shape comparison=maximum observed_bytes=9 maximum_bytes=8 even=not-evaluated",
                "read-shape comparison=even observed_bytes=3 maximum_bytes=8 even=False", null,
                "file-bound comparison=minimum observed_bytes=-9223372036854775808 maximum_bytes=8 even=not-evaluated",
                "file-bound comparison=maximum observed_bytes=9223372036854775807 maximum_bytes=8 even=not-evaluated" };
            for (int index = 0; index < observations.Length; index++) {
                int reads = 0; Exception caught = null; long[] values = observations[index];
                try { RequireSize(() => { SxsTraceSession.Need(reads < values.Length); return values[reads++]; }, 8, phases[index]); }
                catch (Exception error) { caught = error; }
                SxsTraceSession.Need(reads == values.Length);
                if (failures[index] == null) SxsTraceSession.Need(caught == null);
                else SxsTraceSession.Need(caught is SxsTraceSession.PrivateFailure && caught.InnerException == null && caught.Message ==
                    "fixed SxS trace failed stage=evidence-length-" + failures[index] + " raw_error_withheld=True");
            }
            foreach (int maximum in new [] { 1048576, 8388608 }) {
                int reads = 0; RequireSize(() => { reads++; return maximum; }, maximum, LengthPhase.FileBound);
                SxsTraceSession.Need(reads == 2);
                reads = 0; RequireSize(() => { reads++; return maximum; }, maximum, LengthPhase.ReadShape);
                SxsTraceSession.Need(reads == 3);
            }
            foreach (LengthPhase phase in Enum.GetValues(typeof(LengthPhase))) {
                for (int failAt = 1; failAt <= (phase == LengthPhase.FileBound ? 2 : 3); failAt++) {
                    var raw = new IOException("private-length-sentinel"); int reads = 0; Exception caught = null;
                    try { RequireSize(() => { if (++reads == failAt) throw raw; return 2; }, 8, phase); }
                    catch (Exception error) { caught = error; }
                    SxsTraceSession.Need(reads == failAt && Object.ReferenceEquals(caught, raw));
                }
            }
            foreach (int invalid in new [] { -1, 3, Int32.MaxValue }) {
                int reads = 0; bool refused = false;
                try { RequireSize(() => { reads++; return 2; }, 8, (LengthPhase)invalid); }
                catch (InvalidOperationException) { refused = true; }
                SxsTraceSession.Need(refused && reads == 0);
            }
        }
        sealed class PrefixStream : MemoryStream
        {
            internal byte[] retained;
            internal int reads, lengths, closes, mode;
            internal long? observed;
            internal PrefixStream(byte[] bytes) : base(bytes) { }
            public override long Length { get { lengths++; return observed ?? base.Length; } }
            public override int Read(byte[] bytes, int offset, int count)
            {
                retained = bytes; reads++; SxsTraceSession.Need(count > 0 && (mode == 7 || count <= 3 && offset + count <= 3));
                if (mode == 2 || mode == 5 && reads == 2 || mode == 6) throw new IOException("private-prefix-read-sentinel");
                if (mode == 3) return 4;
                return base.Read(bytes, offset, mode == 1 || mode == 5 ? Math.Min(1, count) : count);
            }
            protected override void Dispose(bool disposing)
            { closes++; base.Dispose(disposing); if (mode == 4 || mode == 6) throw new IOException("private-prefix-close-sentinel"); }
        }
        static void CheckPrefixValidation()
        {
            byte[][] inputs = { null, new byte[0], new byte[] { 239 }, new byte[] { 239, 187 },
                new byte[] { 239, 187, 191 }, new byte[] { 255, 254 }, new byte[] { 255, 254, 0 }, new byte[] { 239, 187, 0 } };
            string[] signatures = { "absent", "absent", "other", "other", "utf8-bom", "utf16le-prefix", "utf16le-prefix", "other" };
            for (int index = 0; index < inputs.Length; index++) {
                var report = InspectArray(inputs[index]).Report;
                int count = inputs[index] == null ? 0 : inputs[index].Length;
                SxsTraceSession.Need(report.Message == "fixed SxS trace failed stage=evidence-prefix status=array signature=" +
                    signatures[index] + " transferred_bytes=" + count + " raw_error_withheld=True");
            }
            for (int mode = 0; mode <= 6; mode++) {
                var stream = new PrefixStream(new byte[] { 239, 187, 191 }) { mode = mode };
                Exception caught = null;
                try { ReadOwned(() => stream, "private-manifest-sentinel"); } catch (Exception error) { caught = error; }
                var safe = caught as SxsTraceSession.PrivateFailure;
                SxsTraceSession.Need(safe != null && stream.lengths == 3 && stream.closes == 1 &&
                    stream.reads == (mode == 1 ? 3 : mode == 5 ? 2 : 1) && stream.retained.All(value => value == 0) &&
                    safe.Message.StartsWith("fixed SxS trace failed stage=evidence-length-read-shape comparison=even observed_bytes=3 maximum_bytes=1048576 even=False ", StringComparison.Ordinal) &&
                    !safe.ToString().Contains("sentinel") && safe.InnerException == null);
                var group = safe.Original as AggregateException;
                SxsTraceSession.Need(group != null && group.InnerExceptions.Count == 2);
                if (mode == 4 || mode == 6) {
                    SxsTraceSession.Need(group.InnerExceptions[0] is SxsTraceSession.PrivateFailure &&
                        ((SxsTraceSession.PrivateFailure)group.InnerExceptions[0]).Original is AggregateException &&
                        ((SxsTraceSession.PrivateFailure)group.InnerExceptions[1]).SafeStage == "evidence-close");
                }
                else SxsTraceSession.Need(((SxsTraceSession.PrivateFailure)group.InnerExceptions[0]).SafeStage ==
                    "evidence-length-read-shape comparison=even observed_bytes=3 maximum_bytes=1048576 even=False");
                if (mode == 2 || mode == 3 || mode == 6) SxsTraceSession.Need(safe.Message.Contains("status=read-error signature=unavailable transferred_bytes=0"));
                else if (mode == 5) SxsTraceSession.Need(safe.Message.Contains("status=read-error signature=unavailable transferred_bytes=1"));
                else SxsTraceSession.Need(safe.Message.Contains("status=complete signature=utf8-bom transferred_bytes=3"));
            }
            for (int size = 0; size < 3; size++) {
                var stream = new PrefixStream(new byte[size]); var result = InspectThree(stream).Report;
                SxsTraceSession.Need(result.Message.Contains("status=short signature=" + (size == 0 ? "absent" : "other") + " transferred_bytes=" + size) &&
                    stream.lengths == 0 && stream.reads == (size == 0 ? 1 : 2) && stream.retained.All(value => value == 0));
                stream.Dispose();
            }
            for (int size = 0; size < 3; size++) {
                var stream = new PrefixStream(new byte[size]) { observed = 3 }; Exception caught = null;
                try { ReadOwned(() => stream, "private-manifest-sentinel"); } catch (Exception error) { caught = error; }
                var safe = caught as SxsTraceSession.PrivateFailure;
                SxsTraceSession.Need(safe != null && stream.lengths == 3 && stream.closes == 1 &&
                    stream.reads == (size == 0 ? 1 : 2) && stream.retained.All(value => value == 0) &&
                    safe.Message.Contains("observed_bytes=3") && safe.Message.Contains("status=short signature=" +
                        (size == 0 ? "absent" : "other") + " transferred_bytes=" + size) && !safe.ToString().Contains("sentinel"));
            }
            foreach (int size in new [] { 5, 3177 }) {
                var stream = new PrefixStream(new byte[] { 239, 187, 191 }) { observed = size }; Exception caught = null;
                try { ReadOwned(() => stream, "private-manifest-sentinel"); } catch (Exception error) { caught = error; }
                SxsTraceSession.Need(caught is SxsTraceSession.PrivateFailure && stream.lengths == 3 && stream.reads == 1 &&
                    stream.closes == 1 && stream.retained.All(value => value == 0) &&
                    caught.Message.Contains("observed_bytes=" + size) &&
                    caught.Message.Contains("status=complete signature=utf8-bom transferred_bytes=3"));
            }
            foreach (long third in new long[] { -1, 1, 1048577, Int64.MaxValue }) {
                int reads = 0, inspections = 0; Exception caught = null;
                try { RequireSize(() => ++reads < 3 ? 2 : third, 1048576, LengthPhase.ReadShape,
                    () => { inspections++; return InspectArray(null); }); } catch (Exception error) { caught = error; }
                SxsTraceSession.Need(caught is SxsTraceSession.PrivateFailure && reads == 3 && inspections == 0 &&
                    !caught.Message.Contains("evidence-prefix"));
            }
            foreach (LengthPhase phase in new [] { LengthPhase.FileBound, LengthPhase.InputShape }) {
                int inspections = 0; Exception caught = null;
                try { RequireSize(() => 5, 1048576, phase, () => { inspections++; return InspectArray(null); }); }
                catch (Exception error) { caught = error; }
                SxsTraceSession.Need(inspections == 0 && (phase == LengthPhase.FileBound ? caught == null : caught is SxsTraceSession.PrivateFailure));
            }
            foreach (int size in new [] { 0, 1, 1048577 }) {
                var stream = new PrefixStream(new byte[size]); Exception caught = null;
                try { ReadOwned(() => stream, "private-manifest-sentinel"); } catch (Exception error) { caught = error; }
                SxsTraceSession.Need(caught is SxsTraceSession.PrivateFailure && stream.reads == 0 && stream.closes == 1 &&
                    !caught.Message.Contains("evidence-prefix"));
            }
            const string manifest = "F:\\private-manifest-sentinel\\_ctypes.pyd";
            string block = Begin + "\nManifestPath = " + manifest + "\nERROR: Activation Context generation failed.\n" + End + "\n";
            byte[] valid = new byte[] { 255, 254 }.Concat(new UnicodeEncoding(false, false, true).GetBytes(block)).ToArray();
            var positive = new PrefixStream(valid) { mode = 7 };
            SxsTraceSession.Need(ReadOwned(() => positive, manifest).Contains("activation_failed=True") &&
                positive.lengths == 4 && positive.reads == 1 && positive.closes == 1);
            Exception absent = null; var openError = new IOException("private-open-sentinel");
            try { ReadOwned(() => { throw openError; }, manifest); } catch (Exception error) { absent = error; }
            SxsTraceSession.Need(Object.ReferenceEquals(absent, openError));
            var original = LengthFailure("read-shape", "even", 3, 1048576, false);
            for (int mode = 0; mode < 4; mode++) {
                int selected = mode;
                var safe = Supplement(original, () => {
                    if (selected == 0) return InspectArray(new byte[] { 239, 187, 191 });
                    if (selected == 1) throw new IOException("private-callback-sentinel");
                    if (selected == 2) throw new SxsTraceSession.PrivateFailure(new IOException("private-callback-sentinel"), "unrelated-stage");
                    return null;
                });
                var group = (AggregateException)safe.Original;
                SxsTraceSession.Need(Object.ReferenceEquals(group.InnerExceptions[0], original) && group.InnerExceptions.Count == 2 &&
                    safe.Message.Contains(mode == 0 ? "status=array signature=utf8-bom transferred_bytes=3" :
                        "status=unavailable signature=unavailable transferred_bytes=unavailable") &&
                    !safe.ToString().Contains("sentinel") && !safe.Message.Contains("unrelated-stage"));
            }
            var field = typeof(SxsTraceSession.PrivateFailure).GetField("SafeStage", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
            SxsTraceSession.Need(field != null && field.IsInitOnly && original.SafeStage ==
                "evidence-length-read-shape comparison=even observed_bytes=3 maximum_bytes=1048576 even=False");
        }
        internal static void CheckReportingValidation()
        {
            CheckLengthValidation(); CheckPrefixValidation();
            Exception caught = null;
            try { Parse(new byte[0], "private-manifest-sentinel"); }
            catch (Exception error) { caught = error; }
            SxsTraceSession.Need(caught is SxsTraceSession.PrivateFailure && caught.InnerException == null &&
                caught.Message == "fixed SxS trace failed stage=evidence-length-input-shape comparison=minimum observed_bytes=0 maximum_bytes=1048576 even=not-evaluated evidence-prefix status=array signature=absent transferred_bytes=0 raw_error_withheld=True" &&
                !caught.ToString().Contains("sentinel"));
            const string manifest = "F:\\private-manifest-sentinel\\_ctypes.pyd";
            string block = Begin + "\nManifestPath = " + manifest + "\nERROR: Activation Context generation failed.\n" + End + "\n";
            Func<string, byte[]> encode = value => new byte[] { 255, 254 }.Concat(new UnicodeEncoding(false, false, true).GetBytes(value)).ToArray();
            Action<byte[], string> refuse = (bytes, label) => {
                Exception failure = null;
                try { Parse(bytes, manifest); } catch (Exception error) { failure = error; }
                string prefix = label.StartsWith("length-input-shape", StringComparison.Ordinal) || label == "bom" ?
                    " evidence-prefix status=array signature=" + (bytes == null || bytes.Length == 0 ? "absent" : "other") +
                    " transferred_bytes=" + (bytes == null ? 0 : Math.Min(3, bytes.Length)) : "";
                SxsTraceSession.Need(failure is SxsTraceSession.PrivateFailure && failure.InnerException == null &&
                    failure.Message == "fixed SxS trace failed stage=evidence-" + label + prefix + " raw_error_withheld=True" &&
                    !failure.ToString().Contains("sentinel"));
            };
            SxsTraceSession.Need(Parse(encode(block), manifest).Contains("activation_failed=True"));
            refuse(null, "length-input-shape comparison=present observed_bytes=absent maximum_bytes=1048576 even=not-evaluated");
            refuse(new byte[1], "length-input-shape comparison=minimum observed_bytes=1 maximum_bytes=1048576 even=not-evaluated");
            refuse(new byte[1048578], "length-input-shape comparison=maximum observed_bytes=1048578 maximum_bytes=1048576 even=not-evaluated");
            refuse(new byte[3], "length-input-shape comparison=even observed_bytes=3 maximum_bytes=1048576 even=False");
            refuse(new byte[1048576], "bom");
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
            foreach (int invalid in new [] { -1, 16, Int32.MaxValue }) {
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
                    if (original is AggregateException) original = ((SxsTraceSession.PrivateFailure)((AggregateException)original).InnerExceptions[0]).Original;
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
