using System;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace ScientificSecurity
{
    // A captured original receipt is failure evidence, never cleanup or admission authority.
    internal static class RegistryLoaderEvidence
    {
        const string Categories = "import-ctypes-(?:native|denied|module|procedure|init|memory|format)";
        static readonly Regex Original = new Regex(@"\AREGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=(import-ctypes:" + Categories + @")\n\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
        static readonly Regex Code = new Regex(@"\Awin32-[0-9A-F]{8}\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
        static readonly Regex Descendant = new Regex(@"\AREGISTRY_AUTHORITY_FAILURE role=primary child_exit=(none|[0-9A-F]{8}) errors=(import-ctypes:" + Categories + @"),(.*),(descendant:(?:transport|timeout))\n\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
        static bool NativeCode(string value)
        { return Code.IsMatch(value) && value != "win32-00000000"; }
        internal static bool Tail(string value)
        {
            if (value == "loader:unqualified" || value == "loader:loaded,loader-release:released") return true;
            if (value.StartsWith("loader:win32-", StringComparison.Ordinal)) return NativeCode(value.Substring(7));
            const string prefix = "loader:loaded,loader-release:";
            return value.StartsWith(prefix, StringComparison.Ordinal) && NativeCode(value.Substring(prefix.Length));
        }
        internal static string Detail(string text)
        {
            if (text == null) return null;
            if (text.Length > 512 || text.Any(c => c > 127)) return FromPrefix(Encoding.UTF8.GetBytes(text.Substring(0, Math.Min(128, text.Length))), true);
            var descendant = Descendant.Match(text);
            if (descendant.Success)
                return "child_exit=" + descendant.Groups[1].Value + " errors=" + descendant.Groups[2].Value + "," +
                    (Tail(descendant.Groups[3].Value) ? descendant.Groups[3].Value : "loader:unqualified") + "," + descendant.Groups[4].Value;
            return FromPrefix(Encoding.ASCII.GetBytes(text), false);
        }
        internal static string FromPrefix(byte[] bytes, bool truncated)
        {
            if (bytes == null || bytes.Length > 512) return null;
            int newline = Array.IndexOf(bytes, (byte)10);
            if (newline < 0 || newline >= 128 || bytes.Take(newline + 1).Any(b => b > 127)) return null;
            string first = Encoding.ASCII.GetString(bytes, 0, newline + 1).Replace("\r\n", "\n");
            var match = Original.Match(first); if (!match.Success) return null;
            string detail = "child_exit=none errors=" + match.Groups[1].Value;
            if (newline + 1 == bytes.Length && !truncated) return detail + " followup=none";
            const string marker = "REGISTRY_LOADER_FOLLOWUP role=primary errors=";
            if (!truncated && bytes.Skip(newline + 1).All(b => b <= 127)) {
                string rest = Encoding.ASCII.GetString(bytes, newline + 1, bytes.Length - newline - 1).Replace("\r\n", "\n");
                if (rest.StartsWith(marker, StringComparison.Ordinal) && rest.EndsWith("\n", StringComparison.Ordinal)) {
                    string tail = rest.Substring(marker.Length, rest.Length - marker.Length - 1);
                    if (Tail(tail)) return detail + " followup=" + tail;
                }
            }
            return detail + " followup=unqualified";
        }
        internal sealed class ReceiptFailure : InvalidOperationException
        {
            internal ReceiptFailure(uint? exit, string detail) : base("fixed registry authority failed primary_exit=" +
                (exit.HasValue ? "0x" + exit.Value.ToString("X8") : "none") + " " + detail + " raw_error_withheld=True") { }
        }
        internal static Exception Preserve(Exception operation, uint? exit, byte[] prefix, bool truncated)
        {
            string detail = FromPrefix(prefix, truncated);
            if (detail == null) return operation;
            var original = new ReceiptFailure(exit, detail);
            return operation == null ? original : new AggregateException("registry bootstrap and subsequent operation failed", original, operation);
        }
        internal sealed class PrivateFailure : Exception
        {
            internal readonly Exception Original;
            internal PrivateFailure(Exception original, string category) : base("fixed registry authority failure category=" + category + " raw_error_withheld=True")
            { Original = original; }
        }
        internal static Exception Sanitize(Exception failure)
        {
            if (failure == null || failure is PrivateFailure || failure is ReceiptFailure || failure is SxsTraceSession.PrivateFailure) return failure;
            var qualified = failure as ExplicitEntryComparison.QualifiedFailure;
            if (qualified != null) return new ExplicitEntryComparison.QualifiedFailure(Sanitize(qualified.Original));
            var group = failure as AggregateException;
            if (group != null) return new AggregateException("fixed registry authority operation/cleanup failed", group.InnerExceptions.Select(Sanitize));
            string category = failure is DecoderFallbackException ? "decode" : failure is EncoderFallbackException ? "encode" :
                failure is TimeoutException ? "timeout" : failure is System.ComponentModel.Win32Exception ? "native" :
                failure is InvalidOperationException ? "control" : "other";
            return new PrivateFailure(failure, category);
        }
        internal static void CheckPrivacyValidation()
        {
            var privateCause = new InvalidOperationException("C:\\private-sxs-sentinel\\capture.etl");
            var trace = new SxsTraceSession.PrivateFailure(privateCause, "start-tool");
            RegistryAuthorityComparison.Need(Object.ReferenceEquals(Sanitize(trace), trace));
            var nested = Sanitize(new AggregateException("private-group-sentinel", trace,
                new ExplicitEntryComparison.QualifiedFailure(trace), privateCause)) as AggregateException;
            var qualified = nested.InnerExceptions[1] as ExplicitEntryComparison.QualifiedFailure;
            RegistryAuthorityComparison.Need(Object.ReferenceEquals(nested.InnerExceptions[0], trace) &&
                qualified != null && Object.ReferenceEquals(qualified.Original, trace) &&
                Object.ReferenceEquals(trace.Original, privateCause) && trace.InnerException == null &&
                trace.Message == "fixed SxS trace failed stage=start-tool raw_error_withheld=True" &&
                nested.InnerExceptions[2] is PrivateFailure && !nested.ToString().Contains("sentinel"));
            const string frame = "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=import-ctypes:import-ctypes-native\n";
            byte[] bytes = Encoding.ASCII.GetBytes(frame + "private-sentinel").Concat(new byte[] { 0xED, 0xA0, 0x80 }).ToArray();
            Exception raw = null;
            try { new UTF8Encoding(false, true).GetString(bytes); }
            catch (DecoderFallbackException failure) { raw = failure; }
            RegistryAuthorityComparison.Need(raw != null);
            Exception cleanup = new InvalidOperationException("private-cleanup-sentinel");
            var operation = Preserve(raw, null, bytes, false) as AggregateException;
            var completed = Sanitize(new AggregateException("private-aggregate-sentinel", operation, cleanup)) as AggregateException;
            var ordered = completed.InnerExceptions[0] as AggregateException;
            var retained = ordered.InnerExceptions[1] as PrivateFailure;
            var last = completed.InnerExceptions[1] as PrivateFailure;
            RegistryAuthorityComparison.Need(retained != null && last != null && Object.ReferenceEquals(retained.Original, raw) &&
                Object.ReferenceEquals(last.Original, cleanup) && retained.InnerException == null && last.InnerException == null && retained.Message.Contains("category=decode"));
            string rendered = completed.ToString() + completed.Message;
            RegistryAuthorityComparison.Need(!rendered.Contains("sentinel") && !rendered.Contains("[ED]") && !rendered.Contains("[A0]") && !rendered.Contains("[80]"));
        }
        internal static void CheckValidation()
        {
            const string original = "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=import-ctypes:import-ctypes-native\n";
            string tail = "REGISTRY_LOADER_FOLLOWUP role=primary errors=loader:win32-00000005\n";
            RegistryAuthorityComparison.Need(Detail(original + tail) == "child_exit=none errors=import-ctypes:import-ctypes-native followup=loader:win32-00000005");
            foreach (string invalid in new [] { "loader:win32-00000000", "loader:win32-100000000", "loader:win32-abcdefab", "loader:loaded", "loader-release:released", "loader:loaded,loader-release:win32-00000000" }) {
                RegistryAuthorityComparison.Need(!Tail(invalid));
                RegistryAuthorityComparison.Need(Detail(original + "REGISTRY_LOADER_FOLLOWUP role=primary errors=" + invalid + "\n").EndsWith("followup=unqualified", StringComparison.Ordinal));
            }
            byte[] bytes = Encoding.ASCII.GetBytes(original + "private-malformed");
            var operation = new TimeoutException("fixed timeout");
            var group = Preserve(operation, null, bytes, false) as AggregateException;
            RegistryAuthorityComparison.Need(group != null && Object.ReferenceEquals(group.InnerExceptions[1], operation) && group.InnerExceptions[0].Message.Contains("primary_exit=none") && !group.ToString().Contains("private"));
            RegistryAuthorityComparison.Need(FromPrefix(Encoding.ASCII.GetBytes(original.TrimEnd('\n')), false) == null);
            RegistryAuthorityComparison.Need(FromPrefix(Encoding.ASCII.GetBytes(original), true).EndsWith("followup=unqualified", StringComparison.Ordinal));
            foreach (string events in new [] { "", ",loader:loaded,loader-release:win32-FFFFFFFF", ",loader:unqualified" }) {
                string child = "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=00000000 errors=import-ctypes:import-ctypes-native" + events + ",descendant:transport\n";
                Exception failure = null;
                try { RegistryAuthorityComparison.ValidateWire(1, "private-stdout", child); } catch (Exception error) { failure = error; }
                RegistryAuthorityComparison.Need(failure != null && failure.Message.Contains("child_exit=00000000 errors=import-ctypes:import-ctypes-native") && !failure.ToString().Contains("private"));
            }
            foreach (uint code in new uint[] { 0, 1, 125, 259, 0xC0000005U, UInt32.MaxValue }) {
                Exception receipt = Preserve(null, code, Encoding.ASCII.GetBytes(original + tail), false);
                RegistryAuthorityComparison.Need(receipt.Message.Contains("primary_exit=0x" + code.ToString("X8")));
                Exception cleanup = new InvalidOperationException("fixed cleanup");
                Exception combined = CsrDispatchComparison.FinishUndebugged(receipt, new System.Collections.Generic.List<Exception> { cleanup }, true, false, true);
                var errors = combined as AggregateException;
                RegistryAuthorityComparison.Need(!(combined is ExplicitEntryComparison.QualifiedFailure) && errors != null &&
                    Object.ReferenceEquals(errors.InnerExceptions[0], receipt) && Object.ReferenceEquals(errors.InnerExceptions[1], cleanup));
                RegistryAuthorityComparison.Need(Object.ReferenceEquals(CsrDispatchComparison.FinishUndebugged(receipt,
                    new System.Collections.Generic.List<Exception>(), true, false, true), receipt));
            }
        }
    }
}
