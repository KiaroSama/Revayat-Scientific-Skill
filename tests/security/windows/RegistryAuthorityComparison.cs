using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace ScientificSecurity
{
    // Trusted authority inventory only; readable content remains unapproved.
    public static class RegistryAuthorityComparison
    {
        const string Pattern = @"\A\{""accessible"":(0|[1-9][0-9]{0,2}),""capabilities"":0,""granted_access"":131097,""lpac"":true,""mutation_denied"":true,""no_reparse"":true,""read"":true,""read_surface_approved"":false,""restricted"":true,""role"":""(primary|descendant)"",""subkeys"":(0|[1-9][0-9]{0,2}),""version"":1,""x64"":true\}\n\z";
        static readonly Regex Wire = new Regex(Pattern, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
        static bool started;
        internal static void Need(bool value)
        { if (!value) throw new InvalidOperationException("fixed registry authority prerequisite is inconclusive"); }
        static Exception Combine(Exception first, Exception later)
        { return first == null ? later : later == null ? first : new AggregateException("registry authority operation/recovery failed", first, later); }
        internal sealed class Observation : RegistryDiagnostic
        {
            readonly RegistryStartupComparison.Observation preparation = new RegistryStartupComparison.Observation(1);
            internal bool recorded;
            internal string wire;
            internal override int Expected { get { return 0; } }
            internal override void RequireFresh() { preparation.RequireFresh(); Need(!recorded && wire == null); }
            internal override void Prepare(byte[] primary, byte[] duplicate) { preparation.Prepare(primary, duplicate); }
            internal override void RequirePolicy(byte[] primary, byte[] duplicate) { preparation.RequirePolicy(primary, duplicate); }
            internal override void ReadControl(int status) { preparation.ReadControl(status); }
            internal override void Stage(uint code, string text, string errors)
            { ValidateWire(code, text, errors); preparation.Stage(code, "", ""); wire = text; }
            internal void Complete() { preparation.Complete(); Need(wire != null && !recorded); recorded = true; }
            internal void Clear() { preparation.Clear(); wire = null; }
        }
        static readonly Regex FailureWire = new Regex(@"\AREGISTRY_AUTHORITY_FAILURE role=primary child_exit=(none|[0-9A-F]{8}) errors=((?:start|token|root|mutation|inventory|identity|close|descendant|report):(?:control|timeout|decode|encode|native|transport|other|cleanup)(?:,(?:start|token|root|mutation|inventory|identity|close|descendant|report):(?:control|timeout|decode|encode|native|transport|other|cleanup)){0,7})\n\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
        static Exception TransportFailure(uint code, string errors)
        {
            string detail = "unqualified";
            if (errors != null && errors.Length <= 512 && errors.All(c => c <= 127)) {
                var match = FailureWire.Match(errors.Replace("\r\n", "\n"));
                if (match.Success) detail = "child_exit=" + match.Groups[1].Value + " errors=" + match.Groups[2].Value;
            }
            return new InvalidOperationException("fixed registry authority failed primary_exit=0x" + code.ToString("X8") + " " + detail + " raw_error_withheld=True");
        }
        internal static void ValidateWire(uint code, string text, string errors)
        {
            try { ValidateSuccess(code, text, errors); }
            catch (Exception) { throw TransportFailure(code, errors); }
        }
        static void ValidateSuccess(uint code, string text, string errors)
        {
            Need(code == 0 && text != null && errors != null && errors.Length == 0 && text.Length <= 2048 && text.All(c => c <= 127));
            string[] lines = text.Replace("\r\n", "\n").Split('\n');
            Need(lines.Length == 3 && lines[2] == "");
            for (int index = 0; index < 2; index++) {
                var match = Wire.Match(lines[index] + "\n"); Need(match.Success);
                Need(match.Groups[2].Value == (index == 0 ? "primary" : "descendant"));
                int count = Int32.Parse(match.Groups[3].Value), accessible = Int32.Parse(match.Groups[1].Value);
                Need(count <= 256 && accessible <= count);
            }
        }
        internal static void Execute(Action observe, Func<Tuple<Action, Action>> begin, Action before, Action after, Action emit)
        {
            before(); var lease = begin(); bool clean = false; Exception primary = null;
            try { observe(); clean = true; }
            catch (ExplicitEntryComparison.QualifiedFailure failure) {
                clean = true; primary = failure.Original;
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw(); throw;
            }
            catch (Exception failure) { primary = failure; throw; }
            finally { try { if (clean) lease.Item1(); else lease.Item2(); } catch (Exception cleanup) { throw Combine(primary, cleanup); } }
            after(); emit();
        }
        public static void Run(string run, string state, string python, string root, string scratch, string powershell,
            string chromium, string moniker, string profileFolder, int tcpPort, int udpPort)
        {
            Need(!started); started = true; PythonCsrDispatch.RequireHostPositive(python); LoaderSnaps.RequireClean(run, state);
            RegistryAuthoritySurface.Snapshot before = null; var observation = new Observation();
            try {
                Execute(() => Sandbox.ObserveRegistryAuthority(python, root, scratch, powershell, chromium, moniker, profileFolder, tcpPort, udpPort, observation),
                    () => { var lease = RegistryPolicyLease.Begin(run, state); return Tuple.Create<Action, Action>(lease.Dispose, lease.DeferRecovery); },
                    () => { before = RegistryAuthoritySurface.Read(); before.RequireEqual(RegistryAuthoritySurface.Read()); },
                    () => { before.RequireEqual(RegistryAuthoritySurface.Read()); Need(observation.recorded); },
                    () => {
                        Console.Out.Write(observation.wire);
                        Console.Out.WriteLine("WINDOWS_REGISTRY_AUTHORITY authority_qualified=True root_values=" + before.values + " root_subkeys=" + before.subkeys +
                            " value_type_mask=" + before.types + " host_surface_restored=True read_surface_approved=False production_grant=False target_admitted=False");
                        Console.Out.Flush();
                    });
            }
            finally { observation.Clear(); }
        }
        internal static void CheckFailureProjection()
        {
            const string wire = "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=00000007 errors=descendant:transport,root:control,close:cleanup\n";
            Exception actual = null;
            try { ValidateWire(1, "private-stdout-sentinel", wire); } catch (Exception failure) { actual = failure; }
            Need(actual != null && actual.Message == "fixed registry authority failed primary_exit=0x00000001 child_exit=00000007 errors=descendant:transport,root:control,close:cleanup raw_error_withheld=True");
            Need(actual.InnerException == null && !actual.ToString().Contains("private"));
            foreach (uint code in new uint[] { 7, 259, 0xC0000022U, UInt32.MaxValue }) {
                actual = null; try { ValidateWire(code, "private-stdout-sentinel", "private-error-sentinel"); } catch (Exception failure) { actual = failure; }
                Need(actual != null && actual.Message.Contains("primary_exit=0x" + code.ToString("X8")) && actual.Message.Contains("unqualified") && !actual.ToString().Contains("sentinel"));
            }
            string timeout = "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=descendant:timeout\n";
            Need(TransportFailure(1, timeout).Message.Contains("child_exit=none errors=descendant:timeout"));
            Need(TransportFailure(1, wire.Replace("root:control", "root:private")).Message.Contains("unqualified"));
            var observation = new Observation(); Exception operation = null;
            try { observation.Stage(1, "", wire); } catch (Exception failure) { operation = failure; }
            Need(operation != null && !observation.recorded && observation.wire == null);
            var cleanup = new InvalidOperationException("fixed restoration failed"); Exception combined = null;
            try { Execute(() => { throw new ExplicitEntryComparison.QualifiedFailure(operation); },
                () => Tuple.Create<Action, Action>(() => { throw cleanup; }, () => { throw new InvalidOperationException("unexpected defer"); }),
                () => { }, () => { throw new InvalidOperationException("unexpected completion"); }, () => { }); }
            catch (Exception failure) { combined = failure; }
            var group = combined as AggregateException;
            Need(group != null && group.InnerExceptions.Count == 2 && Object.ReferenceEquals(group.InnerExceptions[0], operation) && Object.ReferenceEquals(group.InnerExceptions[1], cleanup));
        }
        public static void CheckValidation()
        {
            RegistryAuthoritySurface.CheckValidation();
            CheckFailureProjection();
            const string primary = "{\"accessible\":1,\"capabilities\":0,\"granted_access\":131097,\"lpac\":true,\"mutation_denied\":true,\"no_reparse\":true,\"read\":true,\"read_surface_approved\":false,\"restricted\":true,\"role\":\"primary\",\"subkeys\":2,\"version\":1,\"x64\":true}\n";
            string child = primary.Replace("\"primary\"", "\"descendant\"").Replace("\"accessible\":1", "\"accessible\":0").Replace("\"subkeys\":2", "\"subkeys\":0");
            ValidateWire(0, primary + child, "");
            ValidateWire(0, (primary + child).Replace("\n", "\r\n"), "");
            ValidateWire(0, (primary + child).Replace("\"accessible\":1", "\"accessible\":256").Replace("\"subkeys\":2", "\"subkeys\":256"), "");
            foreach (string invalid in new [] { primary, child + primary, primary + primary, primary + child + "\n", (primary + child).Replace("\"mutation_denied\":true", "\"mutation_denied\":false"), (primary + child).Replace("\"accessible\":1", "\"accessible\":3"), (primary + child).Replace("\"subkeys\":2", "\"subkeys\":257"), (primary + child).Replace("\"read_surface_approved\":false", "\"read_surface_approved\":true"), (primary + child).Replace("\"read\":true", "\"read\":true,\"unknown\":0"), null, new string('x', 2049), (primary + child).Replace("\"accessible\":1", "\"accessible\":-1"), (primary + child).Replace("\"accessible\":1", "\"accessible\":01"), (primary + child).Replace("\"version\":1", "\"version\":2"), (primary + child).Replace("\"role\":\"descendant\"", "\"role\":\"descendánt\"") }) {
                bool refused = false; try { ValidateWire(0, invalid, ""); } catch (InvalidOperationException) { refused = true; } Need(refused);
            }
            foreach (string field in new [] { "lpac", "mutation_denied", "no_reparse", "read", "restricted", "x64" }) {
                bool refused = false;
                try { ValidateWire(0, primary + child.Replace("\"" + field + "\":true", "\"" + field + "\":false"), ""); }
                catch (InvalidOperationException) { refused = true; } Need(refused);
            }
            foreach (string errors in new [] { "x", null }) {
                bool refused = false; try { ValidateWire(0, primary + child, errors); } catch (InvalidOperationException) { refused = true; } Need(refused);
            }
            foreach (uint code in new uint[] { 1, 259, 0xC0000022U, UInt32.MaxValue }) {
                bool refused = false; try { ValidateWire(code, primary + child, ""); } catch (InvalidOperationException) { refused = true; } Need(refused);
            }
            for (int mode = 0; mode < 9; mode++) {
                var order = new List<string>(); var failure = new InvalidOperationException("fixed authority operation");
                var cleanup = new InvalidOperationException("fixed authority restore"); Exception caught = null;
                try { Execute(() => { order.Add("observe"); if (mode == 1 || mode == 2) throw new ExplicitEntryComparison.QualifiedFailure(failure); if (mode == 3) throw failure; },
                    () => { order.Add("begin"); if (mode == 7) throw failure; return Tuple.Create<Action, Action>(() => { order.Add("restore"); if (mode == 2 || mode == 8) throw cleanup; }, () => order.Add("defer")); },
                    () => { order.Add("before"); if (mode == 6) throw failure; }, () => { order.Add("after"); if (mode == 4) throw failure; }, () => { order.Add("emit"); if (mode == 5) throw failure; }); }
                catch (Exception error) { caught = error; }
                Need((caught == null) == (mode == 0) && order.Contains("defer") == (mode == 3));
                Need(order.Contains("after") == (mode == 0 || mode == 4 || mode == 5));
                if (mode == 1 || mode >= 3 && mode < 8) Need(Object.ReferenceEquals(caught, failure));
                if (mode == 8) Need(Object.ReferenceEquals(caught, cleanup));
                if (mode == 2) { var group = caught as AggregateException; Need(group != null && Object.ReferenceEquals(group.InnerExceptions[0], failure) && Object.ReferenceEquals(group.InnerExceptions[1], cleanup)); }
            }
        }
    }
}
