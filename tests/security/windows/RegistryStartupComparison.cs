using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace ScientificSecurity
{
    // Pass-code sufficiency only; no target runs under this diagnostic policy.
    public static class RegistryStartupComparison
    {
        static Exception retained;
        static bool started;
        internal sealed class Observation
        {
            internal readonly int condition;
            byte[] policy;
            bool prepared, readQualified, staged;
            internal bool recorded { get; private set; }
            internal uint exit { get; private set; }
            internal int Expected { get { return condition == 1 ? 0 : unchecked((int)0xC0000022); } }
            internal string Label { get { return condition == 0 ? "original" : condition == 1 ? "readable" : "restored"; } }
            internal Observation(int value)
            {
                if (value < 0 || value > 2) throw new ArgumentException("unsupported registry startup condition");
                condition = value;
            }
            internal void RequireFresh() { Need(!prepared && !readQualified && !staged && !recorded && policy == null); }
            internal void Prepare(byte[] primary, byte[] duplicate)
            {
                RequireFresh(); ChildDefaultDacl.RequireEqual(primary, duplicate);
                policy = (byte[])primary.Clone(); prepared = true;
            }
            internal void RequirePolicy(byte[] primary, byte[] duplicate)
            {
                Need(prepared && !staged && !recorded);
                ChildDefaultDacl.RequireEqual(policy, primary); ChildDefaultDacl.RequireEqual(policy, duplicate);
            }
            internal void ReadControl(int status)
            {
                Need(prepared && !readQualified && !staged && !recorded);
                Need(Expected == 0 ? status >= 0 : status == Expected); readQualified = true;
            }
            internal void Stage(uint code, string text, string errors)
            {
                Need(prepared && readQualified && !staged && !recorded && text != null && errors != null && text.Length == 0 && errors.Length == 0);
                exit = code; staged = true;
            }
            internal void Complete() { Need(prepared && readQualified && staged && !recorded); recorded = true; }
            internal void EqualPolicy(Observation other)
            { Need(recorded && other.recorded); ChildDefaultDacl.RequireEqual(policy, other.policy); }
            internal string Metadata()
            {
                Need(recorded);
                return "WINDOWS_REGISTRY_STARTUP condition=" + Label + " key_readable=" + (condition == 1) +
                    " raw_process_exit=0x" + exit.ToString("X8") + " pass_code_completed=" + (exit == 0) +
                    " stdout_empty=True stderr_empty=True default_dacl_unchanged=True process_job_handle_cleanup=True" +
                    " cause_claimed=False target_admitted=False production_grant=False";
            }
            internal void Clear() { if (policy != null) Array.Clear(policy, 0, policy.Length); policy = null; }
        }
        internal static void Need(bool value)
        { if (!value) throw new InvalidOperationException("fixed registry startup comparison is inconclusive"); }
        static Exception Combine(Exception first, Exception later)
        { return first == null ? later : later == null ? first : new AggregateException("registry startup and subsequent operation failed", first, later); }
        static void Emit(string line, Action<string> emit, ref int bytes)
        { Need(line != null); int next = checked(bytes + System.Text.Encoding.UTF8.GetByteCount(line)); Need(next <= 4096); bytes = next; emit(line); }
        internal static Exception Execute(Action<Observation> observe, Func<Tuple<Action, Action>> begin, Action<string> emit)
        {
            var values = new List<Observation>(); int bytes = 0; Exception diagnostic = null;
            Action<Observation> report = value => {
                Need(value.recorded);
                bool mismatch = value.condition == 0 ? value.exit == 0 : value.condition == 1 ? value.exit != 0 :
                    value.exit == 0 || value.exit != values[0].exit;
                if (mismatch) diagnostic = Combine(diagnostic, new InvalidOperationException(
                    "fixed registry startup exit mismatch condition=" + value.Label + " raw_process_exit=0x" + value.exit.ToString("X8")));
                if (value.condition != 0) values[0].EqualPolicy(value);
                Emit(value.Metadata(), emit, ref bytes);
            };
            try {
                var original = new Observation(0); values.Add(original); observe(original); report(original);
                var lease = begin(); bool clean = false; Exception primary = null;
                try {
                    var middle = new Observation(1); values.Add(middle);
                    observe(middle); clean = true; report(middle);
                }
                catch (ExplicitEntryComparison.QualifiedFailure failure) {
                    clean = true; primary = failure.Original;
                    System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw(); throw;
                }
                catch (Exception failure) { primary = failure; throw; }
                finally {
                    try { if (clean) lease.Item1(); else lease.Item2(); }
                    catch (Exception cleanup) { throw Combine(primary, cleanup); }
                }
                var restored = new Observation(2); values.Add(restored); observe(restored); report(restored);
                bool sufficient = original.exit != 0 && values[1].exit == 0 && restored.exit == original.exit;
                Emit("WINDOWS_REGISTRY_STARTUP_COMPARISON baseline_failed=" + (original.exit != 0) +
                    " readable_passed=" + (values[1].exit == 0) + " restored_exit_equal=" + (restored.exit == original.exit) +
                    " baseline_policy_equal=True key_restored=True conditional_sufficiency=" + sufficient +
                    " cache_reset_claimed=False cause_claimed=False target_admitted=False production_grant=False", emit, ref bytes);
                return diagnostic;
            }
            catch (Exception failure) {
                var qualified = failure as ExplicitEntryComparison.QualifiedFailure;
                var original = qualified == null ? failure : qualified.Original;
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(Combine(diagnostic, original)).Throw(); throw;
            }
            finally { foreach (var value in values) value.Clear(); }
        }
        public static void Run(string run, string state, string python, string root, string scratch, string powershell,
            string chromium, string moniker, string profileFolder, int tcpPort, int udpPort)
        {
            Need(!started && retained == null); started = true;
            PythonCsrDispatch.RequireHostPositive(python); LoaderSnaps.RequireClean(run, state);
            retained = Execute(value => Sandbox.ObserveRegistryStartup(python, root, scratch, powershell, chromium,
                moniker, profileFolder, tcpPort, udpPort, value), () => {
                    var lease = RegistryPolicyLease.Begin(run, state);
                    return Tuple.Create<Action, Action>(lease.Dispose, lease.DeferRecovery);
                }, line => { Console.Out.WriteLine(line); Console.Out.Flush(); });
        }
        internal static Exception PreserveFailure(Exception later)
        { var failure = retained; retained = null; return Combine(failure, later); }
        public static void CheckValidation()
        {
            byte[] policy = { 2, 0, 8, 0, 0, 0, 0, 0 };
            for (int mode = 0; mode < 4; mode++) {
                var order = new List<string>(); int reports = 0;
                Exception result = Execute(value => {
                    order.Add(value.Label); value.Prepare(policy, policy); value.RequirePolicy(policy, policy);
                    value.ReadControl(value.Expected);
                    uint code = value.condition == 1 ? (mode == 2 ? 0xC0000022U : 0U) : mode == 1 ? 0U : value.condition == 2 && mode == 3 ? 0xC0150002U : 0xC0000022U;
                    value.Stage(code, "", ""); value.Complete();
                }, () => { order.Add("begin"); return Tuple.Create<Action, Action>(() => order.Add("restore"), () => order.Add("defer")); }, line => {
                    reports++; Need(line.Length <= 4096 && !line.Contains("private-") && !line.Contains("S-1-"));
                });
                Need((result == null) == (mode == 0) && reports == 4 && String.Join(",", order) == "original,begin,readable,restore,restored");
            }
            foreach (int mode in new [] { 0, 1, 2, 3, 4, 5 }) {
                var value = new Observation(0); bool refused = false;
                try {
                    if (mode == 0) value.Stage(0, "", "");
                    value.Prepare(policy, policy);
                    if (mode == 1) value.Prepare(policy, policy);
                    if (mode == 2) value.ReadControl(0);
                    value.ReadControl(value.Expected);
                    if (mode == 3) value.Stage(0, "unexpected", "");
                    if (mode == 4) value.Complete();
                    value.Stage(0xC0000022, "", ""); value.Complete();
                    if (mode == 5) value.Complete();
                } catch (InvalidOperationException) { refused = true; }
                finally { value.Clear(); }
                Need(refused);
            }
            Need(retained == null); var first = new InvalidOperationException("fixed startup diagnostic"); retained = first;
            var later = new InvalidOperationException("fixed later"); var combined = PreserveFailure(later) as AggregateException;
            Need(combined != null && Object.ReferenceEquals(combined.InnerExceptions[0], first) && Object.ReferenceEquals(combined.InnerExceptions[1], later));
            Need(PreserveFailure(null) == null);
            CheckFailures(policy); CheckFailureOrdering(); CheckPolicies(policy); Sandbox.CheckRegistryStartupRole();
        }
        internal static void CheckFailureOrdering()
        {
            byte[] policy = { 2, 0, 8, 0, 0, 0, 0, 0 };
            for (int mode = 0; mode < 8; mode++) {
                var order = new List<string>();
                var operation = new InvalidOperationException("fixed qualified operation");
                var restoration = new InvalidOperationException("fixed restoration");
                var reporting = new InvalidOperationException("fixed reporting");
                Exception caught = null;
                try {
                    Execute(value => {
                        order.Add(value.Label);
                        if (value.condition == 1 && (mode == 3 || mode == 4 || mode == 7))
                            throw new ExplicitEntryComparison.QualifiedFailure(operation);
                        value.Prepare(policy, policy); value.ReadControl(value.Expected);
                        uint code = value.condition == 1 ? (mode < 2 ? 0xC0000022U : 0U) :
                            value.condition == 0 && (mode == 2 || mode == 5 || mode == 7) ? 0U :
                            value.condition == 2 && mode == 6 ? 0xC0150002U : 0xC0000022U;
                        value.Stage(code, "", ""); value.Complete();
                    }, () => {
                        order.Add("begin"); if (mode == 2) throw operation;
                        return Tuple.Create<Action, Action>(() => {
                            order.Add("restore"); if (mode == 0 || mode == 4) throw restoration;
                        }, () => order.Add("defer"));
                    }, line => {
                        if (mode == 1 && line.Contains("condition=readable") ||
                            mode == 5 && line.Contains("condition=original") ||
                            mode == 6 && line.Contains("condition=restored")) throw reporting;
                    });
                } catch (Exception failure) { caught = failure; }
                Need(caught != null && !order.Contains("defer"));
                Need(order.Contains("restored") == (mode == 6));
                if (mode == 3) { Need(Object.ReferenceEquals(caught, operation)); continue; }
                var group = caught as AggregateException;
                Need(group != null); var failures = group.Flatten().InnerExceptions;
                Need(failures.Count == 2);
                if (mode == 4) {
                    Need(Object.ReferenceEquals(failures[0], operation) && Object.ReferenceEquals(failures[1], restoration));
                } else {
                    string label = mode == 2 || mode == 5 || mode == 7 ? "original" : mode == 6 ? "restored" : "readable";
                    Need(failures[0] is InvalidOperationException && failures[0].Message.Contains("condition=" + label) &&
                        !(failures[0] is ExplicitEntryComparison.QualifiedFailure));
                    Need(Object.ReferenceEquals(failures[1], mode == 0 ? restoration : mode == 2 || mode == 7 ? operation : reporting));
                }
            }
        }
        static void CheckPolicies(byte[] policy)
        {
            byte[] different = { 4, 0, 8, 0, 0, 0, 0, 0 };
            for (int mode = 0; mode < 4; mode++) {
                var value = new Observation(0); bool refused = false;
                try {
                    value.Prepare(policy, mode == 0 ? different : policy);
                    if (mode == 1) value.RequirePolicy(different, policy);
                    if (mode == 2) value.RequirePolicy(policy, different);
                    value.ReadControl(value.Expected); value.Stage(1, "", ""); value.Complete();
                    var other = new Observation(2);
                    try { other.Prepare(different, different); other.ReadControl(other.Expected); other.Stage(1, "", ""); other.Complete(); value.EqualPolicy(other); }
                    finally { other.Clear(); }
                } catch (InvalidOperationException) { refused = true; }
                finally { value.Clear(); }
                Need(refused);
            }
            int emitted = 0, bytes = 0; Emit(new string('a', 4096), _ => emitted++, ref bytes);
            bool overflow = false;
            try { Emit("x", _ => emitted++, ref bytes); } catch (InvalidOperationException) { overflow = true; }
            Need(overflow && emitted == 1 && bytes == 4096);
        }
        static void CheckFailures(byte[] policy)
        {
            for (int mode = 0; mode < 6; mode++) {
                var order = new List<string>(); var failure = new InvalidOperationException("fixed operation");
                var cleanup = new InvalidOperationException("fixed restoration"); Exception caught = null;
                try {
                    Execute(value => {
                        order.Add(value.Label);
                        if (value.condition == 1 && mode < 2) {
                            if (mode == 1) throw ExplicitEntryComparison.FinishTrace(failure, new List<Exception>(), true, true, () => "fixed", _ => { });
                            throw failure;
                        }
                        value.Prepare(policy, policy); value.ReadControl(value.Expected);
                        value.Stage(value.condition == 1 ? 0U : 0xC0000022U, "", ""); value.Complete();
                        if (value.condition == 2 && mode == 4) throw failure;
                    }, () => { order.Add("begin"); return Tuple.Create<Action, Action>(
                        () => { order.Add("restore"); if (mode == 2) throw cleanup; }, () => order.Add("defer")); }, line => {
                        if (mode == 3 && line.Contains("condition=readable") || mode == 5 && line.Contains("_COMPARISON")) throw failure;
                    });
                } catch (Exception error) { caught = error; }
                Need(caught != null && !order.Contains("restored") == (mode < 4));
                Need(order.Contains("defer") == (mode == 0) && order.Contains("restore") == (mode != 0));
            }
        }
    }
    public static partial class StartupActivationAccess
    {
        internal static void PrepareRegistryStartup(Native.ProcessInfo child, string package, RegistryStartupComparison.Observation observation)
        {
            RequirePreparationHost(); observation.RequireFresh();
            IntPtr token = IntPtr.Zero, duplicate = IntPtr.Zero; Exception primary = null;
            byte[] first = null, second = null;
            var clock = Stopwatch.StartNew();
            try {
                Native.Check(Native.OpenProcessToken(child.process, 0xA, out token), "open exact registry startup primary token");
                Native.Check(DuplicateTokenEx(token, 0xC, IntPtr.Zero, 2, 2, out duplicate), "duplicate exact registry startup token");
                new RegistryContext(token, duplicate, package);
                first = ChildDefaultDacl.Read(token); second = ChildDefaultDacl.Read(duplicate);
                observation.Prepare(first, second); Array.Clear(first, 0, first.Length); Array.Clear(second, 0, second.Length);
                observation.ReadControl(StartupRegistryAccess.ObserveChild(child, package));
                RequirePreparationHost(); new RegistryContext(token, duplicate, package); Deadline(clock);
                first = ChildDefaultDacl.Read(token); second = ChildDefaultDacl.Read(duplicate);
                observation.RequirePolicy(first, second); Deadline(clock);
            }
            catch (Exception failure) { primary = failure; throw; }
            finally {
                var failures = new List<Exception>();
                if (first != null) Array.Clear(first, 0, first.Length);
                if (second != null) Array.Clear(second, 0, second.Length);
                Attempt(failures, () => { if (duplicate != IntPtr.Zero) Native.Check(Native.CloseHandle(duplicate), "close registry startup duplicate token"); });
                Attempt(failures, () => { if (token != IntPtr.Zero) Native.Check(Native.CloseHandle(token), "close registry startup primary token"); });
                Finish(primary, failures);
            }
        }
    }
    public static partial class Sandbox
    {
        static void PrepareOwnProcessAccess(Native.ProcessInfo child, bool registryStartup)
        {
            if (registryStartup) StartupAccess.RequireOwnQueries(child, false);
            OwnProcessAccess.Repair(child);
        }
        static void RequireRegistryStartupRole(RegistryStartupComparison.Observation observation, int? expected, bool conflict)
        {
            if (observation == null || conflict || expected != observation.Expected)
                throw new ArgumentException("registry startup comparison requires its fixed undebugged pass-code role");
            observation.RequireFresh();
        }
        internal static void CheckRegistryStartupRole()
        {
            foreach (int condition in new [] { 0, 1, 2 }) {
                var observation = new RegistryStartupComparison.Observation(condition);
                RequireRegistryStartupRole(observation, observation.Expected, false);
                foreach (int? expected in new int?[] { null, 1, condition == 1 ? unchecked((int)0xC0000022) : 0 }) {
                    bool refused = false;
                    try { RequireRegistryStartupRole(observation, expected, false); } catch (ArgumentException) { refused = true; }
                    RegistryStartupComparison.Need(refused);
                }
                bool conflict = false;
                try { RequireRegistryStartupRole(observation, observation.Expected, true); } catch (ArgumentException) { conflict = true; }
                RegistryStartupComparison.Need(conflict);
            }
            for (int mode = 0; mode < 21; mode++) {
                bool refused = false;
                var observation = new RegistryStartupComparison.Observation(0);
                try {
                    RunFixed(null, null, null, null, null, null, null, mode != 0, 0, 0,
                        mode == 1, mode == 2, mode == 3, mode == 4, mode == 5, mode == 6, mode == 7,
                        mode == 19 ? (int?)null : observation.Expected, defaultActivation: mode == 8, moduleRole: mode == 9 ? 1 : 0,
                        callbackExit: mode == 10 ? (uint?)1 : null, selfActivation: mode == 11,
                        selfRole: mode == 12 ? SelfActivationRole.Manual : SelfActivationRole.Original,
                        selfEntry: mode == 13, selfResource: mode == 14, dllRequest: mode == 15, pythonCondition: mode == 16,
                        defaultDacl: mode == 17 ? new DefaultDaclComparison.Observation(DefaultDaclComparison.Condition.Baseline) : null,
                        dispatch: mode == 18 ? new CsrDispatchObservation(false, pythonPass: true) : null,
                        preparation: mode == 20 ? new PythonActivationPreparation.Observation(PythonActivationPreparation.Condition.Baseline) : null, registryStartup: observation);
                } catch (ArgumentException) { refused = true; }
                RegistryStartupComparison.Need(refused);
            }
        }
        internal static void ObserveRegistryStartup(string python, string root, string scratch, string powershell,
            string chromium, string moniker, string profileFolder, int tcpPort, int udpPort, RegistryStartupComparison.Observation observation)
        {
            if (observation == null) throw new ArgumentNullException("observation");
            observation.RequireFresh();
            RunFixed(python, root, scratch, powershell, chromium, moniker, profileFolder, true, tcpPort, udpPort,
                false, false, false, false, false, false, false, observation.Expected, registryStartup: observation);
            observation.Complete();
        }
    }
}
