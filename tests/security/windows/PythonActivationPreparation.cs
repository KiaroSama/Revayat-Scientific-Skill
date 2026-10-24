using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace ScientificSecurity
{
    // Matched pass-code preparation only; serial carryover is measured, never assumed reversible.
    public static class PythonActivationPreparation
    {
        internal enum Condition { Baseline, ChildCreate, BaselineAgain }
        internal enum Experiment { Token, Host, Image }
        static Exception retained, hostRetained, imageRetained;
        static bool hostStarted, imageStarted;
        const string Created = "WINDOWS_STARTUP_ACTIVATION context=lpac resource_type=24 resource_id=1 created=True win32_error=0 activated=False child_equivalence_claimed=False cause_claimed=False";
        const string Denied = "WINDOWS_STARTUP_ACTIVATION context=lpac resource_type=24 resource_id=1 created=False win32_error=5 activated=False child_equivalence_claimed=False cause_claimed=False";
        static readonly byte[] EmptyPolicy = { 2, 0, 8, 0, 0, 0, 0, 0 };
        internal static void Need(bool value)
        { if (!value) throw new InvalidOperationException("fixed Python activation preparation is inconclusive"); }
        static void Refuse(Action action)
        {
            bool refused = false;
            try { action(); } catch (InvalidOperationException error) { refused = !error.Message.Contains("private-sentinel"); }
            catch (ArgumentException error) { refused = !error.Message.Contains("private-sentinel"); }
            Need(refused);
        }
        internal sealed class Observation
        {
            internal readonly Condition condition;
            internal readonly Experiment experiment;
            internal bool host { get { return experiment == Experiment.Host; } }
            internal bool image { get { return experiment == Experiment.Image; } }
            internal bool CallExpected { get { return condition == Condition.ChildCreate; } }
            internal string Label { get { return CallExpected && image ? "image-bundle" : host && CallExpected ? "host-create" : Name(condition); } }
            internal string Prefix { get { return image ? "WINDOWS_PYTHON_IMAGE_PREPARATION" : host ? "WINDOWS_PYTHON_HOST_PREPARATION" : "WINDOWS_PYTHON_ACTIVATION_PREPARATION"; } }
            internal byte[] baseline;
            internal bool prepared, attempted, created, recorded, completed;
            internal uint exit;
            bool activationSeen, operationCompleted;
            uint activationError;
            internal Observation(Condition value, bool hostPreparation = false)
                : this(value, hostPreparation ? Experiment.Host : Experiment.Token) { }
            internal Observation(Condition value, Experiment kind)
            {
                Name(value); Need(kind == Experiment.Token || kind == Experiment.Host || kind == Experiment.Image);
                condition = value; experiment = kind;
            }
            internal void RequireFresh()
            { Need(!prepared && !attempted && !created && !recorded && !activationSeen && !operationCompleted && baseline == null); }
            internal void Activation(string line)
            {
                Need(!image && prepared && attempted && !activationSeen && line != null && line.Length < 256);
                var match = Regex.Match(line, @"\AWINDOWS_STARTUP_ACTIVATION context=" + (host ? "host" : "lpac") + @" resource_type=24 resource_id=1 created=(True|False) win32_error=([0-9]{1,10}) activated=False child_equivalence_claimed=False cause_claimed=False\z");
                uint error = 0;
                Need(match.Success && UInt32.TryParse(match.Groups[2].Value, System.Globalization.NumberStyles.None,
                    System.Globalization.CultureInfo.InvariantCulture, out error));
                Need((match.Groups[1].Value == "True") == created && (!created || error == 0));
                activationError = error; activationSeen = true;
            }
            internal void Record(uint code, string text, string errors)
            {
                Need(prepared && baseline != null && !recorded && attempted == CallExpected &&
                    (image ? operationCompleted == attempted && !activationSeen && !created : activationSeen == attempted) &&
                    text != null && errors != null && text.Length == 0 && errors.Length == 0);
                exit = code; completed = code == 0; recorded = true;
            }
            internal void CompleteImages()
            { Need(image && attempted && !operationCompleted && !activationSeen && !created); operationCompleted = true; }
            internal string ActivationMetadata()
            {
                if (image) {
                    Need(recorded && attempted && operationCompleted);
                    return "WINDOWS_PYTHON_IMAGE_PREPARATION_CALL condition=image-bundle operation_completed=True" +
                        " all_access_succeeded_claimed=False cause_claimed=False target_admitted=False production_grant=False";
                }
                Need(recorded && activationSeen);
                return (host ? "WINDOWS_PYTHON_HOST_PREPARATION_CALL condition=host-create context=host created=" :
                    "WINDOWS_PYTHON_ACTIVATION_CALL condition=child-create created=") + created +
                    " win32_error=0x" + activationError.ToString("X8") + " released_if_valid=True activated=False" +
                    " cause_claimed=False target_admitted=False production_grant=False";
            }
            internal string Metadata()
            {
                Need(recorded);
                return Prefix + " condition=" + Label +
                    (image ? " image_bundle_attempted=" : " activation_attempted=") + attempted + " raw_process_exit=0x" + exit.ToString("X8") +
                    " pass_code_completed=" + completed + " stdout_empty=True stderr_empty=True default_dacl_unchanged=True" +
                    " process_job_handle_cleanup=True key_readable=True cause_claimed=False target_admitted=False production_grant=False";
            }
            internal void Clear() { if (baseline != null) Array.Clear(baseline, 0, baseline.Length); baseline = null; }
        }
        static string Name(Condition condition)
        {
            switch (condition) {
                case Condition.Baseline: return "baseline";
                case Condition.ChildCreate: return "child-create";
                case Condition.BaselineAgain: return "baseline-again";
                default: throw new ArgumentException("unsupported fixed Python preparation condition");
            }
        }
        static void EqualAndClear(byte[] expected, byte[] actual)
        { try { ChildDefaultDacl.RequireEqual(expected, actual); } finally { if (actual != null) Array.Clear(actual, 0, actual.Length); } }
        internal static void Prepare(Observation value, Action qualify, Action deadline, Func<byte[]> primary, Func<byte[]> duplicate, Func<bool> create)
        {
            Need(value != null && value.experiment == Experiment.Token);
            PrepareCore(value, qualify, deadline, primary, duplicate, create, () => { }, () => { });
        }
        internal static void PrepareHost(Observation value, Action qualify, Action deadline, Func<byte[]> primary, Func<byte[]> duplicate,
            Func<bool> create, Action leave, Action requireHost, Action enter)
        {
            Need(value != null && (value.host || value.image));
            PrepareCore(value, qualify, deadline, primary, duplicate, create,
                () => { leave(); requireHost(); deadline(); }, () => { requireHost(); deadline(); enter(); });
        }
        static void PrepareCore(Observation value, Action qualify, Action deadline, Func<byte[]> primary, Func<byte[]> duplicate,
            Func<bool> create, Action beforeCall, Action afterCall)
        {
            value.RequireFresh(); byte[] before = null;
            try {
                qualify(); deadline(); before = primary(); EqualAndClear(before, duplicate());
                qualify(); deadline(); beforeCall();
                if (value.CallExpected) {
                    value.attempted = true; bool result = create();
                    if (value.image) { Need(result); value.CompleteImages(); } else value.created = result;
                }
                afterCall(); qualify(); deadline(); EqualAndClear(before, primary()); EqualAndClear(before, duplicate());
                value.baseline = before; before = null; value.prepared = true;
            }
            finally { if (before != null) Array.Clear(before, 0, before.Length); }
        }
        static Exception Combine(Exception first, Exception later)
        { return first == null ? later : later == null ? first : new AggregateException("Python preparation and subsequent operation failed", first, later); }
        static void Emit(string line, Action<string> emit, ref int bytes)
        { Need(line != null); int next = checked(bytes + Encoding.UTF8.GetByteCount(line)); Need(next <= 4096); bytes = next; emit(line); }
        static Exception Execute(Action<Observation> observe, Func<Tuple<Action, Action>> begin, Action<string> emit, bool host = false, bool image = false)
        {
            Need(!host || !image);
            var values = new List<Observation>(); var lease = begin(); bool clean = true;
            Exception primary = null, diagnostic = null; int bytes = 0;
            try {
                foreach (Condition condition in new [] { Condition.Baseline, Condition.ChildCreate, Condition.BaselineAgain }) {
                    var value = new Observation(condition, image ? Experiment.Image : host ? Experiment.Host : Experiment.Token);
                    values.Add(value); clean = false;
                    observe(value); clean = true; Need(value.recorded && value.baseline != null && value.host == host && value.image == image);
                    if (host && value.attempted && !value.created) diagnostic = Combine(diagnostic,
                        new InvalidOperationException("fixed host activation preparation positive control failed"));
                    if (!value.completed) diagnostic = Combine(diagnostic, new InvalidOperationException(
                        "fixed Python preparation pass failed condition=" + value.Label + " raw_process_exit=0x" + value.exit.ToString("X8")));
                    if (values.Count > 1) ChildDefaultDacl.RequireEqual(values[0].baseline, value.baseline);
                    if (value.attempted) Emit(value.ActivationMetadata(), emit, ref bytes);
                    Emit(value.Metadata(), emit, ref bytes);
                }
            }
            catch (Exception failure) { primary = Combine(diagnostic, failure); throw primary; }
            finally {
                try { if (clean) lease.Item1(); else lease.Item2(); }
                catch (Exception cleanup) { throw Combine(primary ?? diagnostic, cleanup); }
                finally { foreach (Observation value in values) value.Clear(); }
            }
            try {
                Emit(values[0].Prefix + "_COMPARISON middle_exit_differs=" + (values[0].exit != values[1].exit) +
                    " final_exit_differs=" + (values[0].exit != values[2].exit) +
                    " baseline_policy_equal=True key_restored=True cache_reset_claimed=False" +
                    " cause_claimed=False target_admitted=False production_grant=False", emit, ref bytes);
            }
            catch (Exception failure) { throw Combine(diagnostic, failure); }
            return diagnostic;
        }
        public static void Run(string run, string state, string python, string root, string scratch, string powershell,
            string chromium, string moniker, string profileFolder, int tcpPort, int udpPort)
        {
            Need(retained == null); LoaderSnaps.RequireClean(run, state); PythonCsrDispatch.PreparedImage(python);
            retained = Execute(value => Sandbox.ObserveActivationPreparation(python, root, scratch, powershell, chromium,
                moniker, profileFolder, tcpPort, udpPort, value), () => {
                    var lease = RegistryPolicyLease.Begin(run, state);
                    return Tuple.Create<Action, Action>(lease.Dispose, lease.DeferRecovery);
                }, line => { Console.Out.WriteLine(line); Console.Out.Flush(); });
        }
        public static void RunHost(string run, string state, string python, string root, string scratch, string powershell,
            string chromium, string moniker, string profileFolder, int tcpPort, int udpPort)
        {
            Need(!hostStarted && hostRetained == null); hostStarted = true;
            LoaderSnaps.RequireClean(run, state); PythonCsrDispatch.PreparedImage(python);
            hostRetained = Execute(value => Sandbox.ObserveActivationPreparation(python, root, scratch, powershell, chromium,
                moniker, profileFolder, tcpPort, udpPort, value), () => {
                    var lease = RegistryPolicyLease.Begin(run, state);
                    return Tuple.Create<Action, Action>(lease.Dispose, lease.DeferRecovery);
                }, line => { Console.Out.WriteLine(line); Console.Out.Flush(); }, true);
        }
        public static void RunImages(string run, string state, string python, string root, string scratch, string powershell,
            string chromium, string moniker, string profileFolder, int tcpPort, int udpPort)
        {
            Need(hostStarted && !imageStarted && imageRetained == null); imageStarted = true;
            LoaderSnaps.RequireClean(run, state); PythonCsrDispatch.PreparedImage(python);
            imageRetained = Execute(value => Sandbox.ObserveActivationPreparation(python, root, scratch, powershell, chromium,
                moniker, profileFolder, tcpPort, udpPort, value), () => {
                    var lease = RegistryPolicyLease.Begin(run, state);
                    return Tuple.Create<Action, Action>(lease.Dispose, lease.DeferRecovery);
                }, line => { Console.Out.WriteLine(line); Console.Out.Flush(); }, image: true);
        }
        public static Exception PreserveFailure(Exception later)
        {
            Exception failure = Combine(Combine(retained, hostRetained), imageRetained);
            retained = null; hostRetained = null; imageRetained = null;
            return Combine(failure, later);
        }
        public static Exception PreserveAllFailures(Exception later)
        { return PreserveFailure(CsrDispatchComparison.PreserveFailure(RegistryCausalComparison.PreserveCallbackFailure(later))); }
        public static void RequireClean() { Exception failure = PreserveAllFailures(null); if (failure != null) throw failure; }
        public static void CheckValidation()
        {
            CheckTransport(); CheckPreparation(); CheckComparison(); CheckHostPreparation(); CheckImagePreparation(); Sandbox.CheckActivationPreparationRole();
            Need(retained == null);
            var first = new Exception("fixed preparation"); var later = new Exception("fixed later");
            retained = first;
            var group = PreserveFailure(later) as AggregateException;
            Need(group != null && Object.ReferenceEquals(group.InnerExceptions[0], first) && Object.ReferenceEquals(group.InnerExceptions[1], later));
            Need(PreserveFailure(null) == null);
            foreach (bool admission in new [] { false, true }) {
                Need(PreserveAllFailures(null) == null);
                var preparation = new Exception("fixed preparation"); var csr = new Exception("fixed CSR");
                var callback = new QualifiedModuleCallbackFailure(new Exception("fixed callback"));
                var subsequent = new Exception("fixed subsequent"); Exception caught = null;
                retained = preparation;
                CsrDispatchComparison.RetainValidationFailure(csr);
                RegistryCausalComparison.RetainValidationFailure(callback);
                if (admission) {
                    try { RequireClean(); } catch (Exception failure) { caught = PreserveAllFailures(failure); }
                } else caught = PreserveAllFailures(subsequent);
                var outer = caught as AggregateException;
                var middle = outer == null ? null : outer.InnerExceptions[1] as AggregateException;
                Need(outer != null && Object.ReferenceEquals(outer.InnerExceptions[0], preparation) && middle != null &&
                    Object.ReferenceEquals(middle.InnerExceptions[0], csr));
                if (admission) Need(Object.ReferenceEquals(middle.InnerExceptions[1], callback));
                else {
                    var inner = middle.InnerExceptions[1] as AggregateException;
                    Need(inner != null && Object.ReferenceEquals(inner.InnerExceptions[0], callback) && Object.ReferenceEquals(inner.InnerExceptions[1], subsequent));
                }
                Need(PreserveAllFailures(null) == null && Object.ReferenceEquals(PreserveAllFailures(caught), caught));
            }
        }
        static Observation Prepared(Condition condition, bool created = true, bool host = false)
        {
            var value = new Observation(condition, host);
            if (host) PrepareHost(value, () => { }, () => { }, () => (byte[])EmptyPolicy.Clone(), () => (byte[])EmptyPolicy.Clone(),
                () => created, () => { }, () => { }, () => { });
            else Prepare(value, () => { }, () => { }, () => (byte[])EmptyPolicy.Clone(), () => (byte[])EmptyPolicy.Clone(), () => created);
            if (value.CallExpected) value.Activation(host ? (created ? Created : Denied).Replace("context=lpac", "context=host") : created ? Created : Denied);
            return value;
        }
        static void CheckTransport()
        {
            foreach (bool host in new [] { false, true })
            foreach (Condition condition in new [] { Condition.Baseline, Condition.ChildCreate, Condition.BaselineAgain }) {
                foreach (uint exit in new uint[] { 0, 1, 121, 0xC0000022, 0xC0150002, UInt32.MaxValue }) {
                    var value = Prepared(condition, host: host); value.Record(exit, "", "");
                    string metadata = value.Metadata();
                    Need(value.recorded && value.exit == exit && value.completed == (exit == 0) &&
                        metadata.Contains("raw_process_exit=0x" + exit.ToString("X8")) && metadata.Contains("pass_code_completed=" + (exit == 0)) &&
                        metadata.Contains("activation_attempted=" + (condition == Condition.ChildCreate)) &&
                        metadata.EndsWith("cause_claimed=False target_admitted=False production_grant=False", StringComparison.Ordinal));
                    Need(metadata.Length < 512 && !metadata.Contains("S-1-") && !metadata.Contains("\\") && !metadata.Contains("private-sentinel"));
                    Refuse(() => value.Record(exit, "", "")); value.Clear();
                    Need(value.baseline == null);
                }
            }
            var denied = Prepared(Condition.ChildCreate, false); denied.Record(0xC0150002, "", ""); denied.Clear();
            Refuse(() => new Observation((Condition)3));
            Refuse(() => new Observation(Condition.Baseline).Record(0, "", ""));
            foreach (bool error in new [] { false, true }) {
                var value = Prepared(Condition.Baseline);
                Refuse(() => value.Record(0, error ? "" : "private-sentinel", error ? "private-sentinel" : "")); value.Clear();
            }
            var missing = new Observation(Condition.ChildCreate);
            Prepare(missing, () => { }, () => { }, () => (byte[])EmptyPolicy.Clone(), () => (byte[])EmptyPolicy.Clone(), () => true);
            Refuse(() => missing.Record(0, "", ""));
            foreach (string text in new [] { Denied, Created + "\n", "private-sentinel", Created.Replace("win32_error=0", "win32_error=1") })
                Refuse(() => missing.Activation(text));
            missing.Activation(Created); Refuse(() => missing.Activation(Created)); missing.Record(0, "", ""); missing.Clear();
            var baseline = Prepared(Condition.Baseline); Refuse(() => baseline.Activation(Created)); baseline.Clear();
        }
        static void CheckPreparation()
        {
            foreach (Condition condition in new [] { Condition.Baseline, Condition.ChildCreate, Condition.BaselineAgain }) {
                var order = new List<string>(); var value = new Observation(condition); int calls = 0;
                Prepare(value, () => order.Add("qualify"), () => order.Add("deadline"),
                    () => { order.Add("primary"); return (byte[])EmptyPolicy.Clone(); },
                    () => { order.Add("duplicate"); return (byte[])EmptyPolicy.Clone(); },
                    () => { calls++; order.Add("create-release"); return true; });
                Need(String.Join(",", order) == "qualify,deadline,primary,duplicate,qualify,deadline," +
                    (condition == Condition.ChildCreate ? "create-release," : "") + "qualify,deadline,primary,duplicate");
                Need(calls == (condition == Condition.ChildCreate ? 1 : 0) && value.prepared && value.attempted == (calls == 1));
                Refuse(() => Prepare(value, () => { }, () => { }, () => null, () => null, () => true)); value.Clear();
            }
            for (int failAt = 1; failAt <= 11; failAt++) {
                int step = 0; var allocations = new List<byte[]>(); var value = new Observation(Condition.ChildCreate);
                var failure = new Exception("fixed preparation failure"); Exception caught = null;
                Action visit = () => { if (++step == failAt) throw failure; };
                Func<byte[]> read = () => { visit(); byte[] bytes = (byte[])EmptyPolicy.Clone(); allocations.Add(bytes); return bytes; };
                try { Prepare(value, visit, visit, read, read, () => { visit(); return true; }); }
                catch (Exception error) { caught = error; }
                Need(Object.ReferenceEquals(caught, failure) && !value.prepared && value.baseline == null);
                Need(allocations.All(bytes => bytes.All(item => item == 0)));
            }
            byte[] before = (byte[])EmptyPolicy.Clone(), wrong = { 4, 0, 8, 0, 0, 0, 0, 0 };
            Refuse(() => EqualAndClear(before, wrong)); Need(wrong.All(item => item == 0));
        }
        static void CheckHostPreparation()
        {
            foreach (Condition condition in new [] { Condition.Baseline, Condition.ChildCreate, Condition.BaselineAgain }) {
                var order = new List<string>(); var value = new Observation(condition, true); bool inside = true;
                Action qualify = () => { Need(inside); order.Add("qualify"); };
                Action host = () => { Need(!inside); order.Add("host"); };
                PrepareHost(value, qualify, () => order.Add("deadline"),
                    () => { Need(inside); order.Add("primary"); return (byte[])EmptyPolicy.Clone(); },
                    () => { Need(inside); order.Add("duplicate"); return (byte[])EmptyPolicy.Clone(); },
                    () => { Need(!inside); order.Add("create-release"); return true; },
                    () => { Need(inside); inside = false; order.Add("leave"); }, host,
                    () => { Need(!inside); inside = true; order.Add("enter"); });
                Need(inside && value.prepared && value.attempted == value.CallExpected);
                Need(String.Join(",", order) == "qualify,deadline,primary,duplicate,qualify,deadline,leave,host,deadline," +
                    (value.CallExpected ? "create-release," : "") + "host,deadline,enter,qualify,deadline,primary,duplicate");
                if (value.CallExpected) {
                    Refuse(() => value.Activation(Created));
                    value.Activation(Created.Replace("context=lpac", "context=host"));
                }
                value.Record(0, "", "");
                Need(value.Metadata().StartsWith("WINDOWS_PYTHON_HOST_PREPARATION condition=" + value.Label, StringComparison.Ordinal));
                if (value.CallExpected) Need(value.ActivationMetadata().Contains("condition=host-create context=host created=True"));
                value.Clear();
            }
            for (int failAt = 1; failAt <= 17; failAt++) {
                int step = 0; var allocations = new List<byte[]>(); var value = new Observation(Condition.ChildCreate, true);
                var failure = new Exception("fixed host preparation transition"); Exception caught = null;
                Action visit = () => { if (++step == failAt) throw failure; };
                Func<byte[]> read = () => { visit(); byte[] bytes = (byte[])EmptyPolicy.Clone(); allocations.Add(bytes); return bytes; };
                try { PrepareHost(value, visit, visit, read, read, () => { visit(); return true; }, visit, visit, visit); }
                catch (Exception error) { caught = error; }
                Need(Object.ReferenceEquals(caught, failure) && !value.prepared && value.baseline == null);
                Need(allocations.All(bytes => bytes.All(item => item == 0)));
            }
            foreach (bool hostSuccess in new [] { false, true }) {
                int visits = 0; var lines = new List<string>();
                Exception failure = Execute(value => {
                    Need(value.host); visits++;
                    PrepareHost(value, () => { }, () => { }, () => (byte[])EmptyPolicy.Clone(), () => (byte[])EmptyPolicy.Clone(),
                        () => hostSuccess, () => { }, () => { }, () => { });
                    if (value.CallExpected) value.Activation((hostSuccess ? Created : Denied).Replace("context=lpac", "context=host"));
                    value.Record(0, "", "");
                }, () => Tuple.Create<Action, Action>(() => lines.Add("restore"), () => { throw new Exception("unexpected defer"); }), lines.Add, true);
                Need(visits == 3 && (failure == null) == hostSuccess && lines.Count == 6 && lines[4] == "restore" &&
                    lines[5].StartsWith("WINDOWS_PYTHON_HOST_PREPARATION_COMPARISON", StringComparison.Ordinal));
                Need(hostSuccess || failure.Message == "fixed host activation preparation positive control failed");
            }
            var tokenFailure = new Exception("fixed token preparation"); var hostFailure = new Exception("fixed host preparation");
            var later = new Exception("fixed subsequent"); retained = tokenFailure; hostRetained = hostFailure;
            var combined = PreserveAllFailures(later) as AggregateException;
            var pair = combined == null ? null : combined.InnerExceptions[0] as AggregateException;
            Need(pair != null && Object.ReferenceEquals(pair.InnerExceptions[0], tokenFailure) &&
                Object.ReferenceEquals(pair.InnerExceptions[1], hostFailure) && Object.ReferenceEquals(combined.InnerExceptions[1], later));
            Need(PreserveAllFailures(null) == null && Object.ReferenceEquals(PreserveAllFailures(combined), combined));
            Refuse(() => Prepare(new Observation(Condition.Baseline, true), () => { }, () => { }, () => null, () => null, () => true));
            Refuse(() => PrepareHost(new Observation(Condition.Baseline), () => { }, () => { }, () => null, () => null,
                () => true, () => { }, () => { }, () => { }));
        }
        static void CheckImagePreparation()
        {
            Refuse(() => new Observation(Condition.Baseline, (Experiment)3));
            Refuse(() => Prepare(new Observation(Condition.Baseline, Experiment.Image), () => { }, () => { },
                () => null, () => null, () => true));
            foreach (Condition condition in new [] { Condition.Baseline, Condition.ChildCreate, Condition.BaselineAgain }) {
                var value = new Observation(condition, Experiment.Image); var order = new List<string>(); bool inside = true;
                Action qualify = () => { Need(inside); order.Add("qualify"); };
                Action host = () => { Need(!inside); order.Add("host"); };
                PrepareHost(value, qualify, () => order.Add("deadline"),
                    () => { Need(inside); order.Add("primary"); return (byte[])EmptyPolicy.Clone(); },
                    () => { Need(inside); order.Add("duplicate"); return (byte[])EmptyPolicy.Clone(); },
                    () => { Need(!inside); order.Add("image-bundle"); return true; },
                    () => { inside = false; order.Add("leave"); }, host, () => { inside = true; order.Add("enter"); });
                Need(inside && value.prepared && !value.created && value.attempted == value.CallExpected);
                Need(String.Join(",", order) == "qualify,deadline,primary,duplicate,qualify,deadline,leave,host,deadline," +
                    (value.CallExpected ? "image-bundle," : "") + "host,deadline,enter,qualify,deadline,primary,duplicate");
                Refuse(() => value.Activation(Created)); value.Record(0, "", "");
                Need(value.Metadata().Contains("image_bundle_attempted=" + value.CallExpected) &&
                    !value.Metadata().Contains("activation_attempted"));
                if (value.CallExpected) Need(value.ActivationMetadata().Contains("operation_completed=True") &&
                    value.ActivationMetadata().Contains("all_access_succeeded_claimed=False") && !value.ActivationMetadata().Contains("created="));
                value.Clear();
            }
            foreach (uint code in new uint[] { 0, 1, 121, 0xC0000022, 0xC0150002, UInt32.MaxValue }) {
                var value = new Observation(Condition.ChildCreate, Experiment.Image);
                PrepareHost(value, () => { }, () => { }, () => (byte[])EmptyPolicy.Clone(), () => (byte[])EmptyPolicy.Clone(),
                    () => true, () => { }, () => { }, () => { });
                Refuse(() => value.Record(code, "private-sentinel", ""));
                Refuse(() => value.Record(code, "", "private-sentinel"));
                value.Record(code, "", "");
                Need(value.exit == code && value.completed == (code == 0) &&
                    value.Metadata().Contains("raw_process_exit=0x" + code.ToString("X8")));
                Refuse(() => value.Record(code, "", "")); value.Clear();
            }
            Refuse(() => new Observation(Condition.Baseline, Experiment.Image).CompleteImages());
            for (int failAt = 1; failAt <= 17; failAt++) {
                int step = 0; var allocations = new List<byte[]>(); var value = new Observation(Condition.ChildCreate, Experiment.Image);
                var failure = new Exception("fixed image preparation transition"); Exception caught = null;
                Action visit = () => { if (++step == failAt) throw failure; };
                Func<byte[]> read = () => { visit(); byte[] bytes = (byte[])EmptyPolicy.Clone(); allocations.Add(bytes); return bytes; };
                try { PrepareHost(value, visit, visit, read, read, () => { visit(); return true; }, visit, visit, visit); }
                catch (Exception error) { caught = error; }
                Need(Object.ReferenceEquals(caught, failure) && !value.prepared && value.baseline == null &&
                    allocations.All(bytes => bytes.All(item => item == 0)));
            }
            for (int mode = 0; mode < 8; mode++) {
                int visits = 0; var lines = new List<string>(); var values = new List<Observation>();
                var operation = new Exception("fixed image operation"); var reporting = new Exception("fixed image report");
                var cleanup = new Exception("fixed image restore"); Exception result = null, caught = null;
                try {
                    result = Execute(value => {
                        Need(value.image && !value.host); visits++; values.Add(value);
                        if (mode == 4 && visits == 2) throw operation;
                        PrepareHost(value, () => { }, () => { }, () => (byte[])EmptyPolicy.Clone(), () => (byte[])EmptyPolicy.Clone(),
                            () => true, () => { }, () => { }, () => { });
                        value.Record(mode == 0 || mode == 2 && visits == 2 || mode == 3 && visits != 1 ? 0U : 0xC0150002U, "", "");
                        if (mode == 7 && visits == 2) value.baseline[0] = 4;
                    }, () => Tuple.Create<Action, Action>(() => { lines.Add("restore"); if (mode == 6) throw cleanup; },
                        () => lines.Add("defer")), line => { lines.Add(line); if (mode == 5) throw reporting; }, image: true);
                } catch (Exception failure) { caught = failure; }
                Need(values.All(value => value.baseline == null));
                if (mode <= 3) Need(caught == null && visits == 3 && lines.Count == 6 && lines[4] == "restore" && (result == null) == (mode == 0));
                else Need(caught is AggregateException && lines.Contains(mode == 4 ? "defer" : "restore"));
            }
            var tokenFailure = new Exception("fixed token"); var hostFailure = new Exception("fixed host");
            var imageFailure = new Exception("fixed image"); var later = new Exception("fixed later");
            retained = tokenFailure; hostRetained = hostFailure; imageRetained = imageFailure;
            var combined = PreserveAllFailures(later) as AggregateException;
            var images = combined == null ? null : combined.InnerExceptions[0] as AggregateException;
            var previous = images == null ? null : images.InnerExceptions[0] as AggregateException;
            Need(previous != null && Object.ReferenceEquals(previous.InnerExceptions[0], tokenFailure) &&
                Object.ReferenceEquals(previous.InnerExceptions[1], hostFailure) && Object.ReferenceEquals(images.InnerExceptions[1], imageFailure) &&
                Object.ReferenceEquals(combined.InnerExceptions[1], later) && PreserveAllFailures(null) == null);
        }
        static void CheckComparison()
        {
            foreach (bool host in new [] { false, true })
            for (int mode = 0; mode < 8; mode++) {
                var order = new List<string>(); var values = new List<Observation>(); int visits = 0, reports = 0;
                var operation = new Exception("fixed operation"); var reporting = new Exception("fixed report"); var cleanup = new Exception("fixed restore");
                Exception result = null, caught = null;
                try {
                    result = Execute(value => {
                        visits++; order.Add(Name(value.condition)); values.Add(value);
                        if (mode == 4 && visits == 2) throw operation;
                        if (host) PrepareHost(value, () => { }, () => { }, () => (byte[])EmptyPolicy.Clone(), () => (byte[])EmptyPolicy.Clone(),
                            () => true, () => { }, () => { }, () => { });
                        else Prepare(value, () => { }, () => { }, () => (byte[])EmptyPolicy.Clone(), () => (byte[])EmptyPolicy.Clone(), () => true);
                        if (value.CallExpected) value.Activation(host ? Created.Replace("context=lpac", "context=host") : Created);
                        uint exit = mode == 0 ? 0U : mode == 2 && visits == 2 || mode == 3 && visits != 1 ? 0U : 0xC0150002U;
                        value.Record(exit, "", "");
                        if (mode == 7 && visits == 2) value.baseline[0] = 4;
                    }, () => { order.Add("begin"); return Tuple.Create<Action, Action>(
                        () => { order.Add("restore"); if (mode == 6) throw cleanup; }, () => order.Add("defer")); },
                    line => { reports++; order.Add("emit"); if (mode == 5) throw reporting; }, host);
                } catch (Exception failure) { caught = failure; }
                Need(values.All(value => value.baseline == null));
                if (mode <= 3) Need(caught == null && visits == 3 && order.Contains("restore") && reports == 5 && (result == null) == (mode == 0));
                else if (mode == 4) Need(caught is AggregateException && visits == 2 && order.Last() == "defer" && !order.Contains("restore"));
                else {
                    Need(caught is AggregateException && order.Contains("restore") && !order.Contains("defer"));
                    var group = (AggregateException)caught;
                    Need(group.InnerExceptions[0].Message.Contains("raw_process_exit=0xC0150002") || group.InnerExceptions[0] is AggregateException);
                    if (mode == 5) Need(Object.ReferenceEquals(group.InnerExceptions[1], reporting) && visits == 1);
                    if (mode == 6) Need(Object.ReferenceEquals(group.InnerExceptions[1], cleanup));
                }
            }
            int emitted = 0, bytes = 0; Emit(new string('a', 4096), _ => emitted++, ref bytes);
            Need(bytes == 4096 && emitted == 1); Refuse(() => Emit("x", _ => emitted++, ref bytes)); Need(emitted == 1);
        }
    }
    public static partial class Sandbox
    {
        internal static void ObserveActivationPreparation(string python, string root, string scratch, string powershell,
            string chromium, string moniker, string profileFolder, int tcpPort, int udpPort, PythonActivationPreparation.Observation observation)
        {
            PythonActivationPreparation.Need(observation != null);
            RunFixed(python, root, scratch, powershell, chromium, moniker, profileFolder, true, tcpPort, udpPort,
                false, false, false, false, false, false, false, 0, preparation: observation);
        }
        internal static void CheckActivationPreparationRole()
        {
            Func<PythonActivationPreparation.Observation> fresh = () => new PythonActivationPreparation.Observation(PythonActivationPreparation.Condition.Baseline);
            foreach (Action action in new Action[] {
                () => RunFixed(null, null, null, null, null, null, null, false, 0, 0, false, false, false, false, false, false, false, 0, preparation: fresh()),
                () => RunFixed(null, null, null, null, null, null, null, true, 0, 0, true, false, false, false, false, false, false, 0, preparation: fresh()),
                () => RunFixed(null, null, null, null, null, null, null, true, 0, 0, false, true, false, false, false, false, false, 0, preparation: fresh()),
                () => RunFixed(null, null, null, null, null, null, null, true, 0, 0, false, false, true, false, false, false, false, 0, preparation: fresh()),
                () => RunFixed(null, null, null, null, null, null, null, true, 0, 0, false, false, false, true, false, false, false, 0, preparation: fresh()),
                () => RunFixed(null, null, null, null, null, null, null, true, 0, 0, false, false, false, false, true, false, false, 0, preparation: fresh()),
                () => RunFixed(null, null, null, null, null, null, null, true, 0, 0, false, false, false, false, false, true, false, 0, preparation: fresh()),
                () => RunFixed(null, null, null, null, null, null, null, true, 0, 0, false, false, false, false, false, false, true, 0, preparation: fresh()),
                () => RunFixed(null, null, null, null, null, null, null, true, 0, 0, false, false, false, false, false, false, false, null, preparation: fresh()),
                () => RunFixed(null, null, null, null, null, null, null, true, 0, 0, false, false, false, false, false, false, false, 1, preparation: fresh()),
                () => RunFixed(null, null, null, null, null, null, null, true, 0, 0, false, false, false, false, false, false, false, 0, defaultActivation: true, preparation: fresh()),
                () => RunFixed(null, null, null, null, null, null, null, true, 0, 0, false, false, false, false, false, false, false, 0, moduleRole: 1, preparation: fresh()),
                () => RunFixed(null, null, null, null, null, null, null, true, 0, 0, false, false, false, false, false, false, false, 0, callbackExit: 0, preparation: fresh()),
                () => RunFixed(null, null, null, null, null, null, null, true, 0, 0, false, false, false, false, false, false, false, 0, selfActivation: true, preparation: fresh()),
                () => RunFixed(null, null, null, null, null, null, null, true, 0, 0, false, false, false, false, false, false, false, 0, selfRole: SelfActivationRole.ExplicitId2, preparation: fresh()),
                () => RunFixed(null, null, null, null, null, null, null, true, 0, 0, false, false, false, false, false, false, false, 0, selfEntry: true, preparation: fresh()),
                () => RunFixed(null, null, null, null, null, null, null, true, 0, 0, false, false, false, false, false, false, false, 0, selfResource: true, preparation: fresh()),
                () => RunFixed(null, null, null, null, null, null, null, true, 0, 0, false, false, false, false, false, false, false, 0, dllRequest: true, preparation: fresh()),
                () => RunFixed(null, null, null, null, null, null, null, true, 0, 0, false, false, false, false, false, false, false, 0, pythonCondition: true, preparation: fresh()),
                () => RunFixed(null, null, null, null, null, null, null, true, 0, 0, false, false, false, false, false, false, false, 0,
                    defaultDacl: new DefaultDaclComparison.Observation(DefaultDaclComparison.Condition.Baseline), preparation: fresh()),
                () => RunFixed(null, null, null, null, null, null, null, true, 0, 0, false, false, false, false, false, false, false, 0,
                    dispatch: new CsrDispatchObservation(false, pythonPass: true), preparation: fresh())
            }) {
                bool refused = false; try { action(); } catch (ArgumentException) { refused = true; }
                PythonActivationPreparation.Need(refused);
            }
        }
    }
}
