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
        static Exception retained;
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
            internal byte[] baseline;
            internal bool prepared, attempted, created, recorded, completed;
            internal uint exit;
            bool activationSeen;
            uint activationError;
            internal Observation(Condition value) { Name(value); condition = value; }
            internal void RequireFresh()
            { Need(!prepared && !attempted && !created && !recorded && !activationSeen && baseline == null); }
            internal void Activation(string line)
            {
                Need(prepared && attempted && !activationSeen && line != null && line.Length < 256);
                var match = Regex.Match(line, @"\AWINDOWS_STARTUP_ACTIVATION context=lpac resource_type=24 resource_id=1 created=(True|False) win32_error=([0-9]{1,10}) activated=False child_equivalence_claimed=False cause_claimed=False\z");
                uint error = 0;
                Need(match.Success && UInt32.TryParse(match.Groups[2].Value, System.Globalization.NumberStyles.None,
                    System.Globalization.CultureInfo.InvariantCulture, out error));
                Need((match.Groups[1].Value == "True") == created && (!created || error == 0));
                activationError = error; activationSeen = true;
            }
            internal void Record(uint code, string text, string errors)
            {
                Need(prepared && baseline != null && !recorded && attempted == (condition == Condition.ChildCreate) &&
                    activationSeen == attempted && text != null && errors != null && text.Length == 0 && errors.Length == 0);
                exit = code; completed = code == 0; recorded = true;
            }
            internal string ActivationMetadata()
            {
                Need(recorded && activationSeen);
                return "WINDOWS_PYTHON_ACTIVATION_CALL condition=child-create created=" + created +
                    " win32_error=0x" + activationError.ToString("X8") + " released_if_valid=True activated=False" +
                    " cause_claimed=False target_admitted=False production_grant=False";
            }
            internal string Metadata()
            {
                Need(recorded);
                return "WINDOWS_PYTHON_ACTIVATION_PREPARATION condition=" + Name(condition) +
                    " activation_attempted=" + attempted + " raw_process_exit=0x" + exit.ToString("X8") +
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
            Need(value != null); value.RequireFresh(); byte[] before = null;
            try {
                qualify(); deadline(); before = primary(); EqualAndClear(before, duplicate());
                qualify(); deadline();
                if (value.condition == Condition.ChildCreate) { value.attempted = true; value.created = create(); }
                qualify(); deadline(); EqualAndClear(before, primary()); EqualAndClear(before, duplicate());
                value.baseline = before; before = null; value.prepared = true;
            }
            finally { if (before != null) Array.Clear(before, 0, before.Length); }
        }
        static Exception Combine(Exception first, Exception later)
        { return first == null ? later : later == null ? first : new AggregateException("Python preparation and subsequent operation failed", first, later); }
        static void Emit(string line, Action<string> emit, ref int bytes)
        { Need(line != null); int next = checked(bytes + Encoding.UTF8.GetByteCount(line)); Need(next <= 4096); bytes = next; emit(line); }
        static Exception Execute(Action<Observation> observe, Func<Tuple<Action, Action>> begin, Action<string> emit)
        {
            var values = new List<Observation>(); var lease = begin(); bool clean = true;
            Exception primary = null, diagnostic = null; int bytes = 0;
            try {
                foreach (Condition condition in new [] { Condition.Baseline, Condition.ChildCreate, Condition.BaselineAgain }) {
                    var value = new Observation(condition); values.Add(value); clean = false;
                    observe(value); clean = true; Need(value.recorded && value.baseline != null);
                    if (!value.completed) diagnostic = Combine(diagnostic, new InvalidOperationException(
                        "fixed Python preparation pass failed condition=" + Name(condition) + " raw_process_exit=0x" + value.exit.ToString("X8")));
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
                Emit("WINDOWS_PYTHON_ACTIVATION_PREPARATION_COMPARISON middle_exit_differs=" + (values[0].exit != values[1].exit) +
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
        public static Exception PreserveFailure(Exception later)
        { Exception failure = retained; retained = null; return Combine(failure, later); }
        public static Exception PreserveAllFailures(Exception later)
        { return PreserveFailure(CsrDispatchComparison.PreserveFailure(RegistryCausalComparison.PreserveCallbackFailure(later))); }
        public static void RequireClean() { Exception failure = PreserveAllFailures(null); if (failure != null) throw failure; }
        public static void CheckValidation()
        {
            CheckTransport(); CheckPreparation(); CheckComparison(); Sandbox.CheckActivationPreparationRole();
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
        static Observation Prepared(Condition condition, bool created = true)
        {
            var value = new Observation(condition);
            Prepare(value, () => { }, () => { }, () => (byte[])EmptyPolicy.Clone(), () => (byte[])EmptyPolicy.Clone(), () => created);
            if (condition == Condition.ChildCreate) value.Activation(created ? Created : Denied);
            return value;
        }
        static void CheckTransport()
        {
            foreach (Condition condition in new [] { Condition.Baseline, Condition.ChildCreate, Condition.BaselineAgain }) {
                foreach (uint exit in new uint[] { 0, 1, 121, 0xC0000022, 0xC0150002, UInt32.MaxValue }) {
                    var value = Prepared(condition); value.Record(exit, "", "");
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
        static void CheckComparison()
        {
            for (int mode = 0; mode < 8; mode++) {
                var order = new List<string>(); var values = new List<Observation>(); int visits = 0, reports = 0;
                var operation = new Exception("fixed operation"); var reporting = new Exception("fixed report"); var cleanup = new Exception("fixed restore");
                Exception result = null, caught = null;
                try {
                    result = Execute(value => {
                        visits++; order.Add(Name(value.condition)); values.Add(value);
                        if (mode == 4 && visits == 2) throw operation;
                        Prepare(value, () => { }, () => { }, () => (byte[])EmptyPolicy.Clone(), () => (byte[])EmptyPolicy.Clone(), () => true);
                        if (value.condition == Condition.ChildCreate) value.Activation(Created);
                        uint exit = mode == 0 ? 0U : mode == 2 && visits == 2 || mode == 3 && visits != 1 ? 0U : 0xC0150002U;
                        value.Record(exit, "", "");
                        if (mode == 7 && visits == 2) value.baseline[0] = 4;
                    }, () => { order.Add("begin"); return Tuple.Create<Action, Action>(
                        () => { order.Add("restore"); if (mode == 6) throw cleanup; }, () => order.Add("defer")); },
                    line => { reports++; order.Add("emit"); if (mode == 5) throw reporting; });
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
