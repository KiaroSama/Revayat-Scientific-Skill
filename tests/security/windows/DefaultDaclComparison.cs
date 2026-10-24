using System;
using System.Collections.Generic;

namespace ScientificSecurity
{
    // Constant readable-key intervention; this comparison can never admit reviewed code.
    public static class DefaultDaclComparison
    {
        internal enum Condition { Baseline, UserAllow, BaselineAgain }
        internal sealed class Observation
        {
            internal readonly Condition condition;
            internal byte[] baseline;
            internal bool opened;
            internal uint exit;
            internal Observation(Condition value) { Name(value); condition = value; }
        }
        static void Need(bool value, [System.Runtime.CompilerServices.CallerLineNumber] int source = 0)
        { if (!value) throw new InvalidOperationException("child default-DACL contract failed component=comparison source_check=" + source); }
        static string Name(Condition condition)
        {
            switch (condition) {
                case Condition.Baseline: return "baseline";
                case Condition.UserAllow: return "user-allow";
                case Condition.BaselineAgain: return "baseline-again";
                default: throw new ArgumentException("unsupported child default-DACL condition");
            }
        }
        internal static string Result(Observation value)
        {
            return "WINDOWS_DEFAULT_DACL_CONDITION condition=" + Name(value.condition) +
                " event_fresh_open=" + value.opened + " python_exit=0x" + value.exit.ToString("X8") +
                " process_job_handle_cleanup=True key_readable=True target_admitted=False production_grant=False cause_claimed=False";
        }
        static void Execute(Func<Condition, Observation> observe, Func<Tuple<Action, Action>> begin, Action<string> emit)
        {
            var observations = new List<Observation>(); var lease = begin();
            Exception primary = null; bool clean = true;
            try {
                foreach (Condition condition in new [] { Condition.Baseline, Condition.UserAllow, Condition.BaselineAgain }) {
                    clean = false;
                    Observation value = observe(condition);
                    clean = true;
                    Need(value != null); observations.Add(value);
                    Need(value.condition == condition && value.baseline != null);
                    if (observations.Count > 1) ChildDefaultDacl.RequireEqual(observations[0].baseline, value.baseline);
                    Need(condition != Condition.UserAllow || value.opened);
                    emit(Result(value)); // Observation returns only after complete child cleanup.
                }
                Need(observations[0].opened == observations[2].opened && observations[0].exit == observations[2].exit);
                clean = true;
            }
            catch (Exception failure) { primary = failure; throw; }
            finally {
                try {
                    try { if (clean) lease.Item1(); else lease.Item2(); }
                    catch (Exception cleanup) {
                        if (primary != null) throw new AggregateException("child default-DACL comparison/recovery failed", primary, cleanup);
                        throw;
                    }
                }
                finally { foreach (Observation value in observations) if (value.baseline != null) Array.Clear(value.baseline, 0, value.baseline.Length); }
            }
            emit("WINDOWS_DEFAULT_DACL_DIFFERENTIAL startup_changed=" + (observations[0].exit != observations[1].exit) +
                " event_access_changed=" + (observations[0].opened != observations[1].opened) +
                " baseline_restored=True key_restored=True target_admitted=False production_grant=False cause_claimed=False");
        }
        public static void Run(string run, string state, string python, string root, string scratch, string powershell,
            string chromium, string moniker, string profileFolder, int tcpPort, int udpPort)
        {
            LoaderSnaps.RequireClean(run, state);
            Execute(condition => Sandbox.ObserveDefaultDacl(python, root, scratch, powershell, chromium, moniker,
                profileFolder, tcpPort, udpPort, condition), () => {
                    var lease = RegistryPolicyLease.Begin(run, state);
                    return Tuple.Create<Action, Action>(lease.Dispose, lease.DeferRecovery);
                }, line => { Console.Out.WriteLine(line); Console.Out.Flush(); });
        }
        public static void CheckValidation()
        {
            string first = null, second = null;
            try { Need(false); } catch (InvalidOperationException error) { first = error.Message; }
            try { Need(false); } catch (InvalidOperationException error) { second = error.Message; }
            Need(first != second && System.Text.RegularExpressions.Regex.IsMatch(first,
                @"^child default-DACL contract failed component=comparison source_check=[1-9][0-9]{0,3}$"));
            byte[] baseline = ChildDefaultDacl.Binary(new System.Security.AccessControl.RawAcl(2, 0));
            var order = new List<string>(); int count = 0;
            Execute(condition => {
                count++; order.Add(Name(condition));
                return new Observation(condition) { baseline = (byte[])baseline.Clone(), opened = true,
                    exit = condition == Condition.UserAllow ? 0U : 0xC0150002U };
            }, () => { order.Add("begin"); return Tuple.Create<Action, Action>(() => order.Add("restore"), () => order.Add("defer")); }, _ => order.Add("emit"));
            Need(count == 3 && String.Join(",", order) == "begin,baseline,emit,user-allow,emit,baseline-again,emit,restore,emit");
            foreach (int failAt in new [] { 0, 1, 2, 3 }) {
                count = 0; int restores = 0, deferred = 0; bool refused = false;
                try {
                    Execute(condition => {
                        count++;
                        if (count == failAt + 1) throw new InvalidOperationException("fixed child failure");
                        return new Observation(condition) { baseline = (byte[])baseline.Clone(), opened = true,
                            exit = condition == Condition.BaselineAgain ? 1U : 0U };
                    }, () => Tuple.Create<Action, Action>(() => restores++, () => deferred++), _ => { });
                } catch (InvalidOperationException) { refused = true; }
                Need(refused && deferred == (failAt < 3 ? 1 : 0) && restores == (failAt == 3 ? 1 : 0) &&
                    count == Math.Min(failAt + 1, 3));
            }
            foreach (int mode in new [] { 0, 1, 2 }) {
                int restores = 0, deferred = 0, visits = 0; Exception caught = null;
                var operation = new InvalidOperationException("fixed observation");
                var cleanup = new InvalidOperationException("fixed recovery");
                try {
                    Execute(condition => {
                        visits++;
                        if (mode == 0) throw operation;
                        return new Observation(condition) { baseline = (byte[])baseline.Clone(), opened = true };
                    }, () => Tuple.Create<Action, Action>(
                        () => { restores++; if (mode == 2) throw cleanup; },
                        () => { deferred++; throw cleanup; }), _ => { if (mode == 1) throw operation; });
                } catch (Exception failure) { caught = failure; }
                if (mode == 0) {
                    var group = caught as AggregateException;
                    Need(group != null && group.InnerExceptions.Count == 2 && Object.ReferenceEquals(group.InnerExceptions[0], operation) &&
                        Object.ReferenceEquals(group.InnerExceptions[1], cleanup) && deferred == 1 && restores == 0 && visits == 1);
                } else Need(Object.ReferenceEquals(caught, mode == 1 ? operation : cleanup) && restores == 1 && deferred == 0 && visits == (mode == 1 ? 1 : 3));
            }
            bool invalid = false;
            try { new Observation((Condition)3); } catch (ArgumentException) { invalid = true; }
            Need(invalid && Result(new Observation(Condition.Baseline) { exit = 0xC0150002 }).Contains("python_exit=0xC0150002"));
        }
    }
}
