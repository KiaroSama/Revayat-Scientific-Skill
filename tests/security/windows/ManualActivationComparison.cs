using System;
using System.Collections.Generic;

namespace ScientificSecurity
{
    // Independent diagnostic sweep; the original fatal comparison still runs afterward.
    public static class ManualActivationComparison
    {
        const int Denied = unchecked((int)0xC0000022);
        const string Denial = "WINDOWS_MANUAL_ACTIVATION entry_reached=True created=False win32_error=0x00000005";
        const string Success = "WINDOWS_MANUAL_ACTIVATION entry_reached=True created=True win32_error=0x00000000";
        static void Need(bool value)
        { if (!value) throw new InvalidOperationException("fixed manual activation comparison contract failed"); }

        public static void Run(string run, string state, string python, string root, string scratch, string powershell,
                               string chromium, string moniker, string profileFolder, int tcpPort, int udpPort)
        {
            SelfActivationFixture.RequireHostPositive(python, true);
            Execute((condition, expected) => Sandbox.ObserveManualActivation(python, root, scratch, powershell,
                chromium, moniker, profileFolder, tcpPort, udpPort, expected), () => {
                    var lease = RegistryPolicyLease.Begin(run, state);
                    return Tuple.Create<Action, Action>(lease.Dispose, lease.DeferRecovery);
                }, line => { Console.Out.WriteLine(line); Console.Out.Flush(); });
        }
        static void Execute(Func<string, int, string> observe, Func<Tuple<Action, Action>> begin, Action<string> emit)
        {
            string original = observe("original", Denied);
            emit(SelfActivationFixture.Condition("original", original, true));
            var lease = begin(); Exception primary = null; bool cleanupQualified = false; string modified;
            try {
                modified = observe("modified", 0);
                emit(SelfActivationFixture.Condition("modified", modified, true));
                cleanupQualified = true;
            }
            catch (Exception failure) { primary = failure; throw; }
            finally {
                try { if (cleanupQualified) lease.Item1(); else lease.Item2(); }
                catch (Exception cleanup) {
                    if (primary != null) throw new AggregateException("fixed manual activation operation/recovery failed", primary, cleanup);
                    throw;
                }
            }
            string restored = observe("restored", Denied);
            Need(original == restored);
            emit(SelfActivationFixture.Condition("restored", restored, true));
            emit("WINDOWS_MANUAL_ACTIVATION_DIFFERENTIAL original_restored_equal=True result_changed=" + (original != modified) +
                " manual_only=True target_admitted=False cause_claimed=False python_equivalence_claimed=False production_grant=False");
        }
        public static void CheckValidation()
        {
            foreach (bool originalSuccess in new [] { false, true }) foreach (bool changed in new [] { false, true }) {
                string baseline = originalSuccess ? Success : Denial, different = originalSuccess ? Denial : Success;
                var order = new List<string>(); int visits = 0;
                Execute((condition, expected) => {
                    Need(expected == (condition == "modified" ? 0 : Denied)); visits++;
                    order.Add(condition + ":clean"); return changed && condition == "modified" ? different : baseline;
                }, () => { order.Add("begin"); return Tuple.Create<Action, Action>(() => order.Add("restore"), () => order.Add("defer")); }, line => {
                    if (line.StartsWith("WINDOWS_MANUAL_ACTIVATION_CONDITION ", StringComparison.Ordinal)) order.Add("emit");
                    else { order.Add("comparison"); Need(line == "WINDOWS_MANUAL_ACTIVATION_DIFFERENTIAL original_restored_equal=True result_changed=" + changed +
                        " manual_only=True target_admitted=False cause_claimed=False python_equivalence_claimed=False production_grant=False"); }
                });
                order.Add("main");
                Need(visits == 3 && String.Join(",", order) == "original:clean,emit,begin,modified:clean,emit,restore,restored:clean,emit,comparison,main");
            }
            var primary = new InvalidOperationException("fixed manual operation");
            var recovery = new InvalidOperationException("fixed manual recovery");
            Exception close = Capture.CheckStrictCleanup(); Need(close != null);
            foreach (int mode in new [] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 }) {
                int visits = 0, begins = 0, restores = 0, defers = 0, emissions = 0, later = 0; Exception caught = null;
                try {
                    Execute((condition, expected) => {
                        visits++;
                        if (mode == 0 && visits == 1 || mode == 3 && visits == 2 || mode == 8 && visits == 3 || mode == 11 && visits == 2) throw primary;
                        if (mode == 5 && visits == 2) throw close;
                        if (mode == 4 && visits == 2) return "private-sentinel";
                        return mode == 9 && visits == 3 ? Success : Denial;
                    }, () => {
                        begins++; if (mode == 2) throw primary;
                        return Tuple.Create<Action, Action>(() => { restores++; if (mode == 7) throw recovery; },
                            () => { defers++; if (mode == 11) throw recovery; });
                    }, _ => {
                        emissions++;
                        if (mode == 1 && emissions == 1 || mode == 6 && emissions == 2 || mode == 10 && emissions == 4) throw primary;
                    });
                    later++;
                } catch (Exception failure) { caught = failure; }
                Need(caught != null && later == 0);
                if (mode <= 2) Need(visits == 1 && begins == (mode == 2 ? 1 : 0) && restores == 0 && defers == 0);
                if (mode >= 3 && mode <= 6 || mode == 11) Need(visits == 2 && begins == 1 && restores == 0 && defers == 1);
                if (mode >= 7 && mode <= 10) Need(begins == 1 && restores == 1 && defers == 0 && visits == (mode == 7 ? 2 : 3));
                if (mode == 0 || mode == 1 || mode == 2 || mode == 3 || mode == 6 || mode == 8 || mode == 10) Need(Object.ReferenceEquals(caught, primary));
                if (mode == 5) Need(Object.ReferenceEquals(caught, close));
                if (mode == 7) Need(Object.ReferenceEquals(caught, recovery));
                if (mode == 4 || mode == 9) Need(caught is InvalidOperationException);
                if (mode == 11) {
                    var group = caught as AggregateException;
                    Need(group != null && group.InnerExceptions.Count == 2 && Object.ReferenceEquals(group.InnerExceptions[0], primary) &&
                        Object.ReferenceEquals(group.InnerExceptions[1], recovery));
                }
            }
        }
    }
}
