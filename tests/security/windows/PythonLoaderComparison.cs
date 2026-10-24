using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace ScientificSecurity
{
    // Fixed clone wording under three qualified conditions, never ordinary admission or causality.
    public static class PythonLoaderComparison
    {
        internal enum Condition { Original, Modified, Restored }
        const int Denied = unchecked((int)0xC0000022);
        const string ExitPrefix = "LOADER_TRACE_EXIT=0x";
        static void Need(bool value)
        { if (!value) throw new InvalidOperationException("fixed Python loader comparison contract failed"); }
        internal static int Expected(Condition condition)
        {
            Name(condition);
            return condition == Condition.Modified ? 0 : Denied;
        }
        static string Name(Condition condition)
        {
            switch (condition) {
                case Condition.Original: return "original";
                case Condition.Modified: return "modified";
                case Condition.Restored: return "restored";
                default: throw new ArgumentException("unsupported fixed Python loader condition");
            }
        }
        static uint RequireExit(string text)
        {
            Need(text != null && text.Length == ExitPrefix.Length + 8 && text.StartsWith(ExitPrefix, StringComparison.Ordinal));
            for (int index = ExitPrefix.Length; index < text.Length; index++)
                Need(text[index] >= '0' && text[index] <= '9' || text[index] >= 'A' && text[index] <= 'F');
            uint value;
            Need(UInt32.TryParse(text.Substring(ExitPrefix.Length), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out value));
            return value;
        }
        static string Begin(Condition condition)
        {
            return "WINDOWS_PYTHON_LOADER_CONDITION condition=" + Name(condition) +
                " phase=begin clone_only=True target_admitted=False cause_claimed=False";
        }
        static string Complete(Condition condition, uint exit)
        {
            return "WINDOWS_PYTHON_LOADER_CONDITION condition=" + Name(condition) + " phase=complete exit=0x" + exit.ToString("X8") +
                " process_job_handle_cleanup=True ifeo_absent=True clone_only=True target_admitted=False cause_claimed=False";
        }
        static uint ObserveLeg(Condition condition, Func<IDisposable> hold, Action enable, Func<Condition, string> observe,
            Action<Exception, IDisposable> cleanup, Action requireClean, Action<string> emit)
        {
            Name(condition); IDisposable lease = hold(); Exception primary = null; uint exit;
            try {
                enable(); emit(Begin(condition));
                exit = RequireExit(observe(condition)); // Sandbox returns only after all process/Job/handle cleanup.
            }
            catch (Exception failure) { primary = failure; throw; }
            finally { cleanup(primary, lease); }
            requireClean(); emit(Complete(condition, exit));
            return exit;
        }
        static void Execute(Func<Condition, uint> observe, Func<Tuple<Action, Action>> begin)
        {
            observe(Condition.Original);
            var lease = begin(); Exception primary = null; bool cleanupQualified = false;
            try { observe(Condition.Modified); cleanupQualified = true; }
            catch (Exception failure) { primary = failure; throw; }
            finally {
                try { if (cleanupQualified) lease.Item1(); else lease.Item2(); }
                catch (Exception cleanup) {
                    if (primary != null) throw new AggregateException("fixed Python loader operation/recovery failed", primary, cleanup);
                    throw;
                }
            }
            observe(Condition.Restored);
        }
        public static void Run(string run, string state, string python, string root, string scratch, string powershell,
            string chromium, string moniker, string profileFolder, int tcpPort, int udpPort)
        {
            Execute(condition => ObserveLeg(condition, () => PythonStartupFixture.Hold(run, state),
                () => LoaderSnaps.EnablePython(run, state),
                selected => Sandbox.ObservePythonLoader(python, root, scratch, powershell, chromium, moniker, profileFolder,
                    tcpPort, udpPort, selected),
                (primary, held) => LoaderSnaps.Cleanup(run, state, primary, held),
                () => LoaderSnaps.RequireClean(run, state), line => { Console.Out.WriteLine(line); Console.Out.Flush(); }),
                () => {
                    var lease = RegistryPolicyLease.Begin(run, state);
                    return Tuple.Create<Action, Action>(lease.Dispose, lease.DeferRecovery);
                });
        }
        public static void CheckValidation()
        {
            Need(RequireExit("LOADER_TRACE_EXIT=0x00000000") == 0 && RequireExit("LOADER_TRACE_EXIT=0xFFFFFFFF") == UInt32.MaxValue &&
                RequireExit("LOADER_TRACE_EXIT=0xC0000022") == 0xC0000022 && RequireExit("LOADER_TRACE_EXIT=0xC0150002") == 0xC0150002);
            foreach (string invalid in new [] { null, "", "LOADER_TRACE_EXIT=0xC0000022\n", " LOADER_TRACE_EXIT=0xC0000022",
                "LOADER_TRACE_EXIT=0xc0000022", "LOADER_TRACE_EXIT=0xC000022", "LOADER_TRACE_EXIT=0x0C0000022",
                "LOADER_TRACE_EXIT=0xG0000022", "LOADER_TRACE_EXIT=0xC0000022private-sentinel" }) {
                bool refused = false; try { RequireExit(invalid); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            Need(Begin(Condition.Original) == "WINDOWS_PYTHON_LOADER_CONDITION condition=original phase=begin clone_only=True target_admitted=False cause_claimed=False");
            Need(Complete(Condition.Modified, 0xC0150002) == "WINDOWS_PYTHON_LOADER_CONDITION condition=modified phase=complete exit=0xC0150002 process_job_handle_cleanup=True ifeo_absent=True clone_only=True target_admitted=False cause_claimed=False");
            Need(Expected(Condition.Original) == Denied && Expected(Condition.Modified) == 0 && Expected(Condition.Restored) == Denied);
            foreach (int invalid in new [] { -1, 3, Int32.MaxValue }) {
                int effects = 0; bool refused = false;
                try { ObserveLeg((Condition)invalid, () => { effects++; return null; }, () => effects++, _ => "",
                    (_, __) => effects++, () => effects++, _ => effects++); }
                catch (ArgumentException) { refused = true; }
                Need(refused && effects == 0);
            }
            CheckOrder(); CheckLegFailures(); CheckSweepFailures();
        }
        sealed class FixtureLease : IDisposable
        {
            readonly Action close;
            internal FixtureLease(Action close) { this.close = close; }
            public void Dispose() { close(); }
        }
        static void CheckOrder()
        {
            foreach (bool changed in new [] { false, true }) {
                var order = new List<string>(); int launches = 0, completions = 0;
                Execute(condition => {
                    string name = Name(condition);
                    return ObserveLeg(condition, () => { order.Add(name + ":hold"); return new FixtureLease(() => order.Add(name + ":release")); },
                        () => order.Add(name + ":enable"), selected => {
                            Need(selected == condition); launches++; order.Add(name + ":trace-clean");
                            return selected == Condition.Modified && changed ? "LOADER_TRACE_EXIT=0xC0150002" : "LOADER_TRACE_EXIT=0xC0000022";
                        }, (primary, held) => { Need(primary == null); order.Add(name + ":ifeo-clean"); held.Dispose(); },
                        () => order.Add(name + ":absent"), line => {
                            if (line == Begin(condition)) order.Add(name + ":begin");
                            else { Need(line == Complete(condition, condition == Condition.Modified && changed ? 0xC0150002U : 0xC0000022U));
                                order.Add(name + ":complete"); completions++; }
                        });
                }, () => { order.Add("policy-begin"); return Tuple.Create<Action, Action>(() => order.Add("policy-restore"), () => order.Add("policy-defer")); });
                Need(launches == 3 && launches - 1 == 2 && completions == 3 && String.Join(",", order) ==
                    "original:hold,original:enable,original:begin,original:trace-clean,original:ifeo-clean,original:release,original:absent,original:complete," +
                    "policy-begin,modified:hold,modified:enable,modified:begin,modified:trace-clean,modified:ifeo-clean,modified:release,modified:absent,modified:complete," +
                    "policy-restore,restored:hold,restored:enable,restored:begin,restored:trace-clean,restored:ifeo-clean,restored:release,restored:absent,restored:complete");
            }
        }
        static void CheckLegFailures()
        {
            for (int stage = 0; stage < 9; stage++) {
                var primary = new IOException("fixed leg failure"); Exception caught = null;
                int effects = 0, cleaned = 0, released = 0, absent = 0, complete = 0, later = 0;
                try {
                    ObserveLeg(Condition.Modified, () => { if (stage == 0) throw primary; return new FixtureLease(() => { released++; if (stage == 6) throw primary; }); },
                        () => { effects++; if (stage == 1) throw primary; }, _ => {
                            effects++; if (stage == 3) throw primary;
                            return stage == 4 ? "private-sentinel" : "LOADER_TRACE_EXIT=0xC0150002";
                        }, (original, held) => {
                            cleaned++; Exception error = null;
                            try { if (stage == 5) throw primary; } catch (Exception failure) { error = failure; }
                            try { held.Dispose(); } catch (Exception failure) { error = failure; }
                            if (error != null) {
                                if (original != null) throw new AggregateException(original, error);
                                throw error;
                            }
                        }, () => { absent++; if (stage == 7) throw primary; }, line => {
                            if (line == Begin(Condition.Modified)) { if (stage == 2) throw primary; }
                            else { complete++; if (stage == 8) throw primary; }
                        });
                    later++;
                } catch (Exception failure) { caught = failure; }
                Need(caught != null && later == 0 && cleaned == (stage == 0 ? 0 : 1) && released == cleaned &&
                    absent == (stage >= 7 ? 1 : 0) && complete == (stage == 8 ? 1 : 0) &&
                    effects == (stage == 0 ? 0 : stage <= 2 ? 1 : 2));
                Need(stage == 4 ? caught is InvalidOperationException : Object.ReferenceEquals(caught, primary));
            }
            var operation = new IOException("fixed trace"); var cleanup = new IOException("fixed cleanup");
            AggregateException combined = null; int attempts = 0;
            try {
                ObserveLeg(Condition.Modified, () => new FixtureLease(() => { attempts++; }), () => { }, _ => { throw operation; },
                    (primary, held) => { held.Dispose(); throw new AggregateException(primary, cleanup); },
                    () => { throw new IOException("absence must not run"); }, _ => { });
            } catch (AggregateException failure) { combined = failure; }
            Need(attempts == 1 && combined != null && combined.InnerExceptions.Count == 2 &&
                Object.ReferenceEquals(combined.InnerExceptions[0], operation) && Object.ReferenceEquals(combined.InnerExceptions[1], cleanup));
        }
        static void CheckSweepFailures()
        {
            for (int stage = 0; stage < 7; stage++) {
                var primary = new IOException("fixed sweep"); var recovery = new IOException("fixed third-state recovery");
                int visits = 0, begins = 0, restores = 0, defers = 0, later = 0; Exception caught = null;
                try {
                    Execute(condition => {
                        visits++;
                        if (stage == 0 && condition == Condition.Original || (stage == 2 || stage == 3) && condition == Condition.Modified ||
                            stage == 5 && condition == Condition.Restored) throw primary;
                        return condition == Condition.Modified ? UInt32.MaxValue : 0U; // Exits are not compared or treated as admission.
                    }, () => {
                        begins++; if (stage == 1) throw primary;
                        return Tuple.Create<Action, Action>(() => { restores++; if (stage == 4 || stage == 6) throw recovery; },
                            () => { defers++; if (stage == 3) throw recovery; });
                    });
                    later++;
                } catch (Exception failure) { caught = failure; }
                Need(caught != null && later == 0 && visits == (stage <= 1 ? 1 : stage == 5 ? 3 : 2) &&
                    begins == (stage == 0 ? 0 : 1) && restores == (stage >= 4 ? 1 : 0) && defers == (stage == 2 || stage == 3 ? 1 : 0));
                if (stage == 3) {
                    var group = caught as AggregateException;
                    Need(group != null && group.InnerExceptions.Count == 2 && Object.ReferenceEquals(group.InnerExceptions[0], primary) &&
                        Object.ReferenceEquals(group.InnerExceptions[1], recovery));
                } else Need(Object.ReferenceEquals(caught, stage == 4 || stage == 6 ? recovery : primary));
            }
        }
    }
}
