using System;
using System.Collections.Generic;

namespace ScientificSecurity
{
    // Trusted original/modified/restored runs only; never an admission certificate.
    public static class RegistryCausalComparison
    {
        const int Denied = unchecked((int)0xC0000022);
        const string ActivationDenied = "WINDOWS_CHILD_ACTIVATION created=False win32_error=0x00000005 cause_claimed=False child_equivalence_claimed=False";
        sealed class Observation { internal string activation; internal uint exit; }
        static void Need(bool value)
        { if (!value) throw new InvalidOperationException("fixed registry causal comparison contract failed"); }
        static void Baseline(Observation value)
        { Need(value.activation == ActivationDenied && value.exit == 0xC0000022); }
        static uint Execute(Func<int, Observation> observe, Func<Trial> begin, Action<string> emit)
        {
            Observation original = observe(Denied); Baseline(original);
            Observation modified;
            Trial lease = begin(); Exception primary = null; bool cleanupQualified = false;
            try { modified = observe(0); cleanupQualified = true; }
            catch (Exception failure) { primary = failure; throw; }
            finally {
                try { if (cleanupQualified) lease.restore(); else lease.defer(); }
                catch (Exception cleanup) {
                    if (primary != null) throw new AggregateException("fixed registry trial/recovery failed", primary, cleanup);
                    throw;
                }
            }
            Observation restored = observe(Denied); Baseline(restored);
            emit("WINDOWS_REGISTRY_DIFFERENTIAL original_python_exit=0x" + original.exit.ToString("X8") +
                " modified_python_exit=0x" + modified.exit.ToString("X8") + " restored_python_exit=0x" + restored.exit.ToString("X8") +
                " activation_changed=" + (original.activation != modified.activation) +
                " python_exit_changed=" + (original.exit != modified.exit) +
                " restored_baseline=True target_admitted=False cause_claimed=False production_grant=False");
            return original.exit;
        }
        static string Condition(string condition, string activation, uint exit)
        {
            Need(condition == "original" || condition == "modified" || condition == "restored");
            Need(ChildActivationFixture.RequireResult(activation + "\n") == activation);
            return "WINDOWS_REGISTRY_CONDITION condition=" + condition + " " + activation +
                " python_exit=0x" + exit.ToString("X8") + " target_admitted=False cause_claimed=False";
        }
        public static uint Run(string run, string state, string python, string root, string scratch, string powershell,
                               string chromium, string moniker, string profileFolder, int tcpPort, int udpPort)
        {
            int visit = 0;
            return Execute(expected => {
                string condition = new [] { "original", "modified", "restored" }[visit++];
                string activation = ChildActivationFixture.RequireResult(Sandbox.ObserveActivation(python, root, scratch,
                    powershell, chromium, moniker, profileFolder, tcpPort, udpPort, expected));
                uint exit = Sandbox.ObservePreflightExit(python, root, scratch, powershell, chromium, moniker, profileFolder,
                    tcpPort, udpPort, expected);
                Console.Out.WriteLine(Condition(condition, activation, exit));
                Console.Out.Flush();
                return new Observation { activation = activation, exit = exit };
            }, () => {
                var lease = RegistryPolicyLease.Begin(run, state);
                return new Trial(lease.Dispose, lease.DeferRecovery);
            }, line => { Console.Out.WriteLine(line); Console.Out.Flush(); });
        }
        public static void RequireAdmission(uint originalExit)
        { if (originalExit != 0) throw new InvalidOperationException("original ordinary admission failure remains batch-fatal"); }
        sealed class Trial
        {
            internal readonly Action restore, defer;
            internal Trial(Action restore, Action defer) { this.restore = restore; this.defer = defer; }
        }
        public static void CheckValidation()
        {
            string success = "WINDOWS_CHILD_ACTIVATION created=True win32_error=0x00000000 cause_claimed=False child_equivalence_claimed=False";
            string otherFailure = ActivationDenied.Replace("00000005", "00000002");
            Need(Condition("modified", success, 0).Contains("created=True win32_error=0x00000000") &&
                Condition("modified", otherFailure, 0xC0000022).Contains("created=False win32_error=0x00000002"));
            foreach (bool changes in new [] { false, true }) {
                var order = new List<string>(); string result = null; int visits = 0;
                uint originalExit = Execute(expected => {
                    visits++; order.Add("observe" + visits);
                    Need(expected == (visits == 2 ? 0 : Denied));
                    return new Observation { activation = visits == 2 && changes ?
                        "WINDOWS_CHILD_ACTIVATION created=True win32_error=0x00000000 cause_claimed=False child_equivalence_claimed=False" : ActivationDenied,
                        exit = visits == 2 && changes ? 0U : 0xC0000022U };
                }, () => { order.Add("begin"); return new Trial(() => order.Add("restore"), () => order.Add("defer")); }, line => { order.Add("emit"); result = line; });
                Need(String.Join(",", order) == "observe1,begin,observe2,restore,observe3,emit" &&
                    result.Contains("activation_changed=" + changes + " python_exit_changed=" + changes) &&
                    result.EndsWith("restored_baseline=True target_admitted=False cause_claimed=False production_grant=False", StringComparison.Ordinal));
                bool admitted = false, refused = false;
                try { uint repeatedPreflight = 0; Need(repeatedPreflight == 0); RequireAdmission(originalExit); admitted = true; }
                catch (InvalidOperationException) { refused = true; }
                Need(refused && !admitted);
            }
            var primary = new InvalidOperationException("fixed operation"); var recovery = new InvalidOperationException("fixed recovery");
            foreach (bool cleanupFails in new [] { false, true }) {
                int visits = 0, restores = 0, deferred = 0, emissions = 0; Exception caught = null;
                try {
                    Execute(_ => { if (++visits == 2) throw primary; return new Observation { activation = ActivationDenied, exit = 0xC0000022 }; },
                        () => new Trial(() => restores++, () => { deferred++; if (cleanupFails) throw recovery; }), _ => emissions++);
                }
                catch (Exception failure) { caught = failure; }
                var aggregate = caught as AggregateException;
                Need(visits == 2 && restores == 0 && deferred == 1 && emissions == 0 && (cleanupFails ?
                    aggregate != null && aggregate.InnerExceptions.Count == 2 && Object.ReferenceEquals(aggregate.InnerExceptions[0], primary) &&
                        Object.ReferenceEquals(aggregate.InnerExceptions[1], recovery) : Object.ReferenceEquals(caught, primary)));
            }
            foreach (bool wrongActivation in new [] { false, true }) {
                int begins = 0; bool refused = false;
                try { Execute(_ => new Observation { activation = wrongActivation ? "other" : ActivationDenied,
                    exit = wrongActivation ? 0xC0000022U : 0U }, () => { begins++; return new Trial(() => { }, () => { }); }, _ => { }); }
                catch (InvalidOperationException) { refused = true; }
                Need(refused && begins == 0);
            }
        }
    }
}
