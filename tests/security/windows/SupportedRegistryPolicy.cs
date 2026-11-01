using System;
using System.Collections.Generic;

namespace ScientificSecurity
{
    // The approved surface is this whole fixed key, not a harmless-content certificate.
    public sealed class SupportedRegistryPolicy : IDisposable
    {
        static SupportedRegistryPolicy active;
        readonly RegistryPolicyLease lease;
        readonly RegistryAuthoritySurface.Snapshot before;
        string moniker;
        int runs;
        bool uncertain, qualified, closed;
        SupportedRegistryPolicy(RegistryPolicyLease owned, RegistryAuthoritySurface.Snapshot original)
        { lease = owned; before = original; }
        static void Need(bool value)
        { if (!value) throw new InvalidOperationException("supported registry policy is unqualified"); }
        internal static void RequireTrialAvailable() { Need(active == null); }
        internal static int RequireReadable() { Need(active != null && active.qualified && !active.closed && !active.uncertain); return 0; }
        internal static int? OrdinaryCondition() { return active == null ? (int?)null : RequireReadable(); }
        internal static SupportedRegistryPolicy EnterRun(string packageMoniker)
        {
            var current = active;
            if (current != null) { Need(packageMoniker == current.moniker && !current.closed && !current.uncertain && current.runs == 0); current.runs++; }
            return current;
        }
        internal void EndRun(bool cleanupQualified)
        { Need(Object.ReferenceEquals(active, this) && runs == 1); runs--; uncertain |= !cleanupQualified; }
        public static SupportedRegistryPolicy Begin(string run, string state, string python, string root, string scratch,
            string powershell, string chromium, string moniker, string profileFolder, int tcpPort, int udpPort)
        {
            RequireTrialAvailable(); Need(moniker == "Scientific.Security." + run); LoaderSnaps.RequireClean(run, state);
            var original = RegistryAuthoritySurface.Read();
            original.RequireEqual(RegistryAuthoritySurface.Read());
            var policy = new SupportedRegistryPolicy(RegistryPolicyLease.Begin(run, state), original) { moniker = moniker };
            active = policy;
            var observation = new RegistryAuthorityComparison.Observation(); Exception primary = null;
            try {
                policy.lease.BindSupported();
                Sandbox.ObserveRegistryAuthority(python, root, scratch, powershell, chromium, moniker, profileFolder,
                    tcpPort, udpPort, observation);
                RegistryAuthorityComparison.RequireRootOnly(observation.wire);
                Need(observation.recorded && policy.runs == 0 && !policy.uncertain);
                policy.qualified = true;
                Console.Out.WriteLine("WINDOWS_SUPPORTED_REGISTRY authority_qualified=True root_key_read_authorized=True immediate_child_reads_denied=True inherited_grant=False content_harmlessness_claimed=False deeper_denial_claimed=False restoration=pending");
                Console.Out.Flush();
                return policy;
            }
            catch (Exception failure) { primary = failure; throw; }
            finally {
                observation.Clear();
                if (primary != null) {
                    try { policy.Dispose(); }
                    catch (Exception cleanup) { throw new AggregateException("supported registry qualification/cleanup failed", primary, cleanup); }
                }
            }
        }
        internal static void Finish(bool safe, Action restore, Action defer, Action compare)
        {
            if (!safe) {
                var failure = new InvalidOperationException("supported registry process cleanup remains uncertain");
                try { defer(); } catch (Exception cleanup) { throw new AggregateException("supported registry recovery deferred", failure, cleanup); }
                throw failure;
            }
            restore(); compare();
        }
        public void Dispose()
        {
            if (closed) return;
            Need(Object.ReferenceEquals(active, this)); closed = true;
            try {
                Finish(runs == 0 && !uncertain, lease.Dispose, lease.DeferRecovery,
                    () => before.RequireEqual(RegistryAuthoritySurface.Read()));
                Console.Out.WriteLine("WINDOWS_SUPPORTED_REGISTRY key_restored=True host_surface_equal=True process_job_handle_cleanup=True");
                Console.Out.Flush();
            }
            finally { active = null; }
        }
        public static void CheckValidation()
        {
            for (int mode = 0; mode < 5; mode++) {
                var order = new List<string>(); var restore = new InvalidOperationException("fixed restore");
                var compare = new InvalidOperationException("fixed compare"); Exception caught = null;
                try {
                    Finish(mode != 1 && mode != 2,
                        () => { order.Add("restore"); if (mode == 3) throw restore; },
                        () => { order.Add("defer"); if (mode == 2) throw restore; },
                        () => { order.Add("compare"); if (mode == 4) throw compare; });
                } catch (Exception failure) { caught = failure; }
                Need(String.Join(",", order) == (mode == 1 || mode == 2 ? "defer" : mode == 3 ? "restore" : "restore,compare"));
                Need(mode == 0 ? caught == null : caught != null);
                if (mode == 3) Need(Object.ReferenceEquals(caught, restore));
                if (mode == 4) Need(Object.ReferenceEquals(caught, compare));
            }
            Need(active == null && EnterRun(null) == null);
            bool refused = false; try { RequireReadable(); } catch (InvalidOperationException) { refused = true; } Need(refused);
            var policy = new SupportedRegistryPolicy(null, null); active = policy;
            try {
                refused = false; try { RequireTrialAvailable(); } catch (InvalidOperationException) { refused = true; } Need(refused);
                policy.moniker = "fixed-run";
                refused = false; try { EnterRun("other-run"); } catch (InvalidOperationException) { refused = true; } Need(refused);
                Need(Object.ReferenceEquals(EnterRun("fixed-run"), policy));
                refused = false; try { EnterRun("fixed-run"); } catch (InvalidOperationException) { refused = true; } Need(refused);
                policy.EndRun(true); Need(!policy.uncertain && policy.runs == 0);
                policy.qualified = true; Need(RequireReadable() == 0);
                EnterRun("fixed-run"); policy.EndRun(false);
                Need(policy.uncertain && policy.runs == 0);
                refused = false; try { EnterRun(null); } catch (InvalidOperationException) { refused = true; } Need(refused);
            } finally { active = null; }
        }
    }
}
