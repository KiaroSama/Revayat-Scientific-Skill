using System;
using System.Collections.Generic;

namespace ScientificSecurity
{
    public static partial class CsrDispatchComparison
    {
        static Exception moduleRetained;
        public static void RunModule(string run, string state, string python, string root, string scratch, string powershell,
            string chromium, string moniker, string profileFolder, int tcpPort, int udpPort)
        {
            Need(moduleRetained == null); ModuleActivationFixture.RequireDispatchHostPositive(python); LoaderSnaps.RequireClean(run, state);
            moduleRetained = Execute(value => Sandbox.ObserveCsrDispatch(python, root, scratch, powershell, chromium,
                moniker, profileFolder, tcpPort, udpPort, value), () => {
                    var lease = RegistryPolicyLease.Begin(run, state);
                    return Tuple.Create<Action, Action>(lease.Dispose, lease.DeferRecovery);
                }, line => { Console.Out.WriteLine(line); Console.Out.Flush(); }, true);
        }
        public static void CheckModuleValidation()
        {
            const string good = "WINDOWS_MODULE_ACTIVATION attach=1 query_succeeded=1 root_evaluated=1 root_is_module=1 win32_error=0x00000000 returned_bytes=0x00000080 assembly_count=0x00000003\n";
            foreach (bool traced in new [] { false, true }) {
                var value = new CsrDispatchObservation(traced, true); value.Record(0, good, "");
                Need(value.completed && !value.receipt && value.characters == good.Length &&
                    value.Metadata().Contains("entry_observed=True association_proved=True completed_wire=True") &&
                    value.Metadata().Contains("invocation_module_verified=False") && !value.Metadata().Contains("pre_call"));
                var failed = new CsrDispatchObservation(traced, true); failed.Record(0xC0150002, "", "");
                Need(!failed.completed && failed.Metadata().Contains("entry_observed=False association_proved=False"));
                foreach (var input in new [] {
                    Tuple.Create(0U, "", ""), Tuple.Create(1U, "", ""), Tuple.Create(121U, "", ""),
                    Tuple.Create(0U, good.TrimEnd('\n'), ""), Tuple.Create(0U, good + good, ""),
                    Tuple.Create(0U, good.Replace("root_is_module=1", "root_is_module=0"), ""),
                    Tuple.Create(0U, good, "private-sentinel"), Tuple.Create(0xC0150002U, good, ""),
                    Tuple.Create(0U, new string('x', 257), ""),
                    Tuple.Create(0U, "EXPLICIT_ID2_BEFORE_CALL\n", "")
                }) {
                    bool refused = false;
                    try { new CsrDispatchObservation(traced, true).Record(input.Item1, input.Item2, input.Item3); }
                    catch (InvalidOperationException error) { refused = !error.Message.Contains("private-sentinel"); }
                    Need(refused);
                }
                bool crossRole = false;
                try { new CsrDispatchObservation(traced).Record(0, good, ""); } catch (InvalidOperationException) { crossRole = true; }
                Need(crossRole);
            }
            ModuleActivationFixture.CheckDispatchValidation(); TrustedSetup.CheckModuleDispatchValidation();
            var first = new InvalidOperationException("fixed explicit failure");
            var second = new InvalidOperationException("fixed module failure");
            var later = new InvalidOperationException("fixed later failure");
            Need(retained == null && moduleRetained == null); retained = first; moduleRetained = second;
            var combined = PreserveFailure(later) as AggregateException;
            var prior = combined == null ? null : combined.InnerExceptions[0] as AggregateException;
            Need(prior != null && Object.ReferenceEquals(prior.InnerExceptions[0], first) &&
                Object.ReferenceEquals(prior.InnerExceptions[1], second) && Object.ReferenceEquals(combined.InnerExceptions[1], later));
            Need(PreserveFailure(null) == null);
            foreach (bool uncertain in new [] { false, true }) {
                var order = new List<string>(); Exception caught = null, result = null;
                try {
                    result = Execute(value => {
                        Need(value.module); order.Add(value.traced ? "trace" : "undebugged");
                        if (value.traced) throw FinishUndebugged(first, uncertain ? new List<Exception> { second } : new List<Exception>(), true, true, true);
                        value.Record(0, good, "");
                    }, () => Tuple.Create<Action, Action>(() => order.Add("restore"), () => order.Add("defer")), _ => order.Add("emit"), true);
                    order.Add("original-chain");
                } catch (Exception error) { caught = error; }
                Need(uncertain ? caught is AggregateException && result == null && String.Join(",", order) == "trace,defer" :
                    caught == null && Object.ReferenceEquals(result, first) && String.Join(",", order) == "trace,undebugged,emit,restore,original-chain");
            }
        }
    }
    public static partial class ModuleActivationFixture
    {
        static bool dispatchHostPositive;
        internal static void RequireDispatchHostPositive(string python)
        { PreparedImage(python, true); Need(dispatchHostPositive); }
        internal static ActivationBoundaryTrace DispatchObserver(string python, Native.ProcessInfo child, Action<string> emit, Action deadline)
        {
            string image = PreparedImage(python, true);
            return new ActivationBoundaryTrace(child.process, child.thread, child.pid, child.tid, image, prepared.hashes[2], emit,
                false, false, true, deadline, true, true);
        }
        public static void RunDispatchHost(string python)
        {
            Need(!dispatchHostPositive); IDisposable held = Hold(python, true);
            CompleteDispatchHost(retain => TrustedSetup.RunModuleCsrDispatch(python, retain), held.Dispose,
                line => { Console.Out.WriteLine(line); Console.Out.Flush(); }, () => dispatchHostPositive = true);
        }
        static void CompleteDispatchHost(Func<Action<string>, string> run, Action close, Action<string> emit, Action accept)
        {
            Exception primary = null; string metadata = null;
            try {
                string result = run(line => { Need(metadata == null && line != null); metadata = line; });
                Need(result != null && result.StartsWith("entry_observed=True association_proved=True exit=0x00000000 ", StringComparison.Ordinal));
                Condition("modified", true, result); Need(metadata != null);
            } catch (Exception error) { primary = error; throw; }
            finally {
                try { close(); } catch (Exception cleanup) {
                    if (primary != null) throw new AggregateException("module CSR host operation/lease cleanup failed", primary, cleanup);
                    throw;
                }
            }
            emit(metadata);
            emit("WINDOWS_MODULE_CSR_HOST positive=True cleanup_complete=True invocation_module_verified=False cause_claimed=False"); accept();
        }
        internal static void CheckDispatchValidation()
        {
            const string wire = "WINDOWS_MODULE_ACTIVATION attach=1 query_succeeded=1 root_evaluated=1 root_is_module=1 win32_error=0x00000000 returned_bytes=0x00000080 assembly_count=0x00000003\n";
            for (int mode = 0; mode < 7; mode++) {
                var order = new List<string>(); Exception caught = null;
                try {
                    CompleteDispatchHost(retain => {
                        order.Add("process-clean"); if (mode != 1) retain("fixed");
                        if (mode == 2) throw new InvalidOperationException("fixed host");
                        return mode == 6 ? Result(true, 0xC0150002, "", "") : Result(true, 0, wire, "");
                    }, () => { order.Add("lease-close"); if (mode == 3) throw new InvalidOperationException("fixed close"); },
                    line => { order.Add(line == "fixed" ? "metadata" : "positive");
                        if (mode == 4 || mode == 5 && line != "fixed") throw new InvalidOperationException("fixed report"); }, () => order.Add("latch"));
                } catch (Exception error) { caught = error; }
                Need((caught == null) == (mode == 0) && order.Contains("lease-close") && order.Contains("latch") == (mode == 0));
                if (mode == 0) Need(String.Join(",", order) == "process-clean,lease-close,metadata,positive,latch");
            }
            Need(!dispatchHostPositive);
        }
    }
}
