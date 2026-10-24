using System;
using System.Collections.Generic;

namespace ScientificSecurity
{
    public static partial class CsrDispatchComparison
    {
        static Exception retained;
        static void Need(bool value)
        { if (!value) throw new InvalidOperationException("fixed CSR dispatch comparison is inconclusive"); }
        // Only a failure qualified by the existing complete-cleanup carrier permits later diagnostics.
        internal static Exception Execute(Action<CsrDispatchObservation> observe, Func<Tuple<Action, Action>> begin, Action<string> emit, bool module = false, bool python = false)
        {
            Need(!module || !python);
            var lease = begin(); Exception primary = null, diagnostic = null; bool clean = true;
            try {
                foreach (bool traced in new [] { true, false }) {
                    var value = new CsrDispatchObservation(traced, module, python); clean = false; bool qualifiedFailure = false;
                    try { observe(value); clean = true; }
                    catch (ExplicitEntryComparison.QualifiedFailure failure) {
                        clean = qualifiedFailure = true;
                        diagnostic = diagnostic == null ? failure.Original : new AggregateException("CSR dispatch diagnostics failed", diagnostic, failure.Original);
                    }
                    if (value.recorded) {
                        if (python && !value.completed) {
                            var failure = new InvalidOperationException("fixed Python CSR pass failed raw_process_exit=0x" + value.exit.ToString("X8"));
                            diagnostic = diagnostic == null ? failure : new AggregateException("CSR dispatch diagnostics failed", diagnostic, failure);
                        }
                        emit(value.Metadata());
                    } else Need(qualifiedFailure);
                }
            }
            catch (Exception failure) {
                primary = diagnostic == null ? failure : new AggregateException("CSR dispatch observations failed", diagnostic, failure);
                throw primary;
            }
            finally {
                try { if (clean) lease.Item1(); else lease.Item2(); }
                catch (Exception cleanup) {
                    var errors = new List<Exception>();
                    if (primary != null) errors.Add(primary); else if (diagnostic != null) errors.Add(diagnostic);
                    errors.Add(cleanup);
                    throw new AggregateException("CSR dispatch operation/recovery failed", errors);
                }
            }
            return diagnostic;
        }
        public static void Run(string run, string state, string python, string root, string scratch, string powershell,
            string chromium, string moniker, string profileFolder, int tcpPort, int udpPort)
        {
            Need(retained == null); SelfActivationFixture.RequireDispatchHostPositive(python); LoaderSnaps.RequireClean(run, state);
            retained = Execute(value => Sandbox.ObserveCsrDispatch(python, root, scratch, powershell, chromium,
                moniker, profileFolder, tcpPort, udpPort, value), () => {
                    var lease = RegistryPolicyLease.Begin(run, state);
                    return Tuple.Create<Action, Action>(lease.Dispose, lease.DeferRecovery);
                }, line => { Console.Out.WriteLine(line); Console.Out.Flush(); });
        }
        public static Exception PreserveFailure(Exception later)
        {
            Exception failure = retained; retained = null;
            if (moduleRetained != null) {
                failure = failure == null ? moduleRetained : new AggregateException("CSR dispatch roles failed", failure, moduleRetained);
                moduleRetained = null;
            }
            if (pythonRetained != null) {
                failure = failure == null ? pythonRetained : new AggregateException("CSR dispatch roles failed", failure, pythonRetained);
                pythonRetained = null;
            }
            return failure == null ? later : later == null ? failure : new AggregateException("CSR dispatch and subsequent operation failed", failure, later);
        }
        internal static void RetainValidationFailure(Exception failure)
        { Need(failure != null && retained == null && moduleRetained == null && pythonRetained == null); retained = failure; }
        public static void RequireClean()
        { Exception failure = PreserveFailure(null); if (failure != null) throw failure; }
        internal static Exception FinishUndebugged(Exception primary, List<Exception> cleanup, bool started, bool signaled, bool reaped)
        { return ExplicitEntryComparison.FinishTrace(primary, cleanup, started, signaled && reaped, () => "", _ => { }); }
        public static void CheckValidation()
        {
            KernelImage.CheckCsrDispatchValidation(); ActivationBoundaryTrace.CheckCsrDispatchValidation();
            CheckLifecycleValidation();
        }
        public static void CheckLifecycleValidation()
        {
            CsrDispatchObservation.CheckValidation(); SelfActivationFixture.CheckDispatchHostValidation();
            var operation = new InvalidOperationException("fixed diagnostic"); var cleanup = new InvalidOperationException("fixed recovery");
            for (int mode = 0; mode < 8; mode++) {
                var order = new List<string>(); Exception caught = null, result = null;
                try {
                    result = Execute(value => {
                        order.Add(value.traced ? "trace-clean" : "undebugged-clean");
                        if (mode == 3 && value.traced || mode == 4 && !value.traced) throw operation;
                        value.Record(0xC0150002, "", "");
                        if (mode == 1 && value.traced || mode == 2 || mode == 7 && value.traced)
                            throw ExplicitEntryComparison.FinishTrace(operation, new List<Exception>(), true, true, () => "fixed", _ => { });
                    }, () => { order.Add("begin"); return Tuple.Create<Action, Action>(
                        () => { order.Add("restore"); if (mode == 6 || mode == 7) throw cleanup; }, () => order.Add("defer")); },
                    _ => { order.Add("emit"); if (mode == 5) throw operation; });
                } catch (Exception failure) { caught = failure; }
                if (mode == 0 || mode == 1 || mode == 2) {
                    Need(caught == null && String.Join(",", order) == "begin,trace-clean,emit,undebugged-clean,emit,restore");
                    Need(mode == 0 ? result == null : result != null);
                } else {
                    Need(caught != null && order.Contains("defer") == (mode == 3 || mode == 4));
                    Need(order.Contains("restore") == (mode >= 5));
                    if (mode == 7) {
                        var group = caught as AggregateException;
                        Need(group != null && group.InnerExceptions.Count == 2 && Object.ReferenceEquals(group.InnerExceptions[0], operation) && Object.ReferenceEquals(group.InnerExceptions[1], cleanup));
                    }
                }
            }
            Need(retained == null); retained = operation;
            var combined = PreserveFailure(cleanup) as AggregateException;
            Need(combined != null && Object.ReferenceEquals(combined.InnerExceptions[0], operation) && Object.ReferenceEquals(combined.InnerExceptions[1], cleanup));
            Need(PreserveFailure(null) == null);
            foreach (bool cleanupFails in new [] { false, true }) {
                var order = new List<string>(); Exception caught = null, diagnostic = null;
                try {
                    diagnostic = Execute(value => {
                        if (value.traced) { value.Record(0xC0150002, "", ""); order.Add("trace-clean"); return; }
                        Exception refusal = null;
                        try { value.Record(0, "EXPLICIT_ID2_BEFORE_CALL\n", ""); }
                        catch (InvalidOperationException failure) { refusal = failure; }
                        Need(refusal != null && !value.recorded); order.Add("undebugged-clean");
                        throw FinishUndebugged(refusal, cleanupFails ? new List<Exception> { cleanup } : new List<Exception>(), true, true, true);
                    }, () => Tuple.Create<Action, Action>(() => order.Add("restore"), () => order.Add("defer")), _ => order.Add("emit"));
                    order.Add("original-chain");
                } catch (Exception failure) { caught = failure; }
                Need(cleanupFails ? caught is AggregateException && diagnostic == null && String.Join(",", order) == "trace-clean,emit,undebugged-clean,defer" :
                    caught == null && diagnostic is InvalidOperationException && String.Join(",", order) == "trace-clean,emit,undebugged-clean,restore,original-chain");
            }
            foreach (bool started in new [] { false, true }) foreach (bool signaled in new [] { false, true }) foreach (bool reaped in new [] { false, true })
                Need((FinishUndebugged(operation, new List<Exception>(), started, signaled, reaped) is ExplicitEntryComparison.QualifiedFailure) == (started && signaled && reaped));
        }
    }
}
