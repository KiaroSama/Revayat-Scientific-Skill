using System;
using System.Collections.Generic;

namespace ScientificSecurity
{
    // A safely finalized trace never replaces the mandatory undebugged sweep.
    public static class ExplicitEntryComparison
    {
        public static void CheckValidation()
        {
            ActivationBoundaryTrace.CheckExplicitEntryValidation();
            LoaderTrace.CheckEntryEventValidation();
            SelfActivationFixture.CheckEntryHostValidation();
            var primary = new InvalidOperationException("fixed entry observation");
            var later = new InvalidOperationException("fixed undebugged observation");
            var cleanup = Capture.CheckStrictCleanup();
            foreach (int mode in new [] { 0, 1, 2, 3, 4, 5, 6 }) {
                var order = new List<string>(); Exception caught = null;
                try {
                    Execute(() => {
                        order.Add("trace");
                        if (mode == 4) throw primary;
                        if (mode == 5) throw FinishTrace(primary, new List<Exception> { cleanup }, true, true, () => "fixed", _ => { });
                        if (mode == 6) throw FinishTrace(primary, new List<Exception>(), true, false, () => "fixed", _ => { });
                        if (mode == 1 || mode == 3) throw FinishTrace(primary, new List<Exception>(), true, true, () => "fixed", _ => { });
                    }, () => { order.Add("undebugged"); if (mode == 2 || mode == 3) throw later; });
                    order.Add("main");
                } catch (Exception failure) { caught = failure; }
                Need(String.Join(",", order) == (mode == 0 ? "trace,undebugged,main" : mode <= 3 ? "trace,undebugged" : "trace"));
                if (mode == 0) Need(caught == null);
                if (mode == 1 || mode == 4 || mode == 6) Need(Object.ReferenceEquals(caught, primary));
                if (mode == 2) Need(Object.ReferenceEquals(caught, later));
                if (mode == 3 || mode == 5) {
                    var group = caught as AggregateException;
                    Need(group != null && group.InnerExceptions.Count == 2 && Object.ReferenceEquals(group.InnerExceptions[0], primary) &&
                        Object.ReferenceEquals(group.InnerExceptions[1], mode == 3 ? later : cleanup));
                }
            }
            int emitted = 0;
            Need(FinishTrace(null, new List<Exception>(), true, true, () => "fixed", _ => emitted++) == null && emitted == 1);
            var reporting = new InvalidOperationException("fixed entry report");
            Exception qualified = FinishTrace(primary, new List<Exception>(), true, true, () => "fixed", _ => { throw reporting; });
            var carrier = qualified as QualifiedFailure;
            var failures = carrier == null ? null : carrier.Original as AggregateException;
            Need(failures != null && Object.ReferenceEquals(failures.InnerExceptions[0], primary) && Object.ReferenceEquals(failures.InnerExceptions[1], reporting));
            Need(!(FinishTrace(primary, new List<Exception>(), false, false, () => "fixed", _ => emitted++) is QualifiedFailure));
            var prerequisiteOrder = new List<string>(); Exception prerequisite = null;
            try {
                Execute(() => { prerequisiteOrder.Add("created");
                    throw FinishTrace(primary, new List<Exception>(), false, true, () => "fixed", _ => prerequisiteOrder.Add("metadata"));
                }, () => prerequisiteOrder.Add("undebugged"));
                prerequisiteOrder.Add("main");
            } catch (Exception failure) { prerequisite = failure; }
            Need(Object.ReferenceEquals(prerequisite, primary) && String.Join(",", prerequisiteOrder) == "created");
        }
        internal sealed class QualifiedFailure : Exception
        {
            internal readonly Exception Original;
            internal QualifiedFailure(Exception original) : base("fixed entry diagnostic failed after qualified cleanup") { Original = original; }
        }
        internal static Exception FinishTrace(Exception primary, List<Exception> cleanup, bool observed, bool destroyed,
            Func<string> metadata, Action<string> emit)
        {
            if (cleanup.Count != 0) {
                var failures = new List<Exception>();
                if (primary != null) failures.Add(primary);
                failures.AddRange(cleanup);
                return new AggregateException("fixed entry operation/cleanup failed", failures);
            }
            if (!observed || !destroyed) return primary ?? new InvalidOperationException("fixed entry lifetime is unqualified");
            try { emit(metadata()); }
            catch (Exception reporting) { primary = primary == null ? reporting : new AggregateException("fixed entry observation/reporting failed", primary, reporting); }
            return primary == null ? null : new QualifiedFailure(primary);
        }
        internal static void Execute(Action trace, Action undebugged)
        {
            Exception retained = null;
            try { trace(); } catch (QualifiedFailure failure) { retained = failure.Original; }
            try { undebugged(); }
            catch (Exception later) {
                if (retained != null) throw new AggregateException("fixed entry and undebugged observations failed", retained, later);
                throw;
            }
            if (retained != null) throw retained;
        }
        public static void Run(string run, string state, string python, string root, string scratch, string powershell,
            string chromium, string moniker, string profileFolder, int tcpPort, int udpPort)
        {
            Execute(() => Sandbox.ObserveExplicitEntry(python, root, scratch, powershell, chromium, moniker, profileFolder, tcpPort, udpPort),
                () => ManualActivationComparison.RunExplicitId2(run, state, python, root, scratch, powershell, chromium, moniker, profileFolder, tcpPort, udpPort));
        }
        static void Need(bool value)
        { if (!value) throw new InvalidOperationException("fixed explicit entry comparison contract failed"); }
    }
}
