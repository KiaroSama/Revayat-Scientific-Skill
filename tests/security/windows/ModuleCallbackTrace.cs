using System;

namespace ScientificSecurity
{
    internal sealed class QualifiedModuleCallbackFailure : Exception
    {
        internal readonly Exception Original;
        internal QualifiedModuleCallbackFailure(Exception original)
            : base("fixed module callback diagnostic failed after qualified cleanup") { Original = original; }
    }
    // Closed pre-entry mode; shared context/cleanup mechanics never select a later invocation.
    public sealed partial class ActivationBoundaryTrace
    {
        readonly bool moduleCallback;
        static bool CallbackComplete(int state, bool restoration, bool invalid)
        { return state == 3 && restoration && !invalid; }
        static string CallbackResult(byte[] context)
        { return "failure_sentinel=" + (U64(context, 120) == UInt64.MaxValue); }
        bool CallbackSoftwareStage(uint eventThread, uint code, bool first)
        {
            return !invalidated && stage >= 1 && stage <= 3 &&
                LoaderTrace.AcceptInitialBreakpoint(eventThread, tid, code, first, initial, null);
        }
        bool CallbackHardwareStage(uint eventThread, bool first)
        { return !invalidated && stage == 2 && first && eventThread == tid && original != null && kernel != null; }
        bool CallbackLoadStage()
        { return !invalidated && stopped && alive && stage == 1 && kernel == null && !changed && !restored; }
        void CallbackCreation(IntPtr file, IntPtr imageBase)
        {
            Need(stage == 0 && stopped && alive);
            fixture = KernelImage.FromModuleCallbackCreation(file, imageBase, path, digest);
            original = Read(); Need(Free(original)); stage = 1;
            emit("phase=module-callback-create identity_qualified=True baseline_free=True entry_armed=False");
        }
        void CallbackLoad(IntPtr file, IntPtr imageBase)
        {
            Need(stopped && alive && stage != 0);
            KernelImage candidate = KernelImage.FromActivationSystemLoad(file, imageBase);
            if (candidate == null) return;
            Need(CallbackLoadStage());
            candidate.RequireModuleCallbackProfile(); kernel = candidate;
            uint site = kernel.ActivationCallbackSite;
            RequireExecutable(kernel, site, 5);
            byte[] before = Read();
            try {
                if (initial) Ownership(before, false);
                else Need(DebugContext.RawDebugEqual(original, before));
                addresses[0] = kernel.Address(site);
                enabled[0] = true; stage = 2; Apply(before, false);
            }
            finally { Array.Clear(before, 0, before.Length); }
            emit("phase=module-callback-load identity_equal=True fixed_profile=True dr0_armed=True entry_armed=False control_integer_unchanged=True");
        }
        bool CallbackSoftware(uint eventThread, uint code, bool first)
        {
            if (code != 0x80000003) return false;
            Check(CallbackSoftwareStage(eventThread, code, first), "software-stage");
            byte[] before = Read(); string qualifiers;
            try { Ownership(before, false); qualifiers = DebugContext.TrapQualifiers(U64(before, 104)); initial = true; }
            finally { Array.Clear(before, 0, before.Length); }
            emit("phase=module-callback-software-stop origin_verified=False ordering_only=True " + qualifiers);
            return true;
        }
        bool CallbackSingleStep(uint eventThread, uint code, bool first, IntPtr exceptionAddress)
        {
            if (code != 0x80000004) return false;
            Check(CallbackHardwareStage(eventThread, first), "hardware-stage");
            byte[] before = Read();
            try {
                ulong status = U64(before, 104); Ownership(before, true);
                Check(DebugContext.OwnedTrapSite(eventThread, tid, first, enabled[0], U64(before, 248), addresses[0]) &&
                    unchecked((ulong)exceptionAddress.ToInt64()) == U64(before, 248) &&
                    DebugContext.OwnedTrapStatus(status, U64(before, 112), Control(), 0), "hardware-trap", before);
                string result = CallbackResult(before);
                addresses[0] = 0; enabled[0] = false;
                Apply(before, true); stage = 3;
                emit("phase=module-callback-result " + result + " " + DebugContext.TrapQualifiers(status) +
                    " process_level=True invocation_module_verified=False runtime_callee_verified=False restored=True control_integer_unchanged=True cause_claimed=False");
                return true;
            }
            finally { Array.Clear(before, 0, before.Length); }
        }
        public static void CheckModuleCallbackValidation()
        {
            ulong[] values = { 0, 1, 0xFFFFFFFFUL, 0x12345678FFFFFFFFUL, UInt64.MaxValue };
            string[] results = { "False", "False", "False", "False", "True" };
            byte[] context = new byte[DebugContext.Size];
            for (int index = 0; index < values.Length; index++) {
                Put(context, 120, values[index]); Put(context, 144, UInt64.MaxValue);
                Need(CallbackResult(context) == "failure_sentinel=" + results[index]);
            }
            byte[] baseline = new byte[DebugContext.Size]; Put(baseline, 112, 0x400);
            byte[] current = (byte[])baseline.Clone(); Put(current, 120, UInt64.MaxValue);
            Put(current, 128, 0x12345678); Put(current, 152, 0x5000); Put(current, 248, 0x8000);
            byte[] armed = Desired(current, baseline, new ulong[] { 0x8000, 0 }, new [] { true, false }, false);
            byte[] restored = Desired(armed, baseline, new ulong[2], new bool[2], true);
            Need(U64(armed, 72) == 0x8000 && U64(armed, 80) == 0 && U64(armed, 112) == 0x401 &&
                DebugContext.RawDebugEqual(restored, baseline) && DebugContext.UnchangedControlInteger(current, restored) &&
                U64(restored, 120) == UInt64.MaxValue && U64(restored, 248) == 0x8000 && !DebugContext.UnchangedControlInteger(baseline, restored));
            foreach (int state in new [] { 1, 2, 3 }) {
                var observer = new ActivationBoundaryTrace(new IntPtr(1), new IntPtr(2), 7, 11, "fixed", "digest", _ => { }, true);
                observer.stage = state; observer.original = baseline; observer.restored = state == 3;
                Need(CallbackComplete(state, observer.restored, false) == (state == 3));
                Need(!CallbackComplete(state, false, false) && !CallbackComplete(state, true, true));
                Need(observer.CallbackSoftwareStage(11, 0x80000003, true));
                Need(!observer.CallbackSoftwareStage(12, 0x80000003, true) &&
                    !observer.CallbackSoftwareStage(11, 0x80000003, false) && !observer.CallbackSoftwareStage(11, 0x80000004, true));
                observer.initial = true; Need(!observer.CallbackSoftwareStage(11, 0x80000003, true)); observer.initial = false;
                observer.kernel = KernelImage.FromActivationWorker(KernelImage.StaticFixture());
                Need(observer.CallbackHardwareStage(11, true) == (state == 2));
                Need(!observer.CallbackHardwareStage(12, true) && !observer.CallbackHardwareStage(11, false));
                observer.invalidated = true;
                Need(!observer.CallbackHardwareStage(11, true) && !observer.CallbackSoftwareStage(11, 0x80000003, true));
                observer.invalidated = false; observer.kernel = null;
                observer.stopped = true; Need(observer.CallbackLoadStage() == (state == 1));
                observer.changed = true; Need(!observer.CallbackLoadStage()); observer.changed = false;
                observer.stopped = false; Need(!observer.CallbackLoadStage());
                observer.stopped = true; observer.alive = false; Need(!observer.CallbackLoadStage()); observer.alive = true;
                if (state == 2) { observer.addresses[0] = 0x8000; observer.enabled[0] = true; }
                byte[] software = Desired(current, baseline, observer.addresses, observer.enabled, state == 3);
                Put(software, 104, 0xFFFF0FF0); observer.Ownership(software, false);
                foreach (int offset in new [] { 72, 80, 88, 96 }) {
                    byte[] foreign = (byte[])software.Clone(); Put(foreign, offset, 0x9999); bool refused = false;
                    try { observer.Ownership(foreign, false); } catch (InvalidOperationException) { refused = true; } Need(refused);
                }
                if (state == 3) observer.RequireComplete();
                else { bool refused = false; try { observer.RequireComplete(); } catch (InvalidOperationException) { refused = true; } Need(refused); }
                bool foreignRefused = false;
                try { observer.Stop(7, 12, 6); } catch (InvalidOperationException) { foreignRefused = true; }
                Need(foreignRefused && observer.invalidated);
            }
            foreach (int state in new [] { 0, 4 }) {
                var observer = new ActivationBoundaryTrace(new IntPtr(1), new IntPtr(2), 7, 11, "fixed", "digest", _ => { }, true);
                observer.stage = state; observer.original = baseline; observer.stopped = true;
                Need(!observer.CallbackSoftwareStage(11, 0x80000003, true) && !observer.CallbackHardwareStage(11, true) &&
                    !observer.CallbackLoadStage() && !CallbackComplete(state, true, false));
            }
            KernelImage.CheckModuleCallbackProfileValidation();
            CheckCallbackDrainValidation();
            CheckCallbackHeaderValidation();
        }
        string CallbackStopHeader(uint eventPid, uint eventThread, uint kind, bool cleanup)
        {
            return "phase=module-callback-stop-refusal kind=" + kind.ToString(System.Globalization.CultureInfo.InvariantCulture) +
                " process_match=" + (eventPid == pid) + " creator=" + (eventThread == tid) + " cleanup=" + cleanup +
                " stage=" + stage.ToString(System.Globalization.CultureInfo.InvariantCulture) + " context_read=False";
        }
        static void CheckCallbackHeaderValidation()
        {
            string reported = null;
            var observer = new ActivationBoundaryTrace(new IntPtr(1), new IntPtr(2), 7, 11, "private-path", "private-digest", line => reported = line, true);
            observer.stage = 2; observer.stopped = observer.changed = true;
            bool refused = false;
            try { observer.Stop(7, 12, 2); } catch (InvalidOperationException) { refused = true; }
            Need(refused && observer.invalidated && !observer.RestorationAllowed && reported ==
                "phase=module-callback-stop-refusal kind=2 process_match=True creator=False cleanup=False stage=2 context_read=False");
            reported = null; observer.Stop(7, 12, 4, true); Need(reported == null && !observer.RestorationAllowed);
            observer.Stop(7, 11, 6, true); Need(reported == null && observer.RestorationAllowed);
            refused = false;
            try { observer.Stop(8, 11, 5, true); } catch (InvalidOperationException) { refused = true; }
            Need(refused && !observer.RestorationAllowed && reported ==
                "phase=module-callback-stop-refusal kind=5 process_match=False creator=True cleanup=True stage=2 context_read=False");
            var reporting = new InvalidOperationException("private-reporting");
            observer = new ActivationBoundaryTrace(new IntPtr(1), new IntPtr(2), 7, 11, "private-path", "private-digest", _ => { throw reporting; }, true);
            AggregateException group = null;
            try { observer.Stop(7, 12, UInt32.MaxValue); } catch (AggregateException failure) { group = failure; }
            Need(group != null && group.InnerExceptions.Count == 2 && group.InnerExceptions[0].Message ==
                "fixed activation observation refused check=callback-thread" && Object.ReferenceEquals(group.InnerExceptions[1], reporting));
            Need(observer.invalidated && !observer.RestorationAllowed && observer.CallbackStopHeader(7, 12, UInt32.MaxValue, false) ==
                "phase=module-callback-stop-refusal kind=4294967295 process_match=True creator=False cleanup=False stage=0 context_read=False");
        }
        static void CheckCallbackDrainValidation()
        {
            foreach (int mode in new [] { 0, 1, 2, 3, 4, 5, 6 }) {
                var observer = new ActivationBoundaryTrace(new IntPtr(1), new IntPtr(2), 7, 11, "fixed", "digest", _ => { }, true);
                observer.changed = true; observer.stopped = true; observer.stage = 2;
                Exception primary = null; uint eventProcess = mode == 6 ? 8U : 7U;
                try { observer.Stop(eventProcess, 12, 2); } catch (InvalidOperationException failure) { primary = failure; }
                Need(primary != null && observer.invalidated && !observer.RestorationAllowed);
                bool pending = true, exited = false; int received = 0, continued = 0, releases = 0, contextAccesses = 0;
                uint kind = 2;
                var failures = new System.Collections.Generic.List<Exception>();
                var close = new InvalidOperationException("fixed close failure");
                var continuation = new InvalidOperationException("fixed continuation failure");
                Action finish = () => {
                    LoaderTrace.RequireCallbackEventProcess(eventProcess, 7);
                    try {
                        LoaderTrace.ActivationEvent(() => { if (kind == 5) exited = true; },
                            () => { if (observer.RestorationAllowed) contextAccesses++; observer.Restore(); },
                            new Action[] { () => { releases++; if (mode == 1 && releases == 1) throw close; } },
                            () => { continued++; if (mode == 2) throw continuation; pending = false; observer.Continued(); });
                    } catch (Exception failure) { failures.Add(failure); }
                };
                try {
                    LoaderTrace.DrainCallbackEvents(() => exited, () => pending,
                        () => mode == 3 ? 0U : 5000U,
                        milliseconds => {
                            Need(milliseconds <= 100);
                            if (pending) throw new InvalidOperationException("fixed pending continuation");
                            received++; kind = mode == 4 ? 6U : (received == 3 ? 5U : 4U);
                            uint eventThread = kind == 5 ? 11U : 12U + (uint)received;
                            pending = true;
                            eventProcess = mode == 5 ? 8U : 7U;
                            observer.Stop(eventProcess, eventThread, kind, true);
                            Need(observer.invalidated && !observer.RestorationAllowed);
                            return true;
                        }, finish);
                } catch (Exception failure) { failures.Add(failure); }
                Need(observer.invalidated && contextAccesses == 0);
                if (mode == 0 || mode == 1) Need(exited && !pending && received == 3 && continued == 4 && releases == 4);
                if (mode == 0) {
                    Need(failures.Count == 0);
                    LoaderTrace.ConfirmActivationDestruction(exited, pending, true, 0, _ => 0, () => { });
                    var qualified = Sandbox.CompletionFailure(primary, failures, true, true) as QualifiedModuleCallbackFailure;
                    Need(qualified != null && Object.ReferenceEquals(qualified.Original, primary));
                } else {
                    Need(failures.Count != 0);
                    var group = Sandbox.CompletionFailure(primary, failures, true, false) as AggregateException;
                    Need(group != null && Object.ReferenceEquals(group.InnerExceptions[0], primary));
                    if (mode == 1) Need(Object.ReferenceEquals(group.InnerExceptions[1], close));
                    if (mode == 2) Need(pending && received == 0 && continued == 1 && !exited);
                    if (mode == 3) Need(received == 0 && !exited);
                    if (mode == 4) Need(received == 128 && !exited);
                    if (mode == 5) Need(received == 1 && continued == 1 && pending && !observer.RestorationAllowed);
                    if (mode == 6) Need(received == 0 && continued == 0 && releases == 0 && pending && !exited);
                }
                foreach (uint wait in new uint[] { 258, UInt32.MaxValue }) {
                    bool refused = false;
                    try { LoaderTrace.ConfirmActivationDestruction(true, false, true, 0, _ => wait, () => { }); }
                    catch (InvalidOperationException) { refused = true; }
                    Need(refused);
                }
                Need(!CallbackComplete(observer.stage, observer.restored, observer.invalidated));
            }
        }
    }
}
