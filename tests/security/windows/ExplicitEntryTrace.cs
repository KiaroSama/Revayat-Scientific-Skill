using System;

namespace ScientificSecurity
{
    // Entry reach is creator-scoped evidence in this traced process, never undebugged equivalence.
    public sealed partial class ActivationBoundaryTrace
    {
        readonly bool entryOnly;
        bool entryHit, entryNaturalExit, entryDestroyed;
        string entryTrap = "";
        void EntryStop(uint eventPid, uint eventThread, uint kind, bool cleanup)
        {
            stopped = false;
            if (cleanup || eventPid != pid) Invalidate();
            Need(eventPid == pid);
            if (kind == 5 || kind == 4 && eventThread == tid) alive = false;
            if (!cleanup && kind == 1 && eventThread != tid) {
                Invalidate(); throw new InvalidOperationException("fixed entry exception is not creator-scoped");
            }
            stopped = alive && eventThread == tid;
        }
        void EntryCreation(IntPtr file, IntPtr imageBase)
        {
            Need(stage == 0 && stopped && alive && !invalidated);
            fixture = KernelImage.FromExplicitEntryCreation(file, imageBase, path, digest);
            RequireExecutable(fixture, fixture.Entry, 1);
            original = Read(); Need(Free(original));
            addresses[0] = fixture.Address(fixture.Entry); enabled[0] = true; stage = 1;
            Apply(original, false);
        }
        bool EntrySoftwareStage(uint eventThread, uint code, bool first)
        {
            return !invalidated && (stage == 1 || stage == 2) &&
                LoaderTrace.AcceptInitialBreakpoint(eventThread, tid, code, first, initial, null);
        }
        bool EntrySoftware(uint eventThread, uint code, bool first)
        {
            if (code != 0x80000003) return false;
            Need(EntrySoftwareStage(eventThread, code, first));
            byte[] before = Read();
            try { AcceptSoftwareContext(before); }
            finally { Array.Clear(before, 0, before.Length); }
            return true;
        }
        bool EntrySingleStep(uint eventThread, uint code, bool first, IntPtr exceptionAddress)
        {
            if (code != 0x80000004) return false;
            Need(!invalidated && stage == 1 && !entryHit && original != null && stopped && alive);
            byte[] before = Read();
            try {
                EntryHardwareContext(eventThread, first, exceptionAddress, before, () => Apply(before, true));
                return true;
            }
            finally { Array.Clear(before, 0, before.Length); }
        }
        void EntryHardwareContext(uint eventThread, bool first, IntPtr exceptionAddress, byte[] context, Action restore)
        {
            Ownership(context, true);
            ulong status = U64(context, 104);
            Need(EntryTrapAccepted(eventThread, tid, first, enabled[0], U64(context, 248), addresses[0],
                unchecked((ulong)exceptionAddress.ToInt64()), status, U64(context, 112), Control()));
            EntryHit(status, restore);
        }
        static bool EntryTrapAccepted(uint actual, uint creator, bool first, bool active, ulong rip, ulong configured,
            ulong exception, ulong status, ulong control, ulong expected)
        {
            return DebugContext.OwnedTrapSite(actual, creator, first, active, rip, configured) && exception == configured &&
                DebugContext.OwnedTrapStatus(status, control, expected, 0);
        }
        void EntryHit(ulong status, Action restore)
        {
            Need(!entryHit && stage == 1);
            entryHit = true; entryTrap = " " + DebugContext.TrapQualifiers(status);
            restore(); addresses[0] = 0; enabled[0] = false; stage = 2;
        }
        internal void EntryExit()
        {
            Need(entryOnly && !alive && !invalidated && stage >= 1);
            entryNaturalExit = true;
        }
        internal string EntryMetadata()
        {
            Need(entryOnly && entryDestroyed);
            string value = "WINDOWS_EXPLICIT_ENTRY traced=True creator_scope=True entry_observed=" + entryHit +
                " restored=" + restored + " natural_exit=" + entryNaturalExit + " state_destroyed=True observation_qualified=" + EntryComplete() +
                entryTrap + softwareTrap + " cause_claimed=False undebugged_equivalence_claimed=False";
            ResourceCheck(value.Length <= 1024, "entry-metadata-budget"); return value;
        }
        bool EntryComplete() { return entryHit && restored && entryNaturalExit && !invalidated; }
        internal static void CheckEntryLifetimeValidation(KernelImage image)
        {
            Func<ActivationBoundaryTrace> create = () => {
                var observer = new ActivationBoundaryTrace(new IntPtr(1), new IntPtr(2), 7, 11, "private-path", "private-digest", _ => { }, false, true);
                observer.stage = 1; observer.fixture = image; observer.original = new byte[DebugContext.Size];
                observer.addresses[0] = image.Address(image.Entry); observer.enabled[0] = true; observer.changed = true;
                return observer;
            };
            foreach (uint kind in new uint[] { 2, 4, 6, 7, 8 }) {
                var observer = create(); int exceptions = 0, exits = 0, closes = 0, continuations = 0;
                observer.Stop(7, 12, kind);
                LoaderTrace.FinalizeEntryEvent(observer, kind, new IntPtr(0x20000000), false, () => exceptions++, () => exits++,
                    new Action[] { () => { Need(!observer.RestorationAllowed && !observer.stopped); closes++; } },
                    status => { Need(status == 0x10002 && !observer.stopped); continuations++; observer.Continued(); });
                Need(!observer.invalidated && exceptions == 0 && exits == 0 && closes == 1 && continuations == 1 && !observer.restored);
            }
            foreach (uint kind in new uint[] { 1, 3, 9, UInt32.MaxValue }) {
                var observer = create(); int exceptions = 0, releases = 0, continuations = 0;
                bool refused = false;
                try {
                    observer.Stop(7, 12, kind);
                    LoaderTrace.FinalizeEntryEvent(observer, kind, IntPtr.Zero, false, () => exceptions++, () => { },
                        new Action[] { () => releases++ }, _ => continuations++);
                } catch (InvalidOperationException) { refused = true; }
                Need(refused && observer.invalidated && !observer.RestorationAllowed && !observer.restored && exceptions == 0 &&
                    releases == (kind == 1 ? 0 : 1) && continuations == releases);
            }
            foreach (bool own in new [] { false, true }) {
                var observer = create(); observer.Stop(7, 12, 7); int continued = 0; bool refused = false;
                try { LoaderTrace.FinalizeEntryEvent(observer, 7, new IntPtr((long)(own ? image.Base : image.Base + 0x10000)), false,
                    () => { throw new Exception("unload dispatched as exception"); }, () => { }, new Action[0], _ => continued++); }
                catch (InvalidOperationException) { refused = true; }
                Need(refused == own && observer.invalidated == own && continued == 1 && !observer.RestorationAllowed);
            }
            foreach (bool hit in new [] { false, true }) foreach (bool forced in new [] { false, true }) {
                var observer = create();
                if (hit) observer.EntryHit(0xFFFE0FF1, () => { observer.restored = true; observer.changed = false; });
                observer.Stop(7, 11, 5, forced); int exits = 0, continued = 0;
                LoaderTrace.FinalizeEntryEvent(observer, 5, IntPtr.Zero, forced, () => { throw new Exception("EXIT dispatched as exception"); },
                    () => exits++, new Action[0], status => { Need(status == 0x10002); continued++; observer.Continued(); });
                Need(!observer.alive && !observer.RestorationAllowed && exits == 1 && continued == 1);
                observer.Destroyed(); bool complete = true;
                try { observer.RequireComplete(); } catch (InvalidOperationException) { complete = false; }
                Need(complete == (hit && !forced));
                string metadata = observer.EntryMetadata();
                Need(!metadata.Contains("private-") && metadata.Contains("creator_scope=True") &&
                    metadata.Contains("entry_observed=" + hit) && metadata.Contains("restored=" + hit) &&
                    metadata.Contains("natural_exit=" + !forced) && metadata.Contains("state_destroyed=True") &&
                    metadata.Contains("observation_qualified=" + complete) &&
                    metadata.EndsWith("cause_claimed=False undebugged_equivalence_claimed=False", StringComparison.Ordinal));
                observer.Stop(7, 11, 6, true); Need(!observer.alive && !observer.RestorationAllowed);
            }
            InvalidOperationException closeFailure = new InvalidOperationException("fixed entry event close"), continuationFailure = new InvalidOperationException("fixed entry event continue");
            var failed = create(); failed.Stop(7, 12, 6); int attempts = 0; AggregateException group = null;
            try { LoaderTrace.FinalizeEntryEvent(failed, 6, IntPtr.Zero, false, () => { }, () => { },
                new Action[] { () => { attempts++; throw closeFailure; }, () => attempts++ }, _ => { attempts++; throw continuationFailure; }); }
            catch (AggregateException failure) { group = failure; }
            Need(failed.invalidated && !failed.RestorationAllowed && attempts == 3 && group != null && group.InnerExceptions.Count == 2 &&
                Object.ReferenceEquals(group.InnerExceptions[0], closeFailure) && Object.ReferenceEquals(group.InnerExceptions[1], continuationFailure));
        }
        static void CheckSoftwarePresentation()
        {
            foreach (int role in new [] { 0, 1, 2 }) foreach (int state in new [] { 1, 2, 3 })
                foreach (ulong status in new ulong[] { 0xFFFE07F0, 0xFFFE0FF0, 0xFFFF07F0, 0xFFFF0FF0 })
                foreach (ulong fixedBit in new ulong[] { 0, 0x400 }) {
                if (role == 0 && state != 1 || role == 2 && state == 3) continue;
                var observer = new ActivationBoundaryTrace(new IntPtr(1), new IntPtr(2), 7, 11, "private-path", "private-digest", _ => { },
                    callback: role == 1, entry: role == 2);
                observer.stage = state; observer.original = new byte[DebugContext.Size]; observer.stopped = true;
                bool armed = role == 0 || role == 1 && state == 2 || role == 2 && state == 1;
                observer.addresses[0] = armed ? 0x8000UL : 0UL; observer.enabled[0] = armed;
                byte[] context = Desired(observer.original, observer.original, observer.addresses, observer.enabled, false);
                Put(context, 104, status); Put(context, 112, observer.Control() ^ fixedBit);
                Func<uint, uint, bool, bool> allowed = (id, code, first) => role == 1 ? observer.CallbackSoftwareStage(id, code, first) :
                    role == 2 ? observer.EntrySoftwareStage(id, code, first) : code == 0x80000003 && Software(state, observer.initial, id, 11, first);
                Need(allowed(11, 0x80000003, true) && !allowed(12, 0x80000003, true) &&
                    !allowed(11, 0x80000004, true) && !allowed(11, 0x80000003, false));
                if (role == 1) {
                    bool refused = false;
                    try { observer.CallbackLoadOwnership(context); } catch (InvalidOperationException) { refused = true; }
                    Need(refused); observer.CallbackLoadOwnership(observer.original);
                }
                foreach (int offset in new [] { 72, 80, 88, 96, 104, 112 }) {
                    byte[] foreign = (byte[])context.Clone(); Put(foreign, offset, U64(foreign, offset) ^ (offset == 104 ? 0x1000UL : offset == 112 ? 0x800UL : 1UL));
                    bool refused = false;
                    try { observer.AcceptSoftwareContext(foreign); } catch (InvalidOperationException) { refused = true; }
                    Need(refused && !observer.initial && observer.softwareTrap == null);
                }
                observer.AcceptSoftwareContext(context); string firstSnapshot = observer.softwareTrap;
                Need(observer.initial && observer.stage == state && !observer.entryHit && !observer.restored &&
                    firstSnapshot.Contains("software_raw_dr6=0x" + status.ToString("X16")) && firstSnapshot.Contains("software_origin_verified=False"));
                Need(!allowed(11, 0x80000003, true));
                Put(context, 104, status ^ 0x10800UL);
                bool repeated = false;
                try { observer.AcceptSoftwareContext(context); } catch (InvalidOperationException) { repeated = true; }
                Need(repeated && observer.softwareTrap == firstSnapshot);
                if (role == 1) observer.CallbackLoadOwnership(context);
                else {
                    bool incomplete = false; try { observer.RequireComplete(); } catch (InvalidOperationException) { incomplete = true; }
                    Need(incomplete);
                }
                if (role == 2) {
                    observer.entryDestroyed = true;
                    string metadata = observer.EntryMetadata();
                    Need(metadata.Length <= 1024 && metadata.Contains(firstSnapshot) && metadata.Contains("entry_observed=False") &&
                        !metadata.Contains("private-") && !metadata.Contains("0000000000008000"));
                    SelfActivationFixture.CheckRejectedEntry(observer.RequireComplete);
                    if (state == 1) {
                        observer.EntryHit(0xFFFE0FF1, () => observer.restored = true); observer.entryNaturalExit = true;
                        metadata = observer.EntryMetadata();
                        Need(metadata.Length <= 1024 && metadata.Contains(firstSnapshot) && metadata.Contains("raw_dr6=0x00000000FFFE0FF1") &&
                            metadata.Contains("entry_observed=True") && metadata.Contains("observation_qualified=True"));
                    }
                }
            }
            CheckSoftwareThenHardwareFailure();
        }
        static void CheckSoftwareThenHardwareFailure()
        {
            for (int mode = 0; mode < 6; mode++) {
                var observer = new ActivationBoundaryTrace(new IntPtr(1), new IntPtr(2), 7, 11, "fixed", "digest", _ => { }, entry: true);
                observer.stage = 1; observer.original = new byte[DebugContext.Size]; observer.stopped = true;
                observer.addresses[0] = 0x8000; observer.enabled[0] = true;
                byte[] context = Desired(observer.original, observer.original, observer.addresses, observer.enabled, false);
                Put(context, 104, 0xFFFE07F0); Put(context, 112, 0x401);
                Need(observer.EntrySoftwareStage(11, 0x80000003, true)); observer.AcceptSoftwareContext(context);
                Put(context, 104, mode == 0 ? 0xFFFE07F1UL : mode == 1 ? 0xFFFE0FF3UL : 0xFFFE0FF1UL);
                Put(context, 248, mode == 2 ? 0x8001UL : 0x8000UL);
                int restores = 0, continuations = 0; Exception caught = null;
                try {
                    LoaderTrace.FinalizeEntryEvent(observer, 1, IntPtr.Zero, false, () => {
                        if (mode == 5 && !observer.SingleStep(11, 0xC0000005, true, new IntPtr(0x8000)) &&
                            !observer.AcceptSoftware(11, 0xC0000005, true))
                            throw new InvalidOperationException("fixed entry observation encountered an unexpected exception");
                        observer.EntryHardwareContext(mode == 3 ? 12U : 11U, mode != 4, new IntPtr(0x8000), context, () => restores++);
                    }, () => { }, new Action[0], status => { Need(status == 0x80010001); continuations++; });
                } catch (InvalidOperationException failure) { caught = failure; }
                Need(caught != null && continuations == 1 && restores == 0 && observer.invalidated && !observer.entryHit && !observer.EntryComplete());
                Put(context, 104, 0xFFFE0FF1); Put(context, 248, 0x8000);
                Need(!observer.EntrySoftwareStage(11, 0x80000003, true));
                bool laterRejected = false;
                try { observer.SingleStep(11, 0x80000004, true, new IntPtr(0x8000)); } catch (InvalidOperationException) { laterRejected = true; }
                Need(laterRejected && !observer.entryHit);
                bool incomplete = false; try { observer.RequireComplete(); } catch (InvalidOperationException) { incomplete = true; }
                Need(incomplete);
                SelfActivationFixture.CheckRejectedEntry(() => { observer.RequireComplete(); });
            }
        }
        public static void CheckExplicitEntryValidation()
        {
            byte[] baseline = new byte[DebugContext.Size]; Put(baseline, 112, 0x400);
            byte[] current = (byte[])baseline.Clone(); Put(current, 120, UInt64.MaxValue); Put(current, 248, 0x8000);
            byte[] armed = Desired(current, baseline, new ulong[] { 0x8000, 0 }, new [] { true, false }, false);
            byte[] reset = Desired(armed, baseline, new ulong[2], new bool[2], true);
            Need(U64(armed, 72) == 0x8000 && U64(armed, 80) == 0 && U64(armed, 112) == 0x401 &&
                DebugContext.RawDebugEqual(reset, baseline) && DebugContext.UnchangedControlInteger(current, reset));
            foreach (uint kind in new uint[] { 2, 4, 6, 7, 8 }) {
                var observer = new ActivationBoundaryTrace(new IntPtr(1), new IntPtr(2), 7, 11, "fixed", "digest", _ => { }, false, true);
                observer.stage = 1; observer.changed = true; observer.original = baseline;
                observer.EntryStop(7, 12, kind, false);
                Need(!observer.stopped && !observer.RestorationAllowed && !observer.invalidated && observer.alive);
                observer.EntryStop(7, 11, 4, false); Need(!observer.alive && !observer.stopped);
                observer.EntryStop(7, 11, 6, false); Need(!observer.alive && !observer.stopped);
            }
            foreach (bool cleanup in new [] { false, true }) {
                var observer = new ActivationBoundaryTrace(new IntPtr(1), new IntPtr(2), 7, 11, "fixed", "digest", _ => { }, false, true);
                observer.stopped = true; observer.changed = true; observer.original = baseline;
                bool refused = false;
                try { observer.EntryStop(7, 12, 1, cleanup); } catch (InvalidOperationException) { refused = true; }
                Need(refused != cleanup && observer.invalidated && !observer.RestorationAllowed);
            }
            foreach (ulong status in new ulong[] { 0xFFFE0FF1, 0xFFFF0FF1 }) {
                Need(EntryTrapAccepted(11, 11, true, true, 0x8000, 0x8000, 0x8000, status, 0x401, 1));
                Need(!EntryTrapAccepted(12, 11, true, true, 0x8000, 0x8000, 0x8000, status, 0x401, 1) &&
                    !EntryTrapAccepted(11, 11, false, true, 0x8000, 0x8000, 0x8000, status, 0x401, 1) &&
                    !EntryTrapAccepted(11, 11, true, false, 0x8000, 0x8000, 0x8000, status, 0x401, 1) &&
                    !EntryTrapAccepted(11, 11, true, true, 0x8001, 0x8000, 0x8000, status, 0x401, 1) &&
                    !EntryTrapAccepted(11, 11, true, true, 0x8000, 0x8000, 0x8001, status, 0x401, 1));
                foreach (ulong foreign in new ulong[] { 2, 4, 8, 0x1000, 0x2000, 0x4000, 0x8000, 0x100000000 })
                    Need(!EntryTrapAccepted(11, 11, true, true, 0x8000, 0x8000, 0x8000, status | foreign, 0x401, 1));
            }
            foreach (bool fail in new [] { false, true }) {
                var observer = new ActivationBoundaryTrace(new IntPtr(1), new IntPtr(2), 7, 11, "fixed", "digest", _ => { }, false, true);
                observer.stage = 1; observer.enabled[0] = true; observer.addresses[0] = 0x8000;
                var restoration = new InvalidOperationException("fixed entry restoration"); Exception caught = null;
                try { observer.EntryHit(0xFFFE0FF1, () => { if (fail) throw restoration; observer.restored = true; }); }
                catch (Exception failure) { caught = failure; }
                Need(observer.entryHit && observer.stage == (fail ? 1 : 2) && observer.restored != fail &&
                    (fail ? Object.ReferenceEquals(caught, restoration) : caught == null));
                bool repeated = false;
                try { observer.EntryHit(0xFFFE0FF1, () => { }); } catch (InvalidOperationException) { repeated = true; }
                Need(repeated);
            }
            bool overlap = false;
            try { new ActivationBoundaryTrace(new IntPtr(1), new IntPtr(2), 7, 11, "fixed", "digest", _ => { }, true, true); }
            catch (ArgumentException) { overlap = true; }
            Need(overlap);
        }
    }
}
