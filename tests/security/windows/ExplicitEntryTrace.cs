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
        bool EntrySoftware(uint eventThread, uint code, bool first)
        {
            if (code != 0x80000003) return false;
            Need(!invalidated && (stage == 1 || stage == 2) &&
                LoaderTrace.AcceptInitialBreakpoint(eventThread, tid, code, first, initial, null));
            byte[] before = Read();
            try { Ownership(before, false); initial = true; }
            finally { Array.Clear(before, 0, before.Length); }
            return true;
        }
        bool EntrySingleStep(uint eventThread, uint code, bool first, IntPtr exceptionAddress)
        {
            if (code != 0x80000004) return false;
            Need(!invalidated && stage == 1 && !entryHit && original != null && stopped && alive);
            byte[] before = Read();
            try {
                Ownership(before, true);
                ulong status = U64(before, 104);
                Need(EntryTrapAccepted(eventThread, tid, first, enabled[0], U64(before, 248), addresses[0],
                    unchecked((ulong)exceptionAddress.ToInt64()), status, U64(before, 112), Control()));
                EntryHit(status, () => Apply(before, true));
                return true;
            }
            finally { Array.Clear(before, 0, before.Length); }
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
            return "WINDOWS_EXPLICIT_ENTRY traced=True creator_scope=True entry_observed=" + entryHit +
                " restored=" + restored + " natural_exit=" + entryNaturalExit + " state_destroyed=True observation_qualified=" + EntryComplete() +
                entryTrap + " cause_claimed=False undebugged_equivalence_claimed=False";
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
