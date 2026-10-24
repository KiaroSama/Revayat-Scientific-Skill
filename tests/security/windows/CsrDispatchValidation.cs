using System;
using System.Collections.Generic;
using System.Linq;

namespace ScientificSecurity
{
    public sealed partial class ActivationBoundaryTrace
    {
        // Exercise the production registry and read seam without invoking native methods.
        public static void CheckCsrDispatchValidation()
        {
            CheckDispatchReads();
            foreach (bool creator in new [] { false, true }) {
                var contexts = new Dictionary<IntPtr, byte[]>(); int writes = 0, targets = 0, closes = 0;
                Action<uint> prepare = id => contexts[new IntPtr(id)] = new byte[DebugContext.Size];
                prepare(11); prepare(12); prepare(13);
                var registry = new ResourceThreads(7, 11, handle => (byte[])contexts[handle].Clone(),
                    (handle, bytes) => { writes++; contexts[handle] = (byte[])bytes.Clone(); }, _ => closes++, () => { });
                registry.Stop(7, 11, 3, false); registry.Enroll(11, new IntPtr(11), false); registry.Continued();
                registry.Stop(7, 12, 2, false); registry.Enroll(12, new IntPtr(12), true); registry.Continued();
                registry.Stop(7, 11, 6, false); registry.ArmDispatch(0x8000, 0x8007, () => targets++); registry.Continued();
                Need(writes == 2 && new [] { 11, 12 }.All(id => U64(contexts[new IntPtr(id)], 72) == 0x8000 &&
                    U64(contexts[new IntPtr(id)], 80) == 0x8007 && U64(contexts[new IntPtr(id)], 112) == 5));
                uint selected = creator ? 11U : 12U, other = creator ? 12U : 11U;
                byte[] trap = contexts[new IntPtr(selected)]; DispatchFixtureTrap(trap, false);
                registry.Stop(7, selected, 1, false); registry.CaptureDispatch(selected, true, new IntPtr(0x8000));
                Need(targets == 1 && writes == 4 && !registry.Captured);
                Need(U64(contexts[new IntPtr(selected)], 72) == 0 && U64(contexts[new IntPtr(selected)], 80) == 0x8007 &&
                    U64(contexts[new IntPtr(selected)], 112) == 4 && U64(contexts[new IntPtr(other)], 72) == 0 &&
                    U64(contexts[new IntPtr(other)], 80) == 0 && U64(contexts[new IntPtr(other)], 112) == 0);
                registry.Continued();
                registry.Stop(7, 13, 2, false); registry.Enroll(13, new IntPtr(13), true); registry.Continued();
                Need(writes == 4 && U64(contexts[new IntPtr(13)], 72) == 0 && U64(contexts[new IntPtr(13)], 80) == 0);
                trap = contexts[new IntPtr(selected)]; DispatchFixtureTrap(trap, true);
                Put(trap, 184, UInt64.MaxValue); Put(trap, 192, UInt64.MaxValue);
                registry.Stop(7, selected, 1, false); registry.CaptureDispatch(selected, true, new IntPtr(0x8007)); registry.Continued();
                Need(registry.Captured && registry.BaseEqual && registry.CaptureRestored && !registry.Failed &&
                    registry.RawEax == 0xC0150002 && registry.CreatorCapture == creator && writes == 6);
                Need(contexts.Values.All(c => U64(c, 72) == 0 && U64(c, 80) == 0 && U64(c, 112) == 0));
                Need(registry.DispatchTraps.Contains("call_transaction_context=unknown") && registry.DispatchTraps.Contains("return_raw_dr6="));
                registry.Stop(7, 11, 1, false); Need(registry.DispatchSoftware(11, true)); registry.Continued();
                registry.Stop(7, 12, 4, false); registry.Continued();
                prepare(14); registry.Stop(7, 12, 2, false);
                DispatchRefuse(() => registry.Enroll(12, new IntPtr(14), true)); registry.Continued();
                registry.Stop(7, 11, 5, false); registry.Continued(); registry.Destroyed();
                Need(closes == 2 && registry.DestroyedState && !registry.Failed);
            }
            CheckDispatchFailures(); CheckDispatchRestoreDrift(); CheckDispatchMetadata(); CheckDispatchGenerations();
            CheckDispatchRefusalReporting();
        }
        static void DispatchFixtureTrap(byte[] context, bool post)
        {
            Put(context, 104, post ? 0xFFFE0FF2UL : 0xFFFF0FF1UL);
            Put(context, 112, post ? 0x404UL : 0x405UL); Put(context, 248, post ? 0x8007UL : 0x8000UL);
            Put(context, 152, 0x9000); Put(context, 184, 0x1001001E); Put(context, 192, 0x1F8);
            Put(context, 120, 0x12345678C0150002);
        }
        static void DispatchRefuse(Action action)
        {
            bool refused = false; try { action(); } catch (InvalidOperationException) { refused = true; } Need(refused);
        }
        static void CheckDispatchFailures()
        {
            // A wrong first delivery cannot be rescued by a corrected later stop.
            for (int mode = 0; mode < 12; mode++) {
                var contexts = new Dictionary<IntPtr, byte[]> { { new IntPtr(11), new byte[DebugContext.Size] }, { new IntPtr(12), new byte[DebugContext.Size] } };
                int calls = 0, restores = 0; bool restoring = false;
                var registry = new ResourceThreads(7, 11, handle => (byte[])contexts[handle].Clone(),
                    (handle, bytes) => { if (restoring) restores++; contexts[handle] = (byte[])bytes.Clone(); }, _ => { }, () => { });
                registry.Stop(7, 11, 3, false); registry.Enroll(11, new IntPtr(11), false); registry.Continued();
                registry.Stop(7, 12, 2, false); registry.Enroll(12, new IntPtr(12), true); registry.Continued();
                registry.Stop(7, 11, 6, false); registry.ArmDispatch(0x8000, 0x8007, () => { calls++; if (mode == 11) throw new InvalidOperationException("fixed target mismatch"); }); registry.Continued();
                byte[] trap = contexts[new IntPtr(11)]; DispatchFixtureTrap(trap, false);
                if (mode == 0) Put(trap, 184, 0);
                if (mode == 1) Put(trap, 104, 0xFFFF0FF3);
                if (mode == 2) Put(trap, 112, 0xC05);
                if (mode == 3) Put(contexts[new IntPtr(12)], 72, 0x9999);
                if (mode == 4) { Put(trap, 104, 0xFFFF0FF2); Put(trap, 248, 0x8007); }
                registry.Stop(7, 11, 1, false);
                if (mode <= 4 || mode == 10 || mode == 11) {
                    DispatchRefuse(() => registry.CaptureDispatch(11, mode != 10, new IntPtr(mode == 4 ? 0x8007 : 0x8000)));
                } else {
                    registry.CaptureDispatch(11, true, new IntPtr(0x8000)); registry.Continued();
                    trap = contexts[new IntPtr(11)]; DispatchFixtureTrap(trap, true);
                    if (mode == 5) Put(trap, 152, 0x8F00);
                    if (mode == 6) Put(trap, 248, 0x8008);
                    if (mode == 7) Put(trap, 104, 0xFFFE2FF2);
                    if (mode == 8) Put(trap, 72, 0x8000);
                    uint id = mode == 9 ? 12U : 11U;
                    registry.Stop(7, id, 1, false);
                    DispatchRefuse(() => registry.CaptureDispatch(id, true, new IntPtr(0x8007)));
                }
                Need(registry.Failed && !registry.Captured);
                DispatchRefuse(() => registry.CaptureDispatch(11, true, new IntPtr(0x8007)));
                bool expectedUncertainty = new [] { 1, 2, 3, 6, 7, 8, 9 }.Contains(mode);
                restoring = true; bool restoreRejected = false;
                try { registry.RestoreAll(); } catch (AggregateException) { restoreRejected = true; }
                Need(restoreRejected == expectedUncertainty && restores == (expectedUncertainty ? 1 : 2));
                registry.Continued(); registry.Stop(7, 11, 5, true); registry.Continued();
                bool uncertain = false; try { registry.Destroyed(); } catch (AggregateException) { uncertain = true; }
                Need(uncertain == expectedUncertainty && registry.Failed && registry.DestroyedState && !registry.CaptureRestored && calls <= 1);
            }
            foreach (bool closeFailure in new [] { false, true }) {
                var contexts = new Dictionary<IntPtr, byte[]> { { new IntPtr(11), new byte[DebugContext.Size] }, { new IntPtr(12), new byte[DebugContext.Size] } };
                int restores = 0, closes = 0;
                var registry = new ResourceThreads(7, 11, handle => (byte[])contexts[handle].Clone(), (handle, bytes) => {
                    if (U64(bytes, 80) == 0) { restores++; if (!closeFailure && handle == new IntPtr(11)) throw new InvalidOperationException("fixed restore"); }
                    contexts[handle] = (byte[])bytes.Clone();
                }, _ => { closes++; if (closeFailure) throw new InvalidOperationException("fixed close"); }, () => { });
                registry.Stop(7, 11, 3, false); registry.Enroll(11, new IntPtr(11), false); registry.Continued();
                registry.Stop(7, 12, 2, false); registry.Enroll(12, new IntPtr(12), true); registry.Continued();
                registry.Stop(7, 11, 6, false); registry.ArmDispatch(0x8000, 0x8007, () => { }); registry.Continued();
                registry.Stop(7, 11, 8, true);
                if (closeFailure) registry.RestoreAll();
                else { bool refused = false; try { registry.RestoreAll(); } catch (AggregateException) { refused = true; } Need(refused); }
                Need(restores == 2); registry.Continued(); registry.Stop(7, 11, 5, true); registry.Continued();
                bool rejected = false; try { registry.Destroyed(); } catch (AggregateException) { rejected = true; }
                Need(rejected && registry.Failed && registry.DestroyedState && closes == 1);
            }
        }
        static void CheckDispatchRestoreDrift()
        {
            foreach (int offset in new [] { 72, 112 }) {
                var contexts = new Dictionary<IntPtr, byte[]> { { new IntPtr(11), new byte[DebugContext.Size] }, { new IntPtr(12), new byte[DebugContext.Size] } };
                var restored = new List<IntPtr>(); bool restoring = false;
                var registry = new ResourceThreads(7, 11, handle => (byte[])contexts[handle].Clone(),
                    (handle, bytes) => { if (restoring) restored.Add(handle); contexts[handle] = (byte[])bytes.Clone(); }, _ => { }, () => { });
                registry.Stop(7, 11, 3, false); registry.Enroll(11, new IntPtr(11), false); registry.Continued();
                registry.Stop(7, 12, 2, false); registry.Enroll(12, new IntPtr(12), true); registry.Continued();
                registry.Stop(7, 11, 6, false); registry.ArmDispatch(0x8000, 0x8007, () => { }); registry.Continued();
                DispatchFixtureTrap(contexts[new IntPtr(11)], false);
                registry.Stop(7, 11, 1, false); registry.CaptureDispatch(11, true, new IntPtr(0x8000)); registry.Continued();
                Put(contexts[new IntPtr(12)], offset, 0x9999);
                DispatchFixtureTrap(contexts[new IntPtr(11)], true); restoring = true;
                registry.Stop(7, 11, 1, false); bool refused = false;
                try { registry.CaptureDispatch(11, true, new IntPtr(0x8007)); } catch (AggregateException) { refused = true; }
                Need(refused && registry.Failed && !registry.CaptureRestored && restored.Count == 1 && restored[0] == new IntPtr(11));
                Need(U64(contexts[new IntPtr(12)], offset) == 0x9999);
                registry.Continued(); registry.Stop(7, 11, 5, true); registry.Continued();
                bool sticky = false; try { registry.Destroyed(); } catch (AggregateException) { sticky = true; }
                Need(sticky && registry.Failed && registry.DestroyedState);
            }
        }
        static void CheckDispatchRefusalReporting()
        {
            for (int mode = 0; mode < 4; mode++) {
                var contexts = new Dictionary<IntPtr, byte[]> {
                    { new IntPtr(11), new byte[DebugContext.Size] }, { new IntPtr(12), new byte[DebugContext.Size] }
                };
                int writes = 0, closes = 0;
                var registry = new ResourceThreads(7, 11, handle => (byte[])contexts[handle].Clone(),
                    (handle, bytes) => { writes++; contexts[handle] = (byte[])bytes.Clone(); }, _ => closes++, () => { });
                registry.Stop(7, 11, 3, false); registry.Enroll(11, new IntPtr(11), false); registry.Continued();
                registry.Stop(7, 12, 2, false); registry.Enroll(12, new IntPtr(12), true); registry.Continued();
                registry.Stop(7, 11, 6, false); registry.ArmDispatch(0x8000, 0x8007, () => { }); registry.Continued();
                if (mode != 0) {
                    DispatchFixtureTrap(contexts[new IntPtr(11)], false);
                    registry.Stop(7, 11, 1, false); registry.CaptureDispatch(11, true, new IntPtr(0x8000)); registry.Continued();
                }
                Put(contexts[new IntPtr(12)], mode == 1 ? 112 : 104, mode == 1 ? 0x9999UL : 0xFFFE0FF0UL);
                if (mode == 0) DispatchFixtureTrap(contexts[new IntPtr(12)], false);
                int before = writes; Exception caught = null;
                if (mode < 2) {
                    DispatchFixtureTrap(contexts[new IntPtr(11)], mode == 1);
                    registry.Stop(7, 11, 1, false);
                    try { registry.CaptureDispatch(11, true, new IntPtr(mode == 1 ? 0x8007 : 0x8000)); }
                    catch (Exception failure) { caught = failure; }
                } else {
                    registry.Stop(7, mode == 3 ? 12U : 11U, mode == 3 ? 1U : 8U, true);
                    try { registry.RestoreAll(); } catch (Exception failure) { caught = failure; }
                }
                string phase = mode == 0 ? "call-disarm" : mode == 1 ? "pair-restore" : "cleanup-restore";
                string expected = "fixed resource observation refused check=dispatch-transition-control snapshot=first phase=" + phase +
                    " event_kind=" + (mode == 2 ? "8" : "1") + " pair_started=True paired=" + (mode == 1) +
                    " cleanup=" + (mode >= 2) + " event_thread_equal=" + (mode == 3) + " dr6_equal=" + (mode == 1) +
                    " dr7_equal=" + (mode >= 2) + " call_site_match=" + (mode == 0) +
                    " post_site_match=False call_status_match=" + (mode == 0) + " post_status_match=False" +
                    " stored_dr6=0x0000000000000000 stored_dr7=0x" + (mode == 0 ? "0000000000000005" : "0000000000000000") +
                    " current_dr6=0x" + (mode == 0 ? "00000000FFFF0FF1" : mode == 1 ? "0000000000000000" : "00000000FFFE0FF0") +
                    " current_dr7=0x" + (mode == 1 ? "0000000000009999" : mode == 0 ? "0000000000000405" : "0000000000000000") +
                    " transaction_context=unknown";
                Exception first = caught;
                while (first != null && first.InnerException != null) first = first.InnerException;
                Need(first is InvalidOperationException && first.Message == expected && expected.Length <= 1024 && writes == before + 1);
                Need(!expected.Contains("0000000000008000") && !expected.Contains("0000000000008007") &&
                    !expected.Contains("0000000000009000") && Array.TrueForAll(expected.ToCharArray(), c => c <= 127));
                Put(contexts[new IntPtr(12)], 104, UInt64.MaxValue); Put(contexts[new IntPtr(12)], 112, UInt64.MaxValue);
                bool repeated = false;
                try { registry.RestoreAll(); } catch (AggregateException failure) {
                    repeated = failure.ToString().Contains(expected) && !failure.ToString().Contains("FFFFFFFFFFFFFFFF");
                }
                Need(repeated && registry.Failed && !registry.CaptureRestored && !registry.DestroyedState);
                registry.Continued(); registry.Stop(7, 11, 5, true); registry.Continued();
                bool sticky = false;
                try { registry.Destroyed(); } catch (AggregateException failure) { sticky = failure.ToString().Contains(expected); }
                Need(sticky && registry.DestroyedState && closes == 1);
            }
        }
        static void CheckDispatchReads()
        {
            var info = new MemoryInfo { address = new IntPtr(0x1000), allocation = new IntPtr(0x1000), size = new UIntPtr(0x1000), state = 0x1000, type = 0x1000000, protect = 2 };
            Need(DispatchReadable(info, 0x1FF8, 0x1000) && !DispatchReadable(info, 0x1FF9, 0x1000));
            foreach (uint protect in new uint[] { 0, 1, 0x10, 0x102 }) { info.protect = protect; Need(!DispatchReadable(info, 0x1100, 0x1000)); }
            info.protect = 2; Need(!DispatchReadable(info, 0x1100, 0x2000)); info.state = 0x2000; Need(!DispatchReadable(info, 0x1100, 0x1000));
            info.state = 0x1000; info.type = 0x20000; Need(!DispatchReadable(info, 0x1100, 0x1000));
            for (int mode = 0; mode < 5; mode++) {
                bool consumed = false, rejected = false; int reads = 0, regions = 0; byte[] retained = null;
                DispatchRead reader = (byte[] bytes, out UIntPtr count) => {
                    reads++; retained = bytes; BitConverter.GetBytes(mode == 3 ? 0x1235UL : 0x1234UL).CopyTo(bytes, 0);
                    count = new UIntPtr(mode == 2 ? 7U : 8U); return mode != 4;
                };
                try { ReadDispatchTarget(ref consumed, () => { regions++; return mode != 1; }, reader, 0x1234); }
                catch (InvalidOperationException) { rejected = true; }
                Need(consumed && rejected == (mode != 0) && regions == 1 && reads == (mode == 1 ? 0 : 1) && (retained == null || retained.All(b => b == 0)));
                DispatchRefuse(() => ReadDispatchTarget(ref consumed, () => { regions++; return true; }, reader, 0x1234));
                Need(regions == 1);
            }
        }
        static void CheckDispatchGenerations()
        {
            var contexts = new Dictionary<IntPtr, byte[]>(); int writes = 0, closes = 0;
            Func<ResourceThreads> create = () => new ResourceThreads(7, 11, handle => (byte[])contexts[handle].Clone(),
                (handle, bytes) => { writes++; contexts[handle] = (byte[])bytes.Clone(); }, _ => closes++, () => { });
            contexts[new IntPtr(11)] = new byte[DebugContext.Size];
            var registry = create();
            registry.Stop(7, 11, 3, false); registry.Enroll(11, new IntPtr(11), false); registry.Continued();
            registry.Stop(7, 11, 6, false); registry.ArmDispatch(0x8000, 0x8007, () => { }); registry.Continued();
            for (int index = 0; index < 127; index++) {
                IntPtr handle = new IntPtr(100 + index); contexts[handle] = new byte[DebugContext.Size];
                registry.Stop(7, 12, 2, false); registry.Enroll(12, handle, true); registry.Continued();
                Need(U64(contexts[handle], 72) == 0x8000 && U64(contexts[handle], 80) == 0x8007);
                registry.Stop(7, 12, 4, false); registry.Continued();
            }
            contexts[new IntPtr(300)] = new byte[DebugContext.Size];
            registry.Stop(7, 12, 2, false); DispatchRefuse(() => registry.Enroll(12, new IntPtr(300), true));
            registry.Continued(); Need(registry.Enrolled == 128 && closes == 127 && writes == 128);
            registry.Stop(7, 11, 5, false); registry.Continued(); registry.Destroyed();
            Need(!registry.Captured && !registry.CaptureRestored); // Natural nonreach never earns a pair.
            registry = create();
            DispatchRefuse(() => registry.Stop(8, 11, 3, false));
            int before = writes;
            DispatchRefuse(() => registry.ArmDispatch(0x8000, 0x8007, () => { })); Need(writes == before);
        }
        static void CheckDispatchMetadata()
        {
            var observer = new ActivationBoundaryTrace(new IntPtr(1), new IntPtr(2), 7, 11, "private-path", "private-digest", _ => { }, false, false, true, () => { }, true);
            DispatchRefuse(() => observer.DispatchMetadata());
            DispatchRefuse(() => observer.RequireComplete());
            observer.resourceDestroyed = true;
            string metadata = observer.DispatchMetadata();
            Need(metadata.Length < 1024 && metadata.Contains("paired=False") && metadata.Contains("observation_qualified=False") &&
                !metadata.Contains("raw_return=") && !metadata.Contains("private-") && metadata.EndsWith("undebugged_equivalence_claimed=False", StringComparison.Ordinal));
            var module = new ActivationBoundaryTrace(new IntPtr(1), new IntPtr(2), 7, 11, "private-path", "private-digest", _ => { }, false, false, true, () => { }, true, true);
            module.resourceDestroyed = true;
            string moduleMetadata = module.DispatchMetadata();
            Need(moduleMetadata.Length < 1024 && moduleMetadata.StartsWith("WINDOWS_MODULE_CSR_DISPATCH invocation_module_verified=False python_equivalence_claimed=False paired=False", StringComparison.Ordinal) &&
                moduleMetadata.Contains("observation_qualified=False") && !moduleMetadata.Contains("private-") && !moduleMetadata.Contains("raw_return="));
            var continuation = new LoaderTrace.ResourceContinuation();
            DispatchRefuse(() => continuation.Run(() => { throw new InvalidOperationException("fixed continue"); }));
            continuation.Run(() => { }); DispatchRefuse(continuation.RequireClean);
        }
    }
}
