using System;
using System.Collections.Generic;

namespace ScientificSecurity
{
    public sealed partial class ActivationBoundaryTrace
    {
        public static void CheckAutomaticResourceValidation()
        {
            var contexts = new Dictionary<IntPtr, byte[]>();
            var closed = new List<IntPtr>(); int reads = 0, writes = 0;
            Func<IntPtr, byte[]> read = handle => { reads++; return (byte[])contexts[handle].Clone(); };
            Action<IntPtr, byte[]> write = (handle, value) => { writes++; contexts[handle] = (byte[])value.Clone(); };
            Func<ResourceThreads> create = () => new ResourceThreads(7, 11, read, write, handle => closed.Add(handle), () => { });
            Func<int, IntPtr> handleFor = value => new IntPtr(value + 1000);
            Action<int> prepare = value => contexts[handleFor(value)] = new byte[1232];
            Action<Action> refuse = action => { bool failed = false; try { action(); } catch (InvalidOperationException) { failed = true; } Need(failed); };
            prepare(11); prepare(12);
            var registry = create();
            refuse(() => registry.Enroll(11, handleFor(11), false)); Need(reads == 0 && writes == 0);
            registry.Stop(7, 11, 3, false); registry.Enroll(11, handleFor(11), false); registry.Continued();
            refuse(() => registry.Arm(0x8000)); Need(writes == 0);
            registry.Stop(7, 11, 6, false); registry.Arm(0x8000); registry.Continued();
            Need(BitConverter.ToUInt64(contexts[handleFor(11)], 72) == 0x8000 && writes == 1);
            registry.Stop(7, 12, 2, false); registry.Enroll(12, handleFor(12), true); registry.Continued();
            Need(BitConverter.ToUInt64(contexts[handleFor(12)], 72) == 0x8000 && writes == 2);
            byte[] trap = contexts[handleFor(12)]; Put(trap, 104, 0xFFFF0FF1); Put(trap, 112, 0x401);
            Put(trap, 120, 0x12345678C0000022); Put(trap, 176, 0x10000000); Put(trap, 248, 0x8000);
            registry.Stop(7, 12, 1, false);
            Need(registry.Capture(12, true, new IntPtr(0x8000), 0x10000000));
            Need(registry.Captured && registry.CaptureRestored && registry.RawEax == 0xC0000022 && registry.BaseEqual && !registry.CreatorCapture);
            Need(writes == 4 && BitConverter.ToUInt64(contexts[handleFor(12)], 120) == 0x12345678C0000022 &&
                BitConverter.ToUInt64(contexts[handleFor(12)], 176) == 0x10000000 && BitConverter.ToUInt64(contexts[handleFor(12)], 248) == 0x8000);
            refuse(() => registry.Capture(12, true, new IntPtr(0x8000), 0x10000000));
            registry.Continued(); registry.Stop(7, 12, 4, false); registry.Continued();
            Need(closed.Count == 1 && closed[0] == handleFor(12));
            registry.Stop(7, 11, 5, false); registry.Continued(); registry.Destroyed();
            Need(registry.CaptureRestored && registry.DestroyedState);
            // Lifetime capacity is never refunded by a continued EXIT and closed duplicate.
            contexts.Clear(); closed.Clear(); reads = writes = 0; registry = create(); prepare(11);
            registry.Stop(7, 11, 3, false); registry.Enroll(11, handleFor(11), false); registry.Continued();
            for (int index = 0; index < 127; index++) {
                int id = 20 + index; prepare(id);
                registry.Stop(7, (uint)id, 2, false); registry.Enroll((uint)id, handleFor(id), true); registry.Continued();
                registry.Stop(7, (uint)id, 4, false); registry.Continued();
            }
            prepare(200); registry.Stop(7, 200, 2, false);
            refuse(() => registry.Enroll(200, handleFor(200), true)); Need(registry.Enrolled == 128);
            // Numeric TID reuse is allowed only after the old generation has retired.
            contexts.Clear(); closed.Clear(); registry = create(); prepare(11); prepare(12);
            registry.Stop(7, 11, 3, false); registry.Enroll(11, handleFor(11), false); registry.Continued();
            registry.Stop(7, 12, 2, false); registry.Enroll(12, handleFor(12), true); registry.Continued();
            registry.Stop(7, 12, 4, false); registry.Continued();
            prepare(13); registry.Stop(7, 12, 2, false); registry.Enroll(12, handleFor(13), true); registry.Continued();
            Need(registry.Enrolled == 3 && registry.Retired == 1);
            // An equality mismatch consumes the first capture; it cannot seek a convenient later hit.
            foreach (bool mismatch in new [] { false, true }) {
                contexts.Clear(); registry = create(); prepare(11);
                registry.Stop(7, 11, 3, false); registry.Enroll(11, handleFor(11), false); registry.Continued();
                registry.Stop(7, 11, 6, false); registry.Arm(0x8000); registry.Continued();
                trap = contexts[handleFor(11)]; Put(trap, 104, 0xFFFE0FF1); Put(trap, 112, 1);
                Put(trap, 176, mismatch ? 0x20000000UL : 0x10000000UL); Put(trap, 248, 0x8000);
                registry.Stop(7, 11, 1, false);
                if (mismatch) refuse(() => registry.Capture(11, true, new IntPtr(0x8000), 0x10000000));
                else Need(registry.Capture(11, true, new IntPtr(0x8000), 0x10000000));
                Need(registry.Captured && registry.CaptureRestored && registry.BaseEqual != mismatch);
            }
            // All safe restores are attempted, and failure stays sticky through later death.
            contexts.Clear(); prepare(11); prepare(12); int restoredAttempts = 0;
            registry = new ResourceThreads(7, 11, read, (handle, value) => {
                if (BitConverter.ToUInt64(value, 72) == 0) { restoredAttempts++; if (handle == handleFor(11)) throw new InvalidOperationException("fixed restore"); }
                write(handle, value);
            }, handle => closed.Add(handle), () => { });
            registry.Stop(7, 11, 3, false); registry.Enroll(11, handleFor(11), false); registry.Continued();
            registry.Stop(7, 12, 2, false); registry.Enroll(12, handleFor(12), true); registry.Continued();
            registry.Stop(7, 11, 6, false); registry.Arm(0x8000); registry.Continued();
            trap = contexts[handleFor(11)]; Put(trap, 104, 0xFFFF0FF1); Put(trap, 112, 0x401);
            Put(trap, 176, 0x10000000); Put(trap, 248, 0x8000);
            registry.Stop(7, 11, 1, false); Exception restoration = null;
            try { registry.Capture(11, true, new IntPtr(0x8000), 0x10000000); } catch (AggregateException failure) { restoration = failure; }
            Need(restoration != null && restoredAttempts == 2 && !registry.CaptureRestored);
            registry.Continued(); registry.Stop(7, 11, 5, true); registry.Continued();
            AggregateException destruction = null;
            try { registry.Destroyed(); } catch (AggregateException failure) { destruction = failure; }
            Need(destruction != null && registry.Failed && !registry.CaptureRestored);
            int beforeReads = reads; registry.Stop(7, 11, 6, true); registry.RestoreAll(); Need(reads == beforeReads);
            CheckResourceRefusal();
            CheckResourceFinalization();
            // An unsupported event clears authority before any context access.
            registry = create(); refuse(() => registry.Stop(8, 11, 6, false)); refuse(() => registry.Enroll(11, handleFor(11), false));
        }
        static void CheckResourceRefusal()
        {
            var contexts = new Dictionary<IntPtr, byte[]> { { new IntPtr(11), new byte[1232] } };
            var registry = new ResourceThreads(7, 11, handle => (byte[])contexts[handle].Clone(),
                (handle, bytes) => contexts[handle] = (byte[])bytes.Clone(), _ => { }, () => { });
            Exception caught = null;
            try { registry.Arm(0x8000); } catch (InvalidOperationException error) { caught = error; }
            Need(caught != null && caught.Message == "fixed resource observation refused check=arm-state");
            registry.Stop(7, 11, 3, false); registry.Enroll(11, new IntPtr(11), false); registry.Continued();
            registry.Stop(7, 11, 6, false); registry.Arm(0x8000); registry.Continued();
            byte[] trap = contexts[new IntPtr(11)]; Put(trap, 104, 0xFFFF0FF1); Put(trap, 112, 0x401);
            Put(trap, 248, 0x8000); Put(trap, 176, 0x20000000);
            registry.Stop(7, 11, 1, false); caught = null;
            try { registry.Capture(11, true, new IntPtr(0x8000), 0x10000000); }
            catch (InvalidOperationException error) { caught = error; }
            Need(caught != null && caught.Message == "fixed resource observation refused check=first-base-equality" &&
                registry.Captured && registry.CaptureRestored && registry.Failed && !registry.BaseEqual);
            Need(BitConverter.ToUInt64(contexts[new IntPtr(11)], 72) == 0);
            var observer = new ActivationBoundaryTrace(new IntPtr(1), new IntPtr(2), 7, 11,
                "private-path", "private-digest", _ => { }, false, false, true, () => { });
            caught = null;
            try { observer.RequireComplete(); } catch (InvalidOperationException error) { caught = error; }
            Need(caught != null && caught.Message == "fixed resource observation incomplete captured=False" +
                " register_base_equal=False capture_live_restored=False failed=False natural_exit=False invalidated=False");
        }
        static void CheckResourceFinalization()
        {
            var continuation = new LoaderTrace.ResourceContinuation();
            var failedContinue = new InvalidOperationException("fixed continue failure");
            int attempts = 0; Exception first = null, final = null;
            try { continuation.Run(() => { attempts++; throw failedContinue; }); } catch (Exception failure) { first = failure; }
            continuation.Run(() => attempts++); // A retry releases the event, not the uncertainty.
            try { continuation.RequireClean(); } catch (Exception failure) { final = failure; }
            Need(attempts == 2 && Object.ReferenceEquals(first, failedContinue) && final != null);
            int metadata = 0, undebugged = 0;
            Exception carrier = ExplicitEntryComparison.FinishTrace(first, new List<Exception> { final }, true, true, () => "fixed", _ => metadata++);
            try { ExplicitEntryComparison.Execute(() => { throw carrier; }, () => undebugged++); } catch (AggregateException) { }
            Need(metadata == 0 && undebugged == 0);
            var contexts = new Dictionary<IntPtr, byte[]> { { new IntPtr(11), new byte[1232] } };
            int writes = 0;
            var registry = new ResourceThreads(7, 11, handle => (byte[])contexts[handle].Clone(),
                (handle, bytes) => { writes++; contexts[handle] = (byte[])bytes.Clone(); }, _ => { }, () => { });
            registry.Stop(7, 11, 3, false); registry.Enroll(11, new IntPtr(11), false); registry.Continued();
            registry.Stop(7, 11, 6, false); registry.Arm(0x8000); registry.Continued();
            registry.Stop(7, 11, 8, true);
            var order = new List<string>();
            LoaderTrace.FinalizeResourceCleanup(() => { order.Add("invalidate"); registry.Invalidate(); },
                () => { order.Add("restore"); registry.RestoreAll(); }, () => order.Add("exit"), false,
                new Action[] { () => order.Add("close") }, () => { order.Add("continue"); registry.Continued(); });
            Need(writes == 2 && BitConverter.ToUInt64(contexts[new IntPtr(11)], 72) == 0 &&
                String.Join(",", order) == "invalidate,restore,close,continue");
        }
    }
}
