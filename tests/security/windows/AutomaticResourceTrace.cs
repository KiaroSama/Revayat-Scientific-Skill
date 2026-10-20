using System;
using System.Collections.Generic;

namespace ScientificSecurity
{
    public sealed partial class ActivationBoundaryTrace
    {
        readonly bool automaticResource;
        ResourceThreads resourceThreads;
        bool resourceNaturalExit, resourceDestroyed;
        internal sealed class ResourceThreads
        {
            sealed class Generation
            {
                internal uint id;
                internal IntPtr handle;
                internal byte[] baseline;
                internal bool owned, dead, retired, changed;
            }
            readonly uint pid, creator;
            readonly Func<IntPtr, byte[]> read;
            readonly Action<IntPtr, byte[]> write;
            readonly Action<IntPtr> close;
            readonly Action deadline;
            readonly List<Generation> generations = new List<Generation>();
            bool epoch, cleanup, processDead, initial, captureRestored, failed, destroyed;
            Exception cleanupUncertainty;
            uint eventThread, kind;
            ulong site;
            internal bool Captured { get; private set; }
            internal bool BaseEqual { get; private set; }
            internal bool CreatorCapture { get; private set; }
            internal uint RawEax { get; private set; }
            internal string Trap { get; private set; }
            internal bool CaptureRestored { get { return captureRestored; } }
            internal bool Failed { get { return failed; } }
            internal bool DestroyedState { get { return destroyed; } }
            internal int Enrolled { get { return generations.Count; } }
            internal int Retired { get; private set; }
            internal int PriorDeadRetired { get; private set; }
            internal ResourceThreads(uint processId, uint creatorId, Func<IntPtr, byte[]> reader,
                Action<IntPtr, byte[]> writer, Action<IntPtr> closer, Action checkDeadline)
            { pid = processId; creator = creatorId; read = reader; write = writer; close = closer; deadline = checkDeadline; }
            Generation Live(uint id)
            {
                foreach (var value in generations) if (value.id == id && !value.retired && !value.dead) return value;
                throw new InvalidOperationException("resource event has no live enrolled thread");
            }
            internal void Stop(uint actualPid, uint actualThread, uint eventKind, bool draining)
            {
                epoch = false;
                ResourceCheck(actualPid == pid, "event-process");
                if (!draining) {
                    ResourceCheck(!processDead && (eventKind >= 1 && eventKind <= 8 && eventKind != 3 ||
                        generations.Count == 0 && eventKind == 3 && actualThread == creator), "event-lifetime-kind");
                    if (eventKind == 2) foreach (var value in generations) ResourceCheck(value.retired || value.id != actualThread, "duplicate-live-thread");
                    if (eventKind == 1 || !Captured && eventKind != 2 && eventKind != 3) Live(actualThread);
                }
                eventThread = actualThread; kind = eventKind; cleanup = draining;
                if (draining) failed = true;
                if (eventKind == 5) {
                    processDead = true;
                    foreach (var value in generations) value.dead = true;
                } else if (eventKind == 4) {
                    foreach (var value in generations) if (value.id == actualThread && !value.retired) value.dead = true;
                }
                epoch = true;
            }
            internal void Enroll(uint id, IntPtr handle, bool owned)
            {
                ValidateEnrollment(id, handle);
                var record = new Generation { id = id, handle = handle, owned = owned };
                generations.Add(record); // Ownership transfers before the first operation that can fail.
                deadline(); record.baseline = read(handle); ResourceCheck(Free(record.baseline), "free-thread-baseline");
                if (site != 0) Apply(record, false);
            }
            internal void Continued()
            {
                ResourceCheck(epoch, "continue-epoch"); epoch = false;
                var failures = new List<Exception>();
                if (kind == 4) foreach (var value in generations) if (value.id == eventThread && value.dead && !value.retired) {
                    Attempt(failures, () => Retire(value));
                }
                if (failures.Count != 0) { failed = true; cleanupUncertainty = new AggregateException("resource thread retirement failed", failures); throw cleanupUncertainty; }
            }
            void Retire(Generation value)
            {
                ResourceCheck(value.dead && !value.retired, "retire-lifetime");
                value.retired = true; Retired++;
                if (!Captured && !processDead) PriorDeadRetired++;
                if (value.baseline != null) Array.Clear(value.baseline, 0, value.baseline.Length);
                IntPtr handle = value.handle; value.handle = IntPtr.Zero;
                if (value.owned && handle != IntPtr.Zero) close(handle);
            }
            internal void Arm(ulong address)
            {
                ResourceCheck(epoch && !cleanup && !processDead && !Captured && site == 0 && address != 0, "arm-state");
                site = address;
                foreach (var value in generations) if (!value.dead && !value.retired) Apply(value, false);
            }
            void Apply(Generation value, bool restore)
            {
                ResourceCheck(epoch && !value.dead && !value.retired && value.baseline != null, "setter-lifetime");
                deadline(); byte[] before = null, desired = null, after = null;
                try {
                    before = read(value.handle);
                    if (!restore) ResourceCheck(DebugContext.RawDebugEqual(value.baseline, before), "arm-baseline-equality");
                    desired = Desired(before, value.baseline, new ulong[] { site, 0 }, new [] { !restore, false }, restore);
                    value.changed = true;
                    write(value.handle, desired); after = read(value.handle);
                    ResourceCheck(DebugContext.RawDebugEqual(desired, after) && DebugContext.UnchangedControlInteger(before, after), "setter-readback");
                    if (restore) value.changed = false;
                } catch (Exception error) {
                    failed = true;
                    if (value.changed && cleanupUncertainty == null) cleanupUncertainty = error;
                    throw;
                }
                finally { foreach (var buffer in new [] { before, desired, after }) if (buffer != null) Array.Clear(buffer, 0, buffer.Length); }
            }
            internal void RestoreAll()
            {
                if (!epoch) return;
                var failures = new List<Exception>();
                foreach (var value in generations) if (value.changed && !value.dead && !value.retired)
                    Attempt(failures, () => Apply(value, true));
                if (failures.Count != 0) { failed = true; cleanupUncertainty = new AggregateException("resource all-thread restoration failed", failures); throw cleanupUncertainty; }
            }
            internal bool Capture(uint id, bool first, IntPtr exception, ulong imageBase)
            {
                ResourceCheck(epoch && !cleanup && !Captured && site != 0 && !processDead, "capture-state");
                deadline(); Generation value = Live(id); byte[] context = read(value.handle);
                try {
                    ResourceCheck(first && value.changed && unchecked((ulong)exception.ToInt64()) == site && U64(context, 248) == site, "capture-site");
                    for (int index = 0; index < 4; index++) ResourceCheck(U64(context, 72 + index * 8) == (index == 0 ? site : U64(value.baseline, 72 + index * 8)), "capture-address-ownership");
                    ResourceCheck(DebugContext.OwnedTrapStatus(U64(context, 104), U64(context, 112), U64(value.baseline, 112) | 1, 0), "capture-trap-ownership");
                    Captured = true; CreatorCapture = id == creator;
                    RawEax = unchecked((uint)U64(context, 120)); BaseEqual = U64(context, 176) == imageBase;
                    Trap = DebugContext.TrapQualifiers(U64(context, 104));
                    RestoreAll(); captureRestored = true;
                    ResourceCheck(BaseEqual, "first-base-equality"); return true;
                } catch { failed = true; throw; }
                finally { Array.Clear(context, 0, context.Length); }
            }
            internal bool Software(uint id, bool first)
            {
                ResourceCheck(epoch && !cleanup && id == creator && first && !initial && !processDead, "software-state");
                Generation value = Live(id); byte[] context = read(value.handle);
                try {
                    ulong expected = U64(value.baseline, 112) | (value.changed ? 1UL : 0UL);
                    for (int index = 0; index < 4; index++) ResourceCheck(U64(context, 72 + index * 8) == (index == 0 && value.changed ? site : U64(value.baseline, 72 + index * 8)), "software-address-ownership");
                    bool qualified = site == 0 && !value.changed ? DebugContext.RawDebugEqual(value.baseline, context) :
                        SoftwareStatus(U64(context, 104), U64(context, 112), expected) ||
                        Captured && BaseEqual && captureRestored && !failed && !value.changed && DebugContext.RawDebugEqual(value.baseline, context);
                    if (!qualified)
                        throw new InvalidOperationException("fixed resource observation refused check=software-control-ownership " +
                            DebugContext.TrapQualifiers(U64(context, 104)) + " raw_dr7=0x" + U64(context, 112).ToString("X16"));
                    initial = true; return true;
                } finally { Array.Clear(context, 0, context.Length); }
            }
            internal void Invalidate() { failed = true; }
            internal void ClearEpoch() { epoch = false; }
            internal void EnrollOwned(uint id, ref IntPtr handle)
            {
                ValidateEnrollment(id, handle);
                IntPtr transferred = handle; handle = IntPtr.Zero;
                Enroll(id, transferred, true);
            }
            void ValidateEnrollment(uint id, IntPtr handle)
            {
                ResourceCheck(epoch && !cleanup && !Captured && !processDead && (kind == 2 || kind == 3) && eventThread == id, "enrollment-state");
                ResourceCheck(generations.Count < 128 && handle != IntPtr.Zero && handle != Native.InvalidHandle, "enrollment-capacity-handle");
                foreach (var value in generations) ResourceCheck(value.retired || value.id != id && value.handle != handle, "enrollment-generation");
            }
            internal void Destroyed()
            {
                ResourceCheck(processDead && !epoch, "destruction-state");
                var failures = new List<Exception>();
                foreach (var value in generations) if (!value.retired) Attempt(failures, () => Retire(value));
                destroyed = true;
                if (cleanupUncertainty != null) failures.Insert(0, cleanupUncertainty);
                if (failures.Count != 0) { failed = true; throw new AggregateException("resource final thread retirement or restoration remains unqualified", failures); }
            }
            static void Attempt(List<Exception> failures, Action action)
            { try { action(); } catch (Exception failure) { failures.Add(failure); } }
        }
        static void ResourceCheck(bool value, string check)
        { if (!value) throw new InvalidOperationException("fixed resource observation refused check=" + check); }
        void ResourceCreation(IntPtr file, IntPtr imageBase)
        {
            ResourceCheck(resourceThreads != null && fixture == null && !invalidated, "creation-state");
            fixture = KernelImage.FromExplicitEntryCreation(file, imageBase, path, digest);
            RequireExecutable(fixture, fixture.Entry, 1);
            resourceThreads.Enroll(tid, thread, false);
        }
        void ResourceLoad(IntPtr file, IntPtr imageBase)
        {
            ResourceCheck(fixture != null && !invalidated, "load-state");
            KernelImage candidate = KernelImage.FromActivationSystemLoad(file, imageBase);
            if (candidate == null) return;
            ResourceCheck(kernel == null, "duplicate-kernel-load"); candidate.RequireModuleCallbackProfile();
            RequireExecutable(candidate, 0x25C1D, 5); kernel = candidate;
            resourceThreads.Arm(kernel.Address(0x25C1D));
        }
        internal bool ResourceCaptured { get { return resourceThreads != null && resourceThreads.Captured; } }
        internal void ResourceClearEpoch() { resourceThreads.ClearEpoch(); }
        internal void ResourceThread(uint id, ref IntPtr owned)
        { resourceThreads.EnrollOwned(id, ref owned); }
        internal void ResourceExit(bool cleanup)
        { if (!cleanup) resourceNaturalExit = true; }
        bool ResourceComplete()
        { return resourceThreads.Captured && resourceThreads.BaseEqual && resourceThreads.CaptureRestored && !resourceThreads.Failed && resourceNaturalExit && !invalidated; }
        void RequireResourceComplete()
        {
            if (!ResourceComplete()) throw new InvalidOperationException("fixed resource observation incomplete captured=" + resourceThreads.Captured +
                " register_base_equal=" + resourceThreads.BaseEqual + " capture_live_restored=" + resourceThreads.CaptureRestored +
                " failed=" + resourceThreads.Failed + " natural_exit=" + resourceNaturalExit + " invalidated=" + invalidated);
        }
        internal string ResourceMetadata()
        {
            ResourceCheck(automaticResource && resourceDestroyed, "metadata-destruction");
            return "WINDOWS_AUTOMATIC_RESOURCE traced=True process_scope=True first_delivery=" + resourceThreads.Captured + " captured=" + resourceThreads.Captured +
                " creator=" + resourceThreads.CreatorCapture + (resourceThreads.Captured ? " raw_eax=0x" + resourceThreads.RawEax.ToString("X8") : "") +
                " register_base_equal=" + resourceThreads.BaseEqual + " capture_live_restored=" + resourceThreads.CaptureRestored +
                " prior_dead_retired=" + resourceThreads.PriorDeadRetired + " retired_count=" + resourceThreads.Retired + " enrolled_count=" + resourceThreads.Enrolled +
                " natural_exit=" + resourceNaturalExit + " state_destroyed=True observation_qualified=" + ResourceComplete() +
                (resourceThreads.Trap == null ? "" : " " + resourceThreads.Trap) + " cause_claimed=False undebugged_equivalence_claimed=False";
        }
    }
}
