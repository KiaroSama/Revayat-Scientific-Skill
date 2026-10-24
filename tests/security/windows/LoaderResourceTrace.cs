using System;

namespace ScientificSecurity
{
    internal sealed partial class LoaderTrace
    {
        readonly string resourcePython;
        readonly bool dispatchMode, moduleDispatchMode;
        uint? dispatchExit;
        internal uint? DispatchExit { get { ThreadCheck(); return dispatchExit; } }
        internal string DispatchMetadata()
        {
            ThreadCheck();
            if (!dispatchMode || activation == null) throw new InvalidOperationException("fixed dispatch observer is unavailable");
            return activation.DispatchMetadata();
        }
        readonly ResourceContinuation resourceContinuation = new ResourceContinuation();
        internal sealed class ResourceContinuation
        {
            Exception failure;
            internal void Run(Action continuation)
            {
                try { continuation(); }
                catch (Exception error) { if (failure == null) failure = error; throw; }
            }
            internal void RequireClean()
            { if (failure != null) throw new InvalidOperationException("resource continuation remains unqualified", failure); }
        }
        internal static void FinalizeResourceCleanup(Action invalidate, Action restore, Action exit,
            bool processExit, Action[] releases, Action continuation)
        {
            ActivationEvent(() => { invalidate(); if (processExit) exit(); restore(); },
                restore, releases, continuation);
        }
        bool ResourceMode { get { return resourcePython != null; } }
        internal string ResourceMetadata()
        {
            ThreadCheck();
            if (!ResourceMode || activation == null) throw new InvalidOperationException("fixed resource observer is unavailable");
            return activation.ResourceMetadata();
        }
        void ResourceDeadline()
        {
            if (activationCleanup.IsRunning) {
                if (RemainingActivationCleanup() == 0) throw new TimeoutException("resource cleanup deadline exceeded");
            } else if (clock.Elapsed.TotalSeconds >= 10 || events > 128 || bytes > 65536)
                throw new TimeoutException("resource observation ceiling exceeded");
        }
        void ResourceFailureRestore()
        {
            if (!activationCleanup.IsRunning) activationCleanup.Start();
            activation.Invalidate(); activation.Restore();
        }
        void ObserveResourceThread()
        {
            if (activation.ResourceCaptured) return; // After capture CREATE_THREAD is transport only.
            IntPtr borrowed = current.data.createThread.thread, owned = IntPtr.Zero;
            if (borrowed == IntPtr.Zero || borrowed == Native.InvalidHandle)
                throw new InvalidOperationException("resource thread event handle is invalid");
            Exception primary = null;
            try {
                Native.Check(DuplicateHandle(Native.GetCurrentProcess(), borrowed, Native.GetCurrentProcess(),
                    out owned, 0, false, 2), "retain event-derived resource thread");
                if (owned == borrowed || owned == IntPtr.Zero || owned == Native.InvalidHandle) {
                    owned = IntPtr.Zero; // An alias is not a separately owned duplicate.
                    throw new InvalidOperationException("resource duplicate ownership is ambiguous");
                }
                activation.ResourceThread(current.tid, ref owned);
            } catch (Exception failure) { primary = failure; throw; }
            finally {
                if (owned != IntPtr.Zero) {
                    try { callbackFiles.Close(ref owned, value => Native.Check(Native.CloseHandle(value), "close unenrolled resource duplicate")); }
                    catch (Exception cleanup) {
                        if (primary != null) throw new AggregateException("resource enrollment/duplicate cleanup failed", primary, cleanup);
                        throw;
                    }
                }
            }
        }
        void ObserveResourceEvent(bool cleanup, Action[] releases)
        {
            uint status = current.code == 1 ? NotHandled : Continue;
            if (cleanup) {
                FinalizeResourceCleanup(activation.Invalidate, activation.Restore,
                    () => { activation.ResourceExit(true); exited = true; }, current.code == 5,
                    releases, () => ContinuePending(status));
                return;
            }
            events++;
            try {
                ActivationEvent(() => {
                    ResourceDeadline();
                    switch (current.code) {
                        case 1:
                            uint code = current.data.exception.record.code;
                            bool first = current.data.exception.firstChance != 0;
                            if (!activation.SingleStep(current.tid, code, first, current.data.exception.record.address) &&
                                !activation.AcceptSoftware(current.tid, code, first))
                                throw new InvalidOperationException("resource observation encountered an unexpected exception");
                            status = Continue; break;
                        case 2: ObserveResourceThread(); break;
                        case 4: case 8: break;
                        case 5:
                            if (dispatchMode) dispatchExit = current.data.exit.code;
                            activation.ResourceExit(false); exited = true; break;
                        case 6: if (!activation.ResourceCaptured) activation.Load(current.data.loadDll.file, current.data.loadDll.imageBase); break;
                        case 7: activation.Unload(current.data.unloadDll.imageBase); break;
                        default: throw new InvalidOperationException("unsupported resource observation event");
                    }
                }, ResourceFailureRestore, releases, () => ContinuePending(status));
            } catch { activation.Invalidate(); throw; }
        }
    }
}
