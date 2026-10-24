using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace ScientificSecurity
{
    // Fixed trusted pass-code phase evidence only. Never an admission result or arbitrary debugger.
    internal sealed partial class LoaderTrace
    {
        [StructLayout(LayoutKind.Sequential)] struct ExceptionParameters {
            internal ulong p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12, p13, p14;
        }
        [StructLayout(LayoutKind.Sequential)] struct ExceptionRecord {
            internal uint code, flags; internal IntPtr nested, address; internal uint count;
            internal ExceptionParameters parameters;
        }
        [StructLayout(LayoutKind.Sequential)] struct ExceptionInfo { internal ExceptionRecord record; internal uint firstChance; }
        [StructLayout(LayoutKind.Sequential)] struct CreateThreadInfo { internal IntPtr thread, localBase, start; }
        [StructLayout(LayoutKind.Sequential)] struct CreateProcessInfo {
            internal IntPtr file, process, thread, imageBase; internal uint debugOffset, debugSize;
            internal IntPtr localBase, start, imageName; internal ushort unicode;
        }
        [StructLayout(LayoutKind.Sequential)] struct ExitInfo { internal uint code; }
        [StructLayout(LayoutKind.Sequential)] struct LoadDllInfo {
            internal IntPtr file, imageBase; internal uint debugOffset, debugSize; internal IntPtr imageName; internal ushort unicode;
        }
        [StructLayout(LayoutKind.Sequential)] struct UnloadDllInfo { internal IntPtr imageBase; }
        [StructLayout(LayoutKind.Sequential)] struct DebugStringInfo { internal IntPtr text; internal ushort unicode, bytes; }
        [StructLayout(LayoutKind.Sequential)] struct RipInfo { internal uint error, type; }
        [StructLayout(LayoutKind.Explicit, Size = 160)] struct DebugUnion {
            [FieldOffset(0)] internal ExceptionInfo exception;
            [FieldOffset(0)] internal CreateThreadInfo createThread;
            [FieldOffset(0)] internal CreateProcessInfo createProcess;
            [FieldOffset(0)] internal ExitInfo exit;
            [FieldOffset(0)] internal LoadDllInfo loadDll;
            [FieldOffset(0)] internal UnloadDllInfo unloadDll;
            [FieldOffset(0)] internal DebugStringInfo debugString;
            [FieldOffset(0)] internal RipInfo rip;
        }
        [StructLayout(LayoutKind.Sequential)] struct DebugEvent { internal uint code, pid, tid; internal DebugUnion data; }
        [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool WaitForDebugEventEx(out DebugEvent value, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr process,
            IntPtr address, byte[] buffer, UIntPtr bytes, out UIntPtr returned);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool ContinueDebugEvent(uint pid, uint tid, uint status);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool DuplicateHandle(IntPtr sourceProcess,
            IntPtr source, IntPtr targetProcess, out IntPtr duplicate, uint access, bool inherit, uint options);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetFinalPathNameByHandleW(IntPtr file, StringBuilder path, uint characters, uint flags);

        readonly uint creator = GetCurrentThreadId();
        readonly Stopwatch clock = new Stopwatch(), activationCleanup = new Stopwatch();
        uint pid, tid; int events, bytes; bool initialBreakpoint, exited, pending;
        DebugEvent current;
        IntPtr originalProcess, originalThread, processAlias, threadAlias, memoryProcess, lifetimeProcess;
        readonly System.Collections.Generic.Dictionary<IntPtr, string> modules = new System.Collections.Generic.Dictionary<IntPtr, string>();
        const uint Continue = 0x10002, NotHandled = 0x80010001;
        readonly bool nativeHardware, pythonSnaps, activationMode, moduleCallback;
        readonly EventCleanupLedger callbackFiles;
        int pythonStringEvents, requestedBytes;
        HardwareTrace hardware;
        ActivationBoundaryTrace activation;
        internal LoaderTrace(bool nativeSnaps = false, bool cloneSnaps = false, bool activationTrace = false, bool callback = false, string explicitEntryPython = null, string automaticResourcePython = null, bool dispatch = false, bool moduleDispatch = false)
        {
            if (moduleDispatch && !dispatch) throw new ArgumentException("module dispatch requires its fixed CSR role");
            if (dispatch && automaticResourcePython == null) throw new ArgumentException("dispatch requires the fixed process-scope role");
            if ((nativeSnaps ? 1 : 0) + (cloneSnaps ? 1 : 0) + (activationTrace ? 1 : 0) + (callback ? 1 : 0) + (explicitEntryPython != null ? 1 : 0) + (automaticResourcePython != null ? 1 : 0) > 1)
                throw new ArgumentException("diagnostic roles cannot overlap");
            nativeHardware = nativeSnaps; pythonSnaps = cloneSnaps; entryPython = explicitEntryPython; resourcePython = automaticResourcePython; dispatchMode = dispatch; moduleDispatchMode = moduleDispatch;
            activationMode = activationTrace || callback || EntryMode || ResourceMode; moduleCallback = callback;
            if (StrictEventOwnership) callbackFiles = new EventCleanupLedger();
            if (IntPtr.Size != 8 || Marshal.SizeOf(typeof(ExceptionRecord)) != 152 ||
                Marshal.SizeOf(typeof(ExceptionInfo)) != 160 || Marshal.OffsetOf(typeof(DebugEvent), "data").ToInt32() != 16 ||
                Marshal.SizeOf(typeof(DebugEvent)) != 176 || Marshal.SizeOf(typeof(CreateProcessInfo)) != 72 ||
                Marshal.SizeOf(typeof(LoadDllInfo)) != 40)
                throw new PlatformNotSupportedException("loader diagnostic requires verified Windows x64 debug-event ABI");
        }
        void ThreadCheck()
        {
            if (GetCurrentThreadId() != creator) throw new InvalidOperationException("loader diagnostic moved off its native creator thread");
        }
        internal void Arm(Native.ProcessInfo child)
        {
            ThreadCheck(); pid = child.pid; tid = child.tid;
            originalProcess = processAlias = child.process; originalThread = threadAlias = child.thread;
        }
        internal void SuppressOriginalAliases(ref Native.ProcessInfo child)
        {
            if (child.process == processAlias) child.process = IntPtr.Zero;
            if (child.thread == threadAlias) child.thread = IntPtr.Zero;
        }
        internal void PrepareHandles(ref Native.ProcessInfo child)
        {
            ThreadCheck();
            // Debug EXIT may close original creation aliases even when duplication fails.
            child.process = child.thread = IntPtr.Zero;
            IntPtr process = IntPtr.Zero, thread = IntPtr.Zero;
            try {
                Native.Check(DuplicateHandle(Native.GetCurrentProcess(), originalProcess, Native.GetCurrentProcess(),
                    out process, 0, false, 2), "duplicate retained loader diagnostic process handle");
                Native.Check(DuplicateHandle(Native.GetCurrentProcess(), originalThread, Native.GetCurrentProcess(),
                    out thread, 0, false, 2), "duplicate retained loader diagnostic thread handle");
                child.process = process; child.thread = thread; memoryProcess = lifetimeProcess = process; process = thread = IntPtr.Zero;
                if (nativeHardware) hardware = new HardwareTrace(child.process, child.thread, pid, tid, Emit);
                if (activationMode) activation = moduleDispatchMode ? ModuleActivationFixture.DispatchObserver(resourcePython, child, Emit, ResourceDeadline) :
                    ResourceMode ? SelfActivationFixture.ResourceObserver(resourcePython, child, Emit, ResourceDeadline, dispatchMode) :
                    EntryMode ? SelfActivationFixture.EntryObserver(entryPython, child, Emit) :
                    moduleCallback ? ModuleActivationFixture.Observer(child, Emit) : ChildActivationFixture.Observer(child, Emit);
            }
            finally {
                if (thread != IntPtr.Zero) Native.CloseHandle(thread);
                if (process != IntPtr.Zero) Native.CloseHandle(process);
            }
        }
        void CaptureCreationEvent()
        {
            ThreadCheck();
            while (!Receive()) {
                if (clock.Elapsed.TotalSeconds >= 10) throw new TimeoutException("loader diagnostic create-event deadline exceeded");
            }
            if (current.code != 3 || current.pid != pid || current.tid != tid)
                throw new InvalidOperationException("loader diagnostic first event is not the exact owned child creation");
            events++; // The initial CREATE counts toward the total 128-event diagnostic ceiling.
            IntPtr file = current.data.createProcess.file;
            if (activation != null) {
                ActivationEvent(() => {
                    Emit("phase=create creator_thread_verified=true image=" + Basename(file));
                    activation.Creation(file, current.data.createProcess.imageBase);
                }, () => { activation.Invalidate(); activation.Restore(); }, new Action[] {
                    () => ReleaseOriginal(ref originalProcess, current.data.createProcess.process),
                    () => ReleaseOriginal(ref originalThread, current.data.createProcess.thread), CloseCurrentFile }, null);
                return; // A failed CREATE is left pending for the outer termination/drain, never continued here.
            }
            try {
                // Retire original creation handles only when distinct from OS debug-event handles.
                ReleaseOriginal(ref originalProcess, current.data.createProcess.process);
                ReleaseOriginal(ref originalThread, current.data.createProcess.thread);
                Emit("phase=create creator_thread_verified=true image=" + Basename(file));
            }
            finally { current.data.createProcess.file = IntPtr.Zero; CloseFile(file); }
            // Gates were completed before resume; validate CREATE before allowing user-mode execution.
        }
        void ReleaseOriginal(ref IntPtr original, IntPtr osOwned)
        {
            if (StrictEventOwnership) {
                if (original == osOwned) { original = IntPtr.Zero; return; }
                callbackFiles.Close(ref original, handle => Native.Check(Native.CloseHandle(handle), "close distinct original creation handle"));
                return;
            }
            IntPtr value = original; original = IntPtr.Zero;
            if (value != IntPtr.Zero && value != osOwned) Native.Check(Native.CloseHandle(value), "close distinct original creation handle");
        }
        bool Receive(uint milliseconds = 100, bool cleanup = false)
        {
            ThreadCheck();
            if (pending) throw new InvalidOperationException("loader debug event was not continued");
            if (StrictEventOwnership && callbackFiles.Overflowed)
                throw new InvalidOperationException("callback event cleanup overflow prevents another receive");
            if (ResourceMode && activation != null) activation.ResourceClearEpoch();
            if (!WaitForDebugEventEx(out current, milliseconds)) {
                int error = Marshal.GetLastWin32Error();
                if (error == 121) return false;
                throw new System.ComponentModel.Win32Exception(error, "wait for owned loader event");
            }
            pending = true;
            if (hardware != null) hardware.Stop(current.pid, current.tid, current.code);
            if (activation != null) activation.Stop(current.pid, current.tid, current.code, StrictEventOwnership && cleanup);
            if (current.pid != pid) throw new InvalidOperationException("loader event is not from the fixed owned child");
            return true;
        }
        void ContinuePending(uint status)
        {
            ThreadCheck();
            if (!pending) return;
            Action continuation = () => Native.Check(ContinueDebugEvent(current.pid, current.tid, status), "continue exact owned loader event");
            if (ResourceMode) resourceContinuation.Run(continuation); else continuation();
            pending = false;
            if (hardware != null) hardware.Continued();
            if (activation != null) activation.Continued();
        }
        static bool TakeDebugString(bool native, bool clone, ref int pythonEvents)
        {
            if (native || clone) return true;
            if (pythonEvents != 0) return false;
            pythonEvents = 1;
            return true;
        }
        static void ChargeRead(ref int charged, int length)
        {
            if (length < 1 || length > 4096 || charged < 0 || charged > 65536 - length)
                throw new InvalidOperationException("fixed clone debug-string requested-byte ceiling exceeded");
            charged += length;
        }
        void ObserveNativeString()
        {
            if (!TakeDebugString(nativeHardware, pythonSnaps, ref pythonStringEvents)) {
                Emit("phase=debug-string observation=unknown event_limit=True content_read=False"); return;
            }
            DebugStringInfo info = current.data.debugString;
            if (info.text == IntPtr.Zero || info.bytes == 0 || info.bytes > 4096 || info.unicode > 1 ||
                (info.unicode == 1 && (info.bytes & 1) != 0)) {
                Emit("phase=debug-string observation=unknown format_valid=False");
                if (pythonSnaps) throw new InvalidOperationException("fixed clone debug-string span is unqualified");
                return;
            }
            if (pythonSnaps) ChargeRead(ref requestedBytes, info.bytes);
            byte[] bytes = new byte[info.bytes];
            try {
                UIntPtr read;
                bool copied = ReadProcessMemory(memoryProcess, info.text, bytes, new UIntPtr(info.bytes), out read);
                int error = copied ? 0 : Marshal.GetLastWin32Error();
                if (!copied || read.ToUInt64() != (ulong)bytes.Length) {
                    Emit("phase=debug-string observation=unknown read_success=" + copied + " native_error=" + error);
                    if (pythonSnaps) throw new InvalidOperationException("fixed clone debug-string transfer is incomplete");
                    return;
                }
                string classified = LoaderSnaps.Classify(bytes, info.unicode, !nativeHardware);
                Emit("phase=debug-string " + classified);
                if (pythonSnaps && classified == "phase=unknown format_valid=False")
                    throw new InvalidOperationException("fixed clone debug-string encoding is unqualified");
            }
            finally { Array.Clear(bytes, 0, bytes.Length); }
        }
        internal static bool AcceptInitialBreakpoint(uint eventThread, uint creatorThread, uint code, bool first, bool seen, Action requireComplete)
        {
            if (eventThread != creatorThread || code != 0x80000003 || !first || seen) return false;
            if (requireComplete != null) requireComplete();
            return true;
        }
        public static void CheckValidation()
        {
            int strings = 0;
            if (!TakeDebugString(false, false, ref strings) || strings != 1 || TakeDebugString(false, false, ref strings) || strings != 1 ||
                !TakeDebugString(true, false, ref strings) || strings != 1 || !TakeDebugString(false, true, ref strings) ||
                !TakeDebugString(false, true, ref strings))
                throw new InvalidOperationException("Python debug-string ceiling or fixed clone separation failed");
            int charged = 0;
            for (int index = 0; index < 16; index++) ChargeRead(ref charged, 4096);
            if (charged != 65536) throw new InvalidOperationException("clone read budget boundary differs");
            foreach (int invalid in new [] { 1, 4097, 0, -1 }) {
                bool rejected = false;
                try { ChargeRead(ref charged, invalid); } catch (InvalidOperationException) { rejected = true; }
                if (!rejected || charged != 65536) throw new InvalidOperationException("clone over-budget request was accepted");
            }
            charged = 0; ChargeRead(ref charged, 4096); // A failed transfer does not refund its request.
            ChargeRead(ref charged, 2);
            if (charged != 4098) throw new InvalidOperationException("clone read requests were not charged cumulatively");
            int qualified = 0;
            Action complete = () => qualified++;
            if (!AcceptInitialBreakpoint(11, 11, 0x80000003, true, false, complete) || qualified != 1)
                throw new InvalidOperationException("initial breakpoint did not qualify its completed observation");
            if (AcceptInitialBreakpoint(12, 11, 0x80000003, true, false, complete) ||
                AcceptInitialBreakpoint(11, 11, 0x80000004, true, false, complete) ||
                AcceptInitialBreakpoint(11, 11, 0x80000003, false, false, complete) ||
                AcceptInitialBreakpoint(11, 11, 0x80000003, true, true, complete) || qualified != 1)
                throw new InvalidOperationException("foreign, repeated or unsupported initial breakpoint was accepted");
            bool refused = false;
            try { AcceptInitialBreakpoint(11, 11, 0x80000003, true, false, () => { throw new InvalidOperationException("incomplete window"); }); }
            catch (InvalidOperationException) { refused = true; }
            if (!refused) throw new InvalidOperationException("initial breakpoint hid incomplete observation failure");
            if (!AcceptInitialBreakpoint(11, 11, 0x80000003, true, false, null))
                throw new InvalidOperationException("ordinary Python trace lost its initial breakpoint handling");
        }
        // Activation-only event finalization: no exception may erase an earlier operation or cleanup result.
        internal static void ActivationEvent(Action operation, Action restore, Action[] releases, Action continuation)
        {
            var failures = new System.Collections.Generic.List<Exception>();
            Action<Action> attempt = action => { try { action(); } catch (Exception failure) { failures.Add(failure); } };
            attempt(operation);
            bool restorationAttempted = failures.Count != 0;
            if (restorationAttempted) attempt(restore);
            foreach (Action release in releases) attempt(release);
            if (!restorationAttempted && failures.Count != 0) attempt(restore);
            if (continuation != null) attempt(continuation);
            if (failures.Count == 1) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failures[0]).Throw();
            if (failures.Count != 0) throw new AggregateException("fixed activation event operation/cleanup failed", failures);
        }
        internal static Exception CheckCallbackCleanupValidation()
        {
            var ledger = new EventCleanupLedger();
            IntPtr handle = new IntPtr(17); int calls = 0;
            var close = new InvalidOperationException("fixed event close"); Exception caught = null;
            try { ledger.Close(ref handle, value => { calls++; throw close; }); }
            catch (Exception failure) { caught = failure; }
            if (handle != IntPtr.Zero || ledger.Count != 1 || !Object.ReferenceEquals(caught, close) || calls != 1)
                throw new InvalidOperationException("callback close failure lost its ownership or primary error");
            handle = new IntPtr(17); bool refused = false;
            try { ledger.Close(ref handle, _ => calls++); } catch (InvalidOperationException) { refused = true; }
            if (!refused || calls != 1 || handle != IntPtr.Zero || ledger.Count != 1)
                throw new InvalidOperationException("callback uncertain close was retried");
            handle = new IntPtr(18); ledger.Close(ref handle, _ => calls++);
            if (calls != 2 || handle != IntPtr.Zero || ledger.Count != 1)
                throw new InvalidOperationException("callback later successful close erased unresolved ownership");
            Exception sticky = null;
            try { ledger.RequireClean(); } catch (Exception failure) { sticky = failure; }
            if (sticky == null) throw new InvalidOperationException("callback destruction erased a cleanup failure");
            var clean = new EventCleanupLedger(); handle = new IntPtr(19);
            clean.Close(ref handle, _ => calls++); clean.RequireClean();
            if (handle != IntPtr.Zero || clean.Count != 0) throw new InvalidOperationException("callback successful close retained ownership");
            var full = new EventCleanupLedger();
            for (int index = 0; index < 260; index++) {
                handle = new IntPtr(100 + index);
                try { full.Close(ref handle, _ => { throw close; }); } catch (InvalidOperationException) { }
            }
            handle = new IntPtr(400); refused = false;
            try { full.Close(ref handle, _ => calls++); } catch (InvalidOperationException) { refused = true; }
            if (!refused || !full.Overflowed || handle != new IntPtr(400) || full.Count != 260 || calls != 3)
                throw new InvalidOperationException("callback ownership overflow discarded an unresolved handle");
            return new AggregateException("fixed callback event cleanup remains unqualified", close, sticky);
        }
        internal static void CheckActivationEventValidation()
        {
            var primary = new InvalidOperationException("operation"); var restoration = new InvalidOperationException("restore");
            var close = new InvalidOperationException("close"); var continuation = new InvalidOperationException("continue");
            var attempts = new System.Collections.Generic.List<string>();
            AggregateException observed = null;
            try { ActivationEvent(() => { attempts.Add("operation"); throw primary; },
                () => { attempts.Add("restore"); throw restoration; },
                new Action[] { () => { attempts.Add("close"); throw close; }, () => attempts.Add("second-close") },
                () => { attempts.Add("continue"); throw continuation; }); }
            catch (AggregateException failure) { observed = failure; }
            if (observed == null || observed.InnerExceptions.Count != 4 ||
                !Object.ReferenceEquals(observed.InnerExceptions[0], primary) || !Object.ReferenceEquals(observed.InnerExceptions[1], restoration) ||
                !Object.ReferenceEquals(observed.InnerExceptions[2], close) || !Object.ReferenceEquals(observed.InnerExceptions[3], continuation) ||
                String.Join(",", attempts) != "operation,restore,close,second-close,continue")
                throw new InvalidOperationException("activation event lost ordered failures or skipped cleanup");
            attempts.Clear(); Exception single = null;
            try { ActivationEvent(() => { throw primary; }, () => attempts.Add("restore"),
                new Action[] { () => attempts.Add("close") }, null); }
            catch (Exception failure) { single = failure; }
            if (!Object.ReferenceEquals(single, primary) || String.Join(",", attempts) != "restore,close")
                throw new InvalidOperationException("activation CREATE failure was replaced or prematurely continued");
            attempts.Clear(); single = null;
            try { ActivationEvent(() => attempts.Add("operation"), () => attempts.Add("restore"),
                new Action[] { () => { attempts.Add("close"); throw close; }, () => attempts.Add("second-close") },
                () => attempts.Add("continue")); }
            catch (Exception failure) { single = failure; }
            if (!Object.ReferenceEquals(single, close) || String.Join(",", attempts) != "operation,close,second-close,restore,continue")
                throw new InvalidOperationException("activation close failure skipped restoration or continuation");
        }
        static uint RemainingActivationCleanup(long elapsed)
        {
            if (elapsed < 0) throw new InvalidOperationException("activation cleanup clock is invalid");
            return elapsed >= 5000 ? 0 : (uint)(5000 - elapsed);
        }
        internal uint RemainingActivationCleanup()
        {
            if (!activationMode || !activationCleanup.IsRunning)
                throw new InvalidOperationException("activation cleanup deadline was not started");
            return RemainingActivationCleanup(activationCleanup.ElapsedMilliseconds);
        }
        internal static void ConfirmActivationDestruction(bool exitReceived, bool eventPending, bool handlePresent, long elapsed,
            Func<uint, uint> wait, Action destroyed)
        {
            if (!exitReceived || eventPending || !handlePresent)
                throw new InvalidOperationException("activation destruction lacks continued EXIT or retained handle");
            uint result = wait(RemainingActivationCleanup(elapsed));
            int error = result == UInt32.MaxValue ? Marshal.GetLastWin32Error() : 0;
            if (result != 0) throw new InvalidOperationException("activation destruction wait did not signal wait_result=0x" +
                result.ToString("X8") + " native_error=" + error);
            destroyed();
        }
        internal static void CheckActivationDestructionValidation()
        {
            long[] elapsed = { 0, 1, 4999, 5000, 5001, Int64.MaxValue };
            uint[] expected = { 5000, 4999, 1, 0, 0, 0 };
            for (int index = 0; index < elapsed.Length; index++)
                if (RemainingActivationCleanup(elapsed[index]) != expected[index])
                    throw new InvalidOperationException("activation cleanup replenished its deadline");
            bool invalid = false;
            try { RemainingActivationCleanup(-1); } catch (InvalidOperationException) { invalid = true; }
            if (!invalid) throw new InvalidOperationException("activation cleanup accepted a negative clock");
            int called = 0; bool destroyed = false;
            ConfirmActivationDestruction(true, false, true, 4999, timeout => { called++; if (timeout != 1) throw new Exception("timeout differs"); return 0; }, () => destroyed = true);
            if (called != 1 || !destroyed) throw new InvalidOperationException("activation destruction did not wait for signaling");
            foreach (uint result in new uint[] { 258, UInt32.MaxValue, 128, 1 }) {
                destroyed = false; invalid = false;
                try { ConfirmActivationDestruction(true, false, true, 5000, timeout => result, () => destroyed = true); }
                catch (InvalidOperationException) { invalid = true; }
                if (!invalid || destroyed) throw new InvalidOperationException("activation destruction accepted a nonsignaled wait");
            }
            foreach (bool[] state in new [] { new [] {false,false,true}, new [] {true,true,true}, new [] {true,false,false} }) {
                called = 0; destroyed = false; invalid = false;
                try { ConfirmActivationDestruction(state[0], state[1], state[2], 0, timeout => { called++; return 0; }, () => destroyed = true); }
                catch (InvalidOperationException) { invalid = true; }
                if (!invalid || called != 0 || destroyed) throw new InvalidOperationException("activation destruction ignored its prerequisites");
            }
            int queries = 0, pauses = 0;
            Sandbox.AwaitActivationJobZero(() => ++queries < 3 ? 1U : 0U,
                () => queries == 1 ? 21U : 1U,
                milliseconds => { if (milliseconds != (pauses++ == 0 ? 20 : 1)) throw new Exception("job remainder differs"); });
            if (queries != 3 || pauses != 2) throw new InvalidOperationException("activation Job-zero was not qualified");
            invalid = false;
            try { Sandbox.AwaitActivationJobZero(() => 1U, () => 0U, _ => { throw new Exception("expired pause"); }); }
            catch (InvalidOperationException) { invalid = true; }
            if (!invalid) throw new InvalidOperationException("activation Job-zero replenished its deadline");
            Sandbox.AwaitActivationJobZero(() => 0U, () => { throw new Exception("zero job waited"); }, _ => { throw new Exception("zero job paused"); });
        }
        void ObserveActivationEvent()
        {
            uint status = current.code == 1 ? NotHandled : Continue;
            ActivationEvent(() => {
                events++;
                switch (current.code) {
                    case 1:
                        uint code = current.data.exception.record.code;
                        bool first = current.data.exception.firstChance != 0;
                        activation.Event(current.tid, code, first);
                        if (!activation.SingleStep(current.tid, code, first, current.data.exception.record.address) &&
                            !activation.AcceptSoftware(current.tid, code, first))
                            throw new InvalidOperationException("fixed activation diagnostic encountered an unexpected exception");
                        status = Continue; break;
                    case 6:
                        activation.Load(current.data.loadDll.file, current.data.loadDll.imageBase);
                        Emit("phase=activation-load-event module=" + Basename(current.data.loadDll.file)); break;
                    case 5:
                        exited = true;
                        Emit("phase=activation-exit code=0x" + current.data.exit.code.ToString("X8")); break;
                    case 7:
                        activation.Unload(current.data.unloadDll.imageBase); break;
                    case 8:
                        Emit("phase=activation-debug-string content_read=False"); break;
                    case 2: case 4:
                        activation.OtherThread(); break;
                    default:
                        throw new InvalidOperationException("fixed activation diagnostic received an unsupported event");
                }
            }, () => { activation.Invalidate(); activation.Restore(); }, new Action[] { CloseCurrentFile }, () => ContinuePending(status));
        }
        internal uint Observe()
        {
            ThreadCheck();
            if (clock.IsRunning || events != 0) throw new InvalidOperationException("loader observation may start only once");
            clock.Start();
            CaptureCreationEvent();
            ContinuePending(Continue);
            while (!exited) {
                if (clock.Elapsed.TotalSeconds >= 10 || events >= 128)
                    throw new TimeoutException("loader diagnostic event/time ceiling exceeded");
                if (!Receive()) continue;
                uint status = current.code == 1 ? NotHandled : Continue;
                if (activation != null) {
                    if (ResourceMode) ObserveResourceEvent(false, new Action[] { CloseCurrentFile });
                    else if (EntryMode) ObserveEntryEvent(); else ObserveActivationEvent();
                    continue;
                }
                try {
                    events++;
                    switch (current.code) {
                        case 1:
                            uint code = current.data.exception.record.code;
                            bool first = current.data.exception.firstChance != 0;
                            if (hardware != null && hardware.SingleStep(current.tid, code, first)) {
                                status = Continue; break;
                            }
                            Action qualify = hardware == null ? null : new Action(hardware.RequireComplete);
                            if (AcceptInitialBreakpoint(current.tid, tid, code, first, initialBreakpoint, qualify)) {
                                initialBreakpoint = true; status = Continue;
                            }
                            else if (hardware != null) { hardware.Invalidate(); hardware.Restore(); }
                            Emit("phase=exception code=0x" + code.ToString("X8") + " first_chance=" + first
                                + " initial_breakpoint_seen=" + initialBreakpoint);
                            break;
                        case 6:
                            IntPtr file = current.data.loadDll.file;
                            try {
                                if (hardware != null) hardware.Load(file, current.data.loadDll.imageBase);
                                string name = Basename(file);
                                if (modules.Count >= 128) throw new InvalidOperationException("loader module metadata exceeds finite bound");
                                modules[current.data.loadDll.imageBase] = name;
                                Emit("phase=load-dll module=" + name);
                            }
                            finally { current.data.loadDll.file = IntPtr.Zero; CloseFile(file); }
                            break;
                        case 5:
                            Emit("phase=exit code=0x" + current.data.exit.code.ToString("X8")
                                + " initial_breakpoint_seen=" + initialBreakpoint);
                            exited = true; break;
                        case 9:
                            if (hardware != null) { hardware.Invalidate(); hardware.Restore(); }
                            Emit("phase=rip error=" + current.data.rip.error + " type=" + current.data.rip.type); break;
                        case 7:
                            if (hardware != null) hardware.Unload(current.data.unloadDll.imageBase);
                            string unloaded;
                            Emit("phase=unload-dll module=" + (modules.TryGetValue(current.data.unloadDll.imageBase, out unloaded) ? unloaded : "unavailable"));
                            modules.Remove(current.data.unloadDll.imageBase); break;
                        case 8:
                            ObserveNativeString(); break;
                        case 2: case 4:
                            if (hardware != null) hardware.OtherThread(current.tid, current.code);
                            Emit("phase=event kind=" + current.code); break; // no strings, pointers or remote reads.
                        default: throw new InvalidOperationException("unexpected owned loader event kind");
                    }
                }
                catch (Exception failure) {
                    try { if (hardware != null) hardware.Restore(); }
                    catch (Exception restoration) { throw new AggregateException("hardware observation and restoration failed", failure, restoration); }
                    throw;
                }
                finally { try { CloseCurrentFile(); } finally { ContinuePending(status); } }
            }
            if (hardware != null) hardware.RequireComplete();
            if (activation != null) activation.RequireComplete();
            return current.data.exit.code;
        }
        internal static void RequireCallbackEventProcess(uint actual, uint expected)
        {
            if (actual != expected) throw new InvalidOperationException("callback cleanup event is not from the fixed owned child");
        }
        internal static void DrainCallbackEvents(Func<bool> hasExited, Func<bool> hasPending, Func<uint> remaining,
            Func<uint, bool> receive, Action finish)
        {
            if (hasPending()) finish();
            int count = 0;
            while (!hasExited() && remaining() != 0 && count < 128) {
                if (hasPending()) throw new InvalidOperationException("callback cleanup event was not continued");
                if (!receive(Math.Min(100U, remaining()))) continue;
                count++; finish();
            }
            if (!hasExited() || hasPending())
                throw new TimeoutException("owned callback EXIT drain exceeded finite cleanup ceiling");
        }
        internal void TerminateAndDrain(IntPtr job, Native.ProcessInfo child)
        {
            ThreadCheck(); memoryProcess = IntPtr.Zero; // Borrowed read reference; never own/close the duplicated process here.
            if (activationMode && !activationCleanup.IsRunning) activationCleanup.Start();
            var failures = new System.Collections.Generic.List<Exception>();
            // Context access is legal only while an already-pending event stops the live creator.
            if (pending && hardware != null) {
                try { hardware.Restore(); } catch (Exception failure) { failures.Add(failure); }
            }
            if (pending && activation != null) {
                try {
                    if (StrictEventOwnership) RequireCallbackEventProcess(current.pid, pid);
                    activation.Restore();
                } catch (Exception failure) { failures.Add(failure); }
            }
            if (!exited) {
                IntPtr process = child.process != IntPtr.Zero ? child.process : originalProcess;
                try { if (process != IntPtr.Zero) Native.Check(Native.TerminateProcess(process, 125), "terminate owned debug child including pre-assignment failures"); }
                catch (Exception error) { failures.Add(error); }
                try { Native.Check(Native.TerminateJobObject(job, 125), "terminate owned loader diagnostic before event drain"); }
                catch (Exception error) { failures.Add(error); }
            }
            // Termination failures must not abandon a pending event or the bounded EXIT drain.
            try {
                if (StrictEventOwnership) {
                    DrainCallbackEvents(() => exited, () => pending, RemainingActivationCleanup,
                        milliseconds => Receive(milliseconds, true), () => FinishCleanupEvent(failures));
                } else {
                    if (pending) FinishCleanupEvent(failures);
                    var cleanup = activationMode ? activationCleanup : Stopwatch.StartNew(); int count = 0;
                    while (!exited && cleanup.Elapsed.TotalSeconds < 5 && count < 128) {
                        if (!Receive(activationMode ? Math.Min(100U, RemainingActivationCleanup()) : 100U)) continue;
                        count++;
                        FinishCleanupEvent(failures);
                    }
                    if (!exited) failures.Add(new TimeoutException("owned loader EXIT drain exceeded finite cleanup ceiling"));
                }
                if (originalProcess != IntPtr.Zero || originalThread != IntPtr.Zero)
                    failures.Add(new InvalidOperationException("loader creation-handle ownership was not resolved"));
            }
            catch (Exception error) { failures.Add(error); }
            if (StrictEventOwnership) {
                try { callbackFiles.RequireClean(); } catch (Exception failure) { failures.Add(failure); }
            }
            if (failures.Count != 0) throw new AggregateException("owned loader cleanup failed", failures);
        }
        internal void ConfirmDestroyed()
        {
            if (activation != null) {
                if (!activationCleanup.IsRunning) throw new InvalidOperationException("activation cleanup deadline was not started");
                ConfirmActivationDestruction(exited, pending, lifetimeProcess != IntPtr.Zero, activationCleanup.ElapsedMilliseconds,
                    milliseconds => Native.WaitForSingleObject(lifetimeProcess, milliseconds), () => {
                        activation.Destroyed();
                        if (ResourceMode) resourceContinuation.RequireClean();
                    });
                return;
            }
            // Caller has reaped the Job to zero; the independent duplicate must already be signaled.
            bool present = lifetimeProcess != IntPtr.Zero;
            uint wait = exited && present ? Native.WaitForSingleObject(lifetimeProcess, 0) : UInt32.MaxValue;
            int error = exited && present && wait == UInt32.MaxValue ? Marshal.GetLastWin32Error() : 0;
            if (!exited || !present || wait != 0)
                throw new InvalidOperationException("hardware destruction requires continued EXIT and a signaled retained process"
                    + " exited=" + exited + " handle_present=" + present + " wait_result=0x" + wait.ToString("X8")
                    + " native_error=" + error);
            if (hardware != null) hardware.Destroyed();
            if (activation != null) activation.Destroyed();
        }
        void FinishCleanupEvent(System.Collections.Generic.List<Exception> failures)
        {
            if (StrictEventOwnership) RequireCallbackEventProcess(current.pid, pid);
            if (activation != null) {
                if (ResourceMode) {
                    try { activation.Stop(current.pid, current.tid, current.code, true); ObserveResourceEvent(true, new Action[] {
                        () => { if (current.code == 3) ReleaseOriginal(ref originalProcess, current.data.createProcess.process); },
                        () => { if (current.code == 3) ReleaseOriginal(ref originalThread, current.data.createProcess.thread); }, CloseCurrentFile }); }
                    catch (Exception failure) { failures.Add(failure); }
                    return;
                }
                if (EntryMode) {
                    try { FinalizeEntryEvent(activation, current.code, IntPtr.Zero, true, () => { }, () => exited = true, new Action[] {
                        () => { if (current.code == 3) ReleaseOriginal(ref originalProcess, current.data.createProcess.process); },
                        () => { if (current.code == 3) ReleaseOriginal(ref originalThread, current.data.createProcess.thread); }, CloseCurrentFile }, ContinuePending); }
                    catch (Exception failure) { failures.Add(failure); }
                    return;
                }
                try {
                    ActivationEvent(() => { if (current.code == 5) exited = true; },
                        () => { activation.Invalidate(); activation.Restore(); }, new Action[] {
                            () => { if (current.code == 3) ReleaseOriginal(ref originalProcess, current.data.createProcess.process); },
                            () => { if (current.code == 3) ReleaseOriginal(ref originalThread, current.data.createProcess.thread); },
                            CloseCurrentFile }, () => ContinuePending(current.code == 1 ? NotHandled : Continue));
                }
                catch (Exception failure) { failures.Add(failure); }
                return;
            }
            try {
                if (current.code == 3) {
                    try { ReleaseOriginal(ref originalProcess, current.data.createProcess.process); }
                    finally { ReleaseOriginal(ref originalThread, current.data.createProcess.thread); }
                }
                if (current.code == 5) exited = true;
            }
            catch (Exception error) { failures.Add(error); }
            finally {
                try { CloseCurrentFile(); }
                catch (Exception error) { failures.Add(error); }
                finally { ContinuePending(current.code == 1 ? NotHandled : Continue); }
            }
        }
        void CloseCurrentFile()
        {
            if (StrictEventOwnership) {
                if (current.code == 3) callbackFiles.Close(ref current.data.createProcess.file, CloseFile);
                if (current.code == 6) callbackFiles.Close(ref current.data.loadDll.file, CloseFile);
                return;
            }
            if (current.code == 3) { IntPtr file = current.data.createProcess.file; current.data.createProcess.file = IntPtr.Zero; CloseFile(file); }
            if (current.code == 6) { IntPtr file = current.data.loadDll.file; current.data.loadDll.file = IntPtr.Zero; CloseFile(file); }
        }
        static void CloseFile(IntPtr file)
        {
            if (file != IntPtr.Zero && file != Native.InvalidHandle) Native.Check(Native.CloseHandle(file), "close owned loader image/DLL event file");
        }
        static string Basename(IntPtr file)
        {
            if (file == IntPtr.Zero || file == Native.InvalidHandle) return "unavailable";
            var path = new StringBuilder(1024);
            uint length = GetFinalPathNameByHandleW(file, path, (uint)path.Capacity, 0);
            if (length == 0 || length >= path.Capacity) return "unavailable";
            string name = Path.GetFileName(path.ToString());
            var safe = new StringBuilder();
            foreach (char value in name) {
                if (safe.Length >= 128) break;
                safe.Append(value >= 32 && value <= 126 && value != '\\' && value != '/' ? value : '_');
            }
            return safe.Length == 0 ? "unavailable" : safe.ToString();
        }
        void Emit(string metadata)
        {
            string line = "WINDOWS_LOADER_TRACE " + metadata;
            int size = Encoding.UTF8.GetByteCount(line) + 1;
            if (bytes + size > 65536) throw new InvalidOperationException("loader metadata exceeds 64 KiB ceiling");
            bytes += size; Console.Out.WriteLine(line); Console.Out.Flush();
        }
    }
}
