using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace ScientificSecurity
{
    // Fixed trusted pass-code phase evidence only. Never an admission result or arbitrary debugger.
    internal sealed class LoaderTrace
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
        readonly Stopwatch clock = new Stopwatch();
        uint pid, tid; int events, bytes; bool initialBreakpoint, exited, pending;
        DebugEvent current;
        IntPtr originalProcess, originalThread, processAlias, threadAlias, memoryProcess, lifetimeProcess;
        readonly System.Collections.Generic.Dictionary<IntPtr, string> modules = new System.Collections.Generic.Dictionary<IntPtr, string>();
        const uint Continue = 0x10002, NotHandled = 0x80010001;
        readonly bool readNativeStrings;
        HardwareTrace hardware;
        internal LoaderTrace(bool nativeSnaps = false)
        {
            readNativeStrings = nativeSnaps;
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
                if (readNativeStrings) hardware = new HardwareTrace(child.process, child.thread, pid, tid, Emit);
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
            try {
                // Retire original creation handles only when distinct from OS debug-event handles.
                ReleaseOriginal(ref originalProcess, current.data.createProcess.process);
                ReleaseOriginal(ref originalThread, current.data.createProcess.thread);
                Emit("phase=create creator_thread_verified=true image=" + Basename(file));
            }
            finally { current.data.createProcess.file = IntPtr.Zero; CloseFile(file); }
            // Gates were completed before resume; validate CREATE before allowing user-mode execution.
        }
        static void ReleaseOriginal(ref IntPtr original, IntPtr osOwned)
        {
            IntPtr handle = original; original = IntPtr.Zero;
            if (handle != IntPtr.Zero && handle != osOwned) Native.Check(Native.CloseHandle(handle), "close distinct original creation handle");
        }
        bool Receive()
        {
            ThreadCheck();
            if (pending) throw new InvalidOperationException("loader debug event was not continued");
            if (!WaitForDebugEventEx(out current, 100)) {
                int error = Marshal.GetLastWin32Error();
                if (error == 121) return false;
                throw new System.ComponentModel.Win32Exception(error, "wait for owned loader event");
            }
            pending = true;
            if (hardware != null) hardware.Stop(current.pid, current.tid, current.code);
            if (current.pid != pid) throw new InvalidOperationException("loader event is not from the fixed owned child");
            return true;
        }
        void ContinuePending(uint status)
        {
            ThreadCheck();
            if (!pending) return;
            Native.Check(ContinueDebugEvent(current.pid, current.tid, status), "continue exact owned loader event");
            pending = false;
            if (hardware != null) hardware.Continued();
        }
        void ObserveNativeString()
        {
            if (!readNativeStrings) { Emit("phase=debug-string content_read=False"); return; }
            DebugStringInfo info = current.data.debugString;
            if (info.text == IntPtr.Zero || info.bytes == 0 || info.bytes > 4096 || info.unicode > 1 ||
                (info.unicode == 1 && (info.bytes & 1) != 0)) {
                Emit("phase=debug-string observation=unknown format_valid=False"); return;
            }
            byte[] bytes = new byte[info.bytes];
            try {
                UIntPtr read;
                bool copied = ReadProcessMemory(memoryProcess, info.text, bytes, new UIntPtr(info.bytes), out read);
                int error = copied ? 0 : Marshal.GetLastWin32Error();
                if (!copied || read.ToUInt64() != (ulong)bytes.Length) {
                    Emit("phase=debug-string observation=unknown read_success=" + copied + " native_error=" + error); return;
                }
                Emit("phase=debug-string " + LoaderSnaps.Classify(bytes, info.unicode));
            }
            finally { Array.Clear(bytes, 0, bytes.Length); }
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
                try {
                    events++;
                    switch (current.code) {
                        case 1:
                            uint code = current.data.exception.record.code;
                            bool first = current.data.exception.firstChance != 0;
                            if (hardware != null && hardware.SingleStep(current.tid, code, first)) {
                                status = Continue; break;
                            }
                            if (hardware != null) hardware.Restore();
                            if (!initialBreakpoint && first && code == 0x80000003) {
                                initialBreakpoint = true; status = Continue;
                            }
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
            return current.data.exit.code;
        }
        internal void TerminateAndDrain(IntPtr job, Native.ProcessInfo child)
        {
            ThreadCheck(); memoryProcess = IntPtr.Zero; // Borrowed read reference; never own/close the duplicated process here.
            var failures = new System.Collections.Generic.List<Exception>();
            // Context access is legal only while an already-pending event stops the live creator.
            if (pending && hardware != null) {
                try { hardware.Restore(); } catch (Exception failure) { failures.Add(failure); }
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
                if (pending) FinishCleanupEvent(failures);
                var cleanup = Stopwatch.StartNew(); int count = 0;
                while (!exited && cleanup.Elapsed.TotalSeconds < 5 && count < 128) {
                    if (!Receive()) continue;
                    count++;
                    FinishCleanupEvent(failures);
                }
                if (!exited) failures.Add(new TimeoutException("owned loader EXIT drain exceeded finite cleanup ceiling"));
                if (originalProcess != IntPtr.Zero || originalThread != IntPtr.Zero)
                    failures.Add(new InvalidOperationException("loader creation-handle ownership was not resolved"));
            }
            catch (Exception error) { failures.Add(error); }
            if (failures.Count != 0) throw new AggregateException("owned loader cleanup failed", failures);
        }
        internal void ConfirmDestroyed()
        {
            // Caller has reaped the Job to zero; the independent duplicate must already be signaled.
            bool present = lifetimeProcess != IntPtr.Zero;
            uint wait = exited && present ? Native.WaitForSingleObject(lifetimeProcess, 0) : UInt32.MaxValue;
            int error = exited && present && wait == UInt32.MaxValue ? Marshal.GetLastWin32Error() : 0;
            if (!exited || !present || wait != 0)
                throw new InvalidOperationException("hardware destruction requires continued EXIT and a signaled retained process"
                    + " exited=" + exited + " handle_present=" + present + " wait_result=0x" + wait.ToString("X8")
                    + " native_error=" + error);
            if (hardware != null) hardware.Destroyed();
        }
        void FinishCleanupEvent(System.Collections.Generic.List<Exception> failures)
        {
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
