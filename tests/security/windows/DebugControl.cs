using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace ScientificSecurity
{
    // One fixed trusted-host observation. Never launches reviewed code or changes LPAC policy.
    public static class DebugControl
    {
        const uint Continue = 0x10002, NotHandled = 0x80010001;
        [StructLayout(LayoutKind.Sequential)] struct ExceptionRecord {
            internal uint code, flags; internal IntPtr nested, address; internal uint count;
            internal ulong p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12, p13, p14;
        }
        [StructLayout(LayoutKind.Sequential)] struct ExceptionInfo { internal ExceptionRecord record; internal uint first; }
        [StructLayout(LayoutKind.Sequential)] struct Creation {
            internal IntPtr file, process, thread, imageBase; internal uint offset, size;
            internal IntPtr localBase, start, imageName; internal ushort unicode;
        }
        [StructLayout(LayoutKind.Sequential)] struct ThreadCreation { internal IntPtr thread, localBase, start; }
        [StructLayout(LayoutKind.Sequential)] struct Load {
            internal IntPtr file, imageBase; internal uint offset, size; internal IntPtr name; internal ushort unicode;
        }
        [StructLayout(LayoutKind.Sequential)] struct Exit { internal uint code; }
        [StructLayout(LayoutKind.Explicit, Size = 160)] struct Data {
            [FieldOffset(0)] internal ExceptionInfo exception;
            [FieldOffset(0)] internal Creation create;
            [FieldOffset(0)] internal ThreadCreation thread;
            [FieldOffset(0)] internal Load load;
            [FieldOffset(0)] internal Exit exit;
        }
        [StructLayout(LayoutKind.Sequential)] struct Event { internal uint kind, pid, tid; internal Data data; }
        [StructLayout(LayoutKind.Sequential)] struct Region {
            internal IntPtr address, allocation; internal uint protection; internal ushort partition;
            internal UIntPtr bytes; internal uint state, access, type;
        }
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool WaitForDebugEventEx(out Event value, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool ContinueDebugEvent(uint pid, uint tid, uint status);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool DuplicateHandle(IntPtr source, IntPtr handle,
            IntPtr destination, out IntPtr duplicate, uint access, bool inherit, uint options);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetFinalPathNameByHandleW(IntPtr file, StringBuilder path, uint length, uint flags);
        [DllImport("kernel32.dll", SetLastError = true)] static extern UIntPtr VirtualQueryEx(IntPtr process, IntPtr address,
            out Region region, UIntPtr length);

        public static void CheckValidation()
        {
            DebugContext.CheckTrapValidation();
            NativeFixture.CheckDebugControlValidation();
            Sandbox.CheckCleanupValidation();
            bool requested = false; int attempts = 0;
            RequestTermination(ref requested, () => attempts++);
            RequestTermination(ref requested, () => attempts++);
            Need(requested && attempts == 1, "fixed control repeated a successful termination request");
            requested = false; attempts = 0;
            var expectedFailure = new InvalidOperationException("fixed termination failure");
            Exception observedFailure = null;
            try { RequestTermination(ref requested, () => { attempts++; throw expectedFailure; }); }
            catch (Exception failure) { observedFailure = failure; }
            Need(!requested && attempts == 1 && Object.ReferenceEquals(observedFailure, expectedFailure),
                "fixed control lost a failed termination request");
            RequestTermination(ref requested, () => attempts++);
            Need(requested && attempts == 2, "fixed control did not retry a failed termination request");
            var before = new byte[1232]; var after = (byte[])before.Clone();
            Put(after, 104, 0xFFFE0FF1); Put(after, 112, 0x401);
            string metadata = Status("fixture", before, after);
            if (!metadata.Contains("dr6_actual=0x00000000FFFE0FF1") || !metadata.Contains("raw_debug_equal=False") ||
                !DebugContext.UnchangedControlInteger(before, after) || metadata.Length > 512)
                throw new InvalidOperationException("fixed debugger-control status fixture failed");
            Put(after, 152, 0x123456789ABCDEF0);
            if (DebugContext.UnchangedControlInteger(before, after) || Status("fixture", before, after).Contains("123456789ABCDEF0"))
                throw new InvalidOperationException("fixed debugger-control metadata exposed an address or accepted context mutation");
        }
        static ulong U64(byte[] bytes, int offset) { return BitConverter.ToUInt64(bytes, offset); }
        static void Put(byte[] bytes, int offset, ulong value) { BitConverter.GetBytes(value).CopyTo(bytes, offset); }
        static bool DebugEqual(byte[] expected, byte[] actual)
        {
            return DebugContext.RawDebugEqual(expected, actual);
        }
        static string Status(string stage, byte[] expected, byte[] actual)
        {
            return "stage=" + stage + " dr6_expected=0x" + U64(expected, 104).ToString("X16")
                + " dr6_actual=0x" + U64(actual, 104).ToString("X16")
                + " dr7_expected=0x" + U64(expected, 112).ToString("X16")
                + " dr7_actual=0x" + U64(actual, 112).ToString("X16")
                + " classic_cause=0x" + (U64(actual, 104) & 0xE00FUL).ToString("X16")
                + " raw_debug_equal=" + DebugEqual(expected, actual)
                + " control_integer_unchanged=" + DebugContext.UnchangedControlInteger(expected, actual);
        }
        static void RequestTermination(ref bool requested, Action terminate)
        {
            if (requested) return;
            terminate();
            requested = true;
        }
        static void Need(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
        static void Attempt(List<Exception> failures, Action action)
        { try { action(); } catch (Exception failure) { failures.Add(failure); } }

        public static void RunFixed(string run, string state)
        {
            CheckValidation();
            Need(IntPtr.Size == 8 && Marshal.SizeOf(typeof(Event)) == 176 && Marshal.SizeOf(typeof(Region)) == 48,
                "fixed debugger control requires the verified Windows x64 ABI");
            Need(state != null && run != null && run.Length == 32 && run.All(c => (c >= 'a' && c <= 'f') || (c >= '0' && c <= '9')) &&
                Path.IsPathFullyQualified(state) && Path.GetFileName(Path.TrimEndingDirectorySeparator(state)) == "security-windows-" + run,
                "fixed debugger control requires this run's owned state");
            state = Path.GetFullPath(state); NativeFixture.Plain(state);
            string executable = Path.Combine(state, "python", "debug-control-native.exe");
            uint site = NativeFixture.DebugControlSiteFromFile(executable);
            using (var owner = new Owner(executable, state, site)) owner.Run();
        }
        sealed class Owner : IDisposable
        {
            readonly string executable, state;
            readonly uint site;
            readonly int ownerThread = Environment.CurrentManagedThreadId;
            readonly Stopwatch observation = new Stopwatch(), cleanup = new Stopwatch();
            readonly List<IntPtr> allocations = new List<IntPtr>(), standard = new List<IntPtr>();
            Capture output, error;
            Native.ProcessInfo child;
            IntPtr job, attributes, environment, originalProcess, originalThread, processAlias, threadAlias;
            bool duplicatesRetained, terminationRequested;
            Event current;
            bool pending, started, exited, live = true, changed, hit, creation, initialBreakpoint;
            byte[] saved;
            ulong breakpoint;
            int events, emitted;
            Exception primary;
            internal Owner(string image, string directory, uint rva) { executable = image; state = directory; site = rva; }
            void Emit(string message)
            {
                string line = "WINDOWS_DEBUG_CONTROL " + message + "\n";
                emitted += Encoding.UTF8.GetByteCount(line); Need(emitted <= 65536, "fixed debug-control output exceeded 64 KiB");
                Console.Out.Write(line); Console.Out.Flush();
            }
            void ThreadCheck() { Need(Environment.CurrentManagedThreadId == ownerThread, "fixed debug-control event owner thread changed"); }
            bool Receive(uint milliseconds)
            {
                ThreadCheck(); Need(!pending, "fixed debug-control event is already pending");
                if (!WaitForDebugEventEx(out current, milliseconds)) {
                    int code = Marshal.GetLastWin32Error();
                    if (code == 121 || code == 258) return false;
                    throw new System.ComponentModel.Win32Exception(code, "receive fixed debugger-control event");
                }
                pending = true; Need(current.pid == child.pid, "fixed debugger-control event belongs to another process");
                if (current.kind == 5 || (current.kind == 4 && current.tid == child.tid)) live = false;
                return true;
            }
            void ContinueEvent(uint status)
            {
                if (!pending) return;
                Native.Check(ContinueDebugEvent(current.pid, current.tid, status), "continue fixed debugger-control event"); pending = false;
            }
            byte[] Read()
            { Need(pending && live, "fixed debug-control context requires a stopped live creator"); return DebugContext.Read(child.thread); }
            void Write(byte[] before, byte[] desired, string stage)
            {
                Need(pending && live, "fixed debug-control context write requires a stopped live creator");
                BitConverter.GetBytes(0x100010U).CopyTo(desired, 48); changed = true;
                DebugContext.Write(child.thread, desired); byte[] after = Read();
                Emit(Status(stage, desired, after)); // Observe raw OS normalization BEFORE strict rejection.
                Need(DebugContext.UnchangedControlInteger(before, after) && DebugEqual(desired, after),
                    "fixed debug-control raw context readback is inconclusive");
            }
            void Restore()
            {
                if (!changed || saved == null || !pending || !live) return;
                byte[] before = Read(), desired = (byte[])before.Clone();
                for (int offset = 72; offset <= 112; offset += 8) Put(desired, offset, U64(saved, offset));
                Write(before, desired, "restore-readback"); changed = false;
            }
            void Creation()
            {
                Need(!creation && current.kind == 3 && current.tid == child.tid, "fixed control creation event is ambiguous");
                creation = true;
                try {
                    var path = new StringBuilder(512);
                    uint length = GetFinalPathNameByHandleW(current.data.create.file, path, 512, 0);
                    Need(length > 0 && length < 512, "fixed control image handle provenance is unavailable");
                    string actual = path.ToString(); if (actual.StartsWith(@"\\?\", StringComparison.Ordinal)) actual = actual.Substring(4);
                    Need(String.Equals(actual, executable, StringComparison.OrdinalIgnoreCase), "fixed control image is not the owned executable");
                    Need(NativeFixture.DebugControlSiteFromFile(actual) == site, "fixed control site changed since qualification");
                    ulong image = unchecked((ulong)current.data.create.imageBase.ToInt64());
                    Need(image > 0 && image <= 0x7FFFFFFFFFFFFFFFUL - site, "fixed control site address overflows"); breakpoint = image + site;
                    Region region; UIntPtr size = new UIntPtr((uint)Marshal.SizeOf(typeof(Region)));
                    Need(VirtualQueryEx(child.process, new IntPtr((long)breakpoint), out region, size).ToUInt64() == size.ToUInt64(),
                        "fixed control image region query is unavailable");
                    ulong regionStart = unchecked((ulong)region.address.ToInt64()), regionLength = region.bytes.ToUInt64();
                    Need(breakpoint >= regionStart && breakpoint - regionStart <= regionLength &&
                        6UL <= regionLength - (breakpoint - regionStart) && region.state == 0x1000 && region.type == 0x1000000 && region.allocation == current.data.create.imageBase &&
                        (region.access & 0x100) == 0 && new uint[] { 0x10, 0x20, 0x40, 0x80 }.Contains(region.access & 0xFF),
                        "fixed control site is not a committed executable image span");
                    saved = Read(); Emit("site_bytes_qualified=True transaction_context=unknown launch_context=trusted_host " + Status("baseline", saved, saved));
                    for (int offset = 72; offset <= 96; offset += 8) Need(U64(saved, offset) == 0, "fixed control refuses occupied debug addresses");
                    Need((U64(saved, 112) & 0xFFFF2BFFUL) == 0 && (U64(saved, 104) & 0xE00FUL) == 0,
                        "fixed control refuses pre-existing debug control/cause");
                    byte[] desired = (byte[])saved.Clone(); Put(desired, 72, breakpoint); Put(desired, 112, U64(saved, 112) | 1);
                    Write(saved, desired, "arm-readback");
                }
                finally {
                    try { CloseFile(ref current.data.create.file); }
                    finally {
                        try { ReleaseOriginal(ref originalProcess, current.data.create.process); }
                        finally { ReleaseOriginal(ref originalThread, current.data.create.thread); }
                    }
                }
            }
            void Exception()
            {
                uint code = current.data.exception.record.code;
                if (code == 0x80000003 && current.data.exception.first != 0 && current.tid == child.tid && !hit && !initialBreakpoint) {
                    initialBreakpoint = true; return;
                } // Ordinary initial loader breakpoint, at most once.
                Need(code == 0x80000004 && current.data.exception.first != 0 && current.tid == child.tid && !hit,
                    "fixed debugger control observed an unexpected exception/thread");
                byte[] context = Read();
                Emit("stage=known-site-event " + DebugContext.TrapQualifiers(U64(context, 104))
                    + " raw_dr7=0x" + U64(context, 112).ToString("X16") + " setter_readback_claimed=False");
                Need(DebugContext.OwnedTrapSite(current.tid, child.tid, current.data.exception.first != 0,
                    (U64(context, 112) & 1) != 0, U64(context, 248), breakpoint) && U64(context, 72) == breakpoint && (U64(context, 104) & 0xE00FUL) == 1,
                    "fixed debugger-control B0 cannot be paired to the qualified site");
                for (int offset = 80; offset <= 96; offset += 8)
                    Need(U64(context, offset) == U64(saved, offset), "fixed debugger-control unowned address changed");
                Need(DebugContext.OwnedTrapStatus(U64(context, 104), U64(context, 112), U64(saved, 112) | 1, 0),
                    "fixed debugger-control observed an unsupported or foreign owned-trap qualifier");
                hit = true; Restore();
                Emit("known_site_b0=True " + DebugContext.TrapQualifiers(U64(context, 104)) + " normalization_approved=False");
            }
            internal void Run()
            {
                try {
                    observation.Start(); Setup();
                    if (Native.ResumeThread(child.thread) == UInt32.MaxValue) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "resume fixed host debugger control");
                    output.CloseWriter(); error.CloseWriter();
                    foreach (IntPtr handle in standard) Native.Check(Native.CloseHandle(handle), "close fixed control inherited standard handle"); standard.Clear();
                    while (!exited) {
                        Need(observation.Elapsed.TotalSeconds < 10 && events < 128, "fixed debugger-control event/time bound exceeded");
                        if (!Receive(100)) continue; events++;
                        uint status = current.kind == 1 ? NotHandled : Continue;
                        var eventFailures = new List<Exception>();
                        try {
                            if (current.kind == 3) Creation();
                            else if (current.kind == 1) { Exception(); status = Continue; }
                            else if (current.kind == 2 || current.kind == 4) throw new InvalidOperationException("fixed debugger control observed another thread transition");
                            else if (current.kind == 5) { exited = true; Need(hit && current.data.exit.code == 0, "fixed debugger-control did not complete its qualified site/exit"); }
                            // No debug-string/remote-memory reads; unrelated events are not evidence.
                        }
                        catch (Exception failure) {
                            eventFailures.Add(failure); Attempt(eventFailures, Restore); Attempt(eventFailures, Terminate);
                        }
                        finally {
                            Attempt(eventFailures, CloseEventFile);
                            Attempt(eventFailures, () => ContinueEvent(status));
                        }
                        if (eventFailures.Count != 0) throw new AggregateException("fixed control event/cleanup failed", eventFailures);
                    }
                    uint exit; uint remaining = (uint)Math.Max(0, 10000 - observation.ElapsedMilliseconds);
                    Need(Native.WaitForSingleObject(child.process, remaining) == 0, "fixed debugger control exit is not signaled within observation bound");
                    Native.Check(Native.GetExitCodeProcess(child.process, out exit), "read fixed control exit");
                    Need(exit == 0, "fixed debugger control exit differs from expected value");
                    Need(String.IsNullOrWhiteSpace(output.Read()) && String.IsNullOrWhiteSpace(error.Read()), "fixed debugger control emitted unexpected application output");
                }
                catch (Exception failure) {
                    primary = failure;
                    try { Emit("outcome=inconclusive normalization_approved=False"); }
                    catch (Exception logging) { primary = new AggregateException("fixed control observation/output failed", failure, logging); throw primary; }
                    throw;
                }
            }
            void Setup()
            {
                job = Native.CreateJobObject(IntPtr.Zero, null); Native.Check(job != IntPtr.Zero, "create fixed host-control job");
                var limits = new Native.ExtendedLimits(); limits.basic.flags = 0x2000 | 0x200 | 0x100 | 8 | 4;
                limits.basic.processes = 8; limits.basic.jobTime = 30L * 10000000; limits.processMemory = new UIntPtr(384UL * 1024 * 1024); limits.jobMemory = new UIntPtr(512UL * 1024 * 1024);
                Native.SetJob(job, 9, limits); Native.SetJob(job, 15, new Native.CpuLimits { flags = 5, rate = 1000 });
                Native.ExtendedLimits actual = Native.QueryJob<Native.ExtendedLimits>(job, 9);
                Native.CpuLimits cpu = Native.QueryJob<Native.CpuLimits>(job, 15);
                Need(actual.basic.flags == limits.basic.flags && actual.basic.processes == 8 &&
                    actual.processMemory == limits.processMemory && actual.jobMemory == limits.jobMemory &&
                    actual.basic.jobTime == limits.basic.jobTime && cpu.flags == 5 && cpu.rate == 1000,
                    "fixed control Job limits differ from required finite values");
                IntPtr size = IntPtr.Zero; Native.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
                Need(size != IntPtr.Zero, "fixed control handle-attribute size is unavailable"); attributes = Marshal.AllocHGlobal(size);
                Native.Check(Native.InitializeProcThreadAttributeList(attributes, 1, 0, ref size), "initialize fixed control handle attributes");
                output = new Capture(); error = new Capture(); var sa = new Native.SecurityAttributes { size = (uint)Marshal.SizeOf(typeof(Native.SecurityAttributes)), inherit = 1 };
                IntPtr input = Native.CreateFileW("NUL", 0x80000000, 3, ref sa, 3, 0x80, IntPtr.Zero);
                Native.Check(input != Native.InvalidHandle, "open fixed control stdin"); standard.Add(input);
                IntPtr list = Marshal.AllocHGlobal(3 * IntPtr.Size); allocations.Add(list);
                Marshal.WriteIntPtr(list, input); Marshal.WriteIntPtr(list, IntPtr.Size, output.Writer); Marshal.WriteIntPtr(list, 2 * IntPtr.Size, error.Writer);
                Native.Check(Native.UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x20002), list, new IntPtr(3 * IntPtr.Size), IntPtr.Zero, IntPtr.Zero), "bind fixed control three handles");
                string temp = Path.Combine(state, "control-temp"); NativeFixture.Plain(temp, true);
                Need(!Directory.Exists(temp) && !File.Exists(temp), "fixed control temp directory already exists"); Directory.CreateDirectory(temp);
                var env = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
                    { "SystemRoot", Environment.GetFolderPath(Environment.SpecialFolder.Windows) }, { "TEMP", temp }, { "TMP", temp }
                };
                environment = Marshal.StringToHGlobalUni(String.Join("\0", env.Select(pair => pair.Key + "=" + pair.Value)) + "\0\0");
                var startup = new Native.StartupEx(); startup.startup.cb = (uint)Marshal.SizeOf(typeof(Native.StartupEx)); startup.startup.flags = 0x100;
                startup.startup.input = input; startup.startup.output = output.Writer; startup.startup.error = error.Writer; startup.attributes = attributes;
                Native.Check(Native.CreateProcessW(executable, new StringBuilder(TrustedSetup.Quote(executable)), IntPtr.Zero, IntPtr.Zero, true,
                    Native.ExtendedStartup | Native.Suspended | Native.UnicodeEnvironment | Native.NoWindow | 2, environment, Path.GetDirectoryName(executable), ref startup, out child),
                    "create fixed suspended host debugger control"); started = true;
                originalProcess = processAlias = child.process; originalThread = threadAlias = child.thread;
                Native.Check(Native.AssignProcessToJobObject(job, child.process), "assign fixed control job before resume");
                IntPtr process = IntPtr.Zero, thread = IntPtr.Zero;
                try {
                    Native.Check(DuplicateHandle(Native.GetCurrentProcess(), originalProcess, Native.GetCurrentProcess(), out process, 0, false, 2), "retain fixed control process duplicate");
                    Native.Check(DuplicateHandle(Native.GetCurrentProcess(), originalThread, Native.GetCurrentProcess(), out thread, 0, false, 2), "retain fixed control creator duplicate");
                    child.process = process; child.thread = thread; process = thread = IntPtr.Zero; duplicatesRetained = true;
                }
                finally {
                    try { if (thread != IntPtr.Zero) Native.Check(Native.CloseHandle(thread), "close failed fixed control thread duplicate"); }
                    finally { if (process != IntPtr.Zero) Native.Check(Native.CloseHandle(process), "close failed fixed control process duplicate"); }
                }
            }
            void Terminate()
            {
                var failures = new List<Exception>();
                Attempt(failures, () => {
                    if (started && !exited) RequestTermination(ref terminationRequested,
                        () => Native.Check(Native.TerminateProcess(child.process, 125), "terminate fixed debug control"));
                });
                Attempt(failures, () => { if (job != IntPtr.Zero) Native.Check(Native.TerminateJobObject(job, 125), "terminate fixed debug-control job"); });
                if (failures.Count != 0) throw new AggregateException("fixed control termination failed", failures);
            }
            static void CloseFile(ref IntPtr file) { IntPtr handle = file; file = IntPtr.Zero; if (handle != IntPtr.Zero && handle != Native.InvalidHandle) Native.Check(Native.CloseHandle(handle), "close fixed control event image"); }
            void CloseEventFile() { if (current.kind == 3) CloseFile(ref current.data.create.file); else if (current.kind == 6) CloseFile(ref current.data.load.file); }
            static void ReleaseOriginal(ref IntPtr original, IntPtr eventHandle)
            { IntPtr handle = original; original = IntPtr.Zero; if (handle != IntPtr.Zero && handle != eventHandle) Native.Check(Native.CloseHandle(handle), "close fixed control non-debug alias"); }
            public void Dispose()
            {
                var failures = new List<Exception>(); cleanup.Start();
                Attempt(failures, ThreadCheck);
                Attempt(failures, Restore); Attempt(failures, Terminate);
                if (pending) Attempt(failures, () => {
                    try {
                        if (current.kind == 3) {
                            try { ReleaseOriginal(ref originalProcess, current.data.create.process); }
                            finally { ReleaseOriginal(ref originalThread, current.data.create.thread); }
                        }
                        if (current.kind == 5) exited = true;
                    }
                    finally { try { CloseEventFile(); } finally { ContinueEvent(current.kind == 1 ? NotHandled : Continue); } }
                });
                int drained = 0;
                while (started && !exited && !pending && cleanup.Elapsed.TotalSeconds < 5 && drained < 128) {
                    bool received;
                    try { received = Receive(100); }
                    catch (Exception failure) { failures.Add(failure); break; }
                    if (!received) continue; drained++;
                    Attempt(failures, () => {
                        try {
                            if (current.kind == 3) {
                                try { ReleaseOriginal(ref originalProcess, current.data.create.process); }
                                finally { ReleaseOriginal(ref originalThread, current.data.create.thread); }
                            }
                            if (current.kind == 5) exited = true;
                        } finally { try { CloseEventFile(); } finally { ContinueEvent(current.kind == 1 ? NotHandled : Continue); } }
                    });
                }
                Attempt(failures, () => {
                    if (started) {
                        uint remaining = (uint)Math.Max(0, 5000 - cleanup.ElapsedMilliseconds);
                        Need(exited && duplicatesRetained && Native.WaitForSingleObject(child.process, remaining) == 0,
                            "fixed control destruction requires EXIT and a signaled independent duplicate");
                    }
                    if (job != IntPtr.Zero) Need(Native.QueryJob<Native.Accounting>(job, 1).activeProcesses == 0, "fixed control job still has processes");
                    if (started) Emit("state_destroyed=True normalization_approved=False");
                });
                if (saved != null) Array.Clear(saved, 0, saved.Length);
                Attempt(failures, () => { if (output != null) output.Dispose(); }); Attempt(failures, () => { if (error != null) error.Dispose(); });
                // OS debug aliases can be auto-closed by EXIT; only independent duplicates are closed here.
                Attempt(failures, () => { if (child.thread != IntPtr.Zero && child.thread != threadAlias) Native.Check(Native.CloseHandle(child.thread), "close fixed control thread duplicate"); });
                Attempt(failures, () => { if (child.process != IntPtr.Zero && child.process != processAlias) Native.Check(Native.CloseHandle(child.process), "close fixed control process duplicate"); });
                foreach (IntPtr handle in standard) Attempt(failures, () => Native.Check(Native.CloseHandle(handle), "close fixed control stdin"));
                Attempt(failures, () => { if (attributes != IntPtr.Zero) { try { Native.DeleteProcThreadAttributeList(attributes); } finally { Marshal.FreeHGlobal(attributes); } } });
                foreach (IntPtr allocation in allocations) Attempt(failures, () => Marshal.FreeHGlobal(allocation));
                Attempt(failures, () => { if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment); });
                Attempt(failures, () => { if (job != IntPtr.Zero) Native.Check(Native.CloseHandle(job), "close fixed control job"); });
                if (failures.Count != 0) { if (primary != null) failures.Insert(0, primary); throw new AggregateException("fixed debug control and cleanup failed", failures); }
            }
        }
    }
}
