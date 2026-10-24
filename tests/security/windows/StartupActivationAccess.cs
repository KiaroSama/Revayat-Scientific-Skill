using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace ScientificSecurity
{
    // One fixed operation comparison, not a child-loader identity or causality certificate.
    public static partial class StartupActivationAccess
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct ActCtx {
            internal uint size, flags;
            [MarshalAs(UnmanagedType.LPWStr)] internal string source;
            internal ushort architecture, language;
            [MarshalAs(UnmanagedType.LPWStr)] internal string assemblyDirectory;
            internal IntPtr resource;
            [MarshalAs(UnmanagedType.LPWStr)] internal string application;
            internal IntPtr module;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CreateActCtxW(ref ActCtx context);
        [DllImport("kernel32.dll")] static extern void ReleaseActCtx(IntPtr context);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool DuplicateTokenEx(
            IntPtr token, uint access, IntPtr attributes, int level, int kind, out IntPtr duplicate);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool ImpersonateLoggedOnUser(IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool RevertToSelf();
        static ActCtx Fixed(string python, ushort language)
        {
            return new ActCtx { size = 56, flags = 0x2E, source = python, language = language,
                assemblyDirectory = Path.GetDirectoryName(python), resource = new IntPtr(1), application = python };
        }
        static string Outcome(string context, IntPtr handle, uint error)
        {
            bool success = handle != Native.InvalidHandle;
            if (handle == IntPtr.Zero || (success && error != 0))
                throw new InvalidOperationException("activation context result/handle is inconsistent");
            return "WINDOWS_STARTUP_ACTIVATION context=" + context + " resource_type=24 resource_id=1 created=" + success +
                " win32_error=" + error + " activated=False child_equivalence_claimed=False cause_claimed=False";
        }
        internal static void Attempt(List<Exception> failures, Action action)
        { try { action(); } catch (Exception failure) { failures.Add(failure); } }
        internal static void Finish(Exception primary, List<Exception> failures)
        {
            if (failures.Count == 0) return;
            if (primary != null) failures.Insert(0, primary);
            throw new AggregateException("fixed activation operation/cleanup failed", failures);
        }
        internal static void FinalizeComparison(Exception primary, bool impersonating, Func<bool> revert, Action failFast, Action emit, params Action[] cleanup)
        {
            if (impersonating) {
                bool reverted;
                try { reverted = revert(); }
                catch { failFast(); throw; }
                if (!reverted) {
                    failFast();
                    throw new InvalidOperationException("activation identity restoration did not terminate");
                }
            }
            var failures = new List<Exception>();
            foreach (Action action in cleanup) Attempt(failures, action);
            Attempt(failures, emit);
            Finish(primary, failures);
        }
        static void Deadline(Stopwatch clock)
        { if (clock.Elapsed.TotalSeconds > 10) throw new TimeoutException("fixed activation comparison exceeded 10 seconds"); }
        internal static int Observe(Native.ProcessInfo child, string python, string package)
        {
            CheckValidation();
            using (WindowsIdentity current = WindowsIdentity.GetCurrent(true))
                if (current != null) throw new InvalidOperationException("activation host is already impersonating");
            if (!String.Equals(Path.GetFileName(python), "python.exe", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("activation comparison requires the fixed prepared Python");
            NativeFixture.Plain(python);
            foreach (string path in new [] { python + ".manifest", Path.ChangeExtension(python, ".manifest"),
                python + ".config", Path.ChangeExtension(python, ".config") }) {
                NativeFixture.Plain(path, true);
                try { File.GetAttributes(path); }
                catch (FileNotFoundException) { continue; }
                catch (DirectoryNotFoundException) { continue; }
                throw new InvalidOperationException("activation comparison has an external override collision");
            }
            FileStream held = null; IntPtr token = IntPtr.Zero, duplicate = IntPtr.Zero;
            bool impersonating = false; Exception primary = null;
            var lines = new List<string>(); var clock = Stopwatch.StartNew();
            try {
                held = new FileStream(python, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (held.Length < 256 || held.Length > 16777216) throw new InvalidOperationException("activation image exceeds bound");
                byte[] bytes = new byte[(int)held.Length]; int offset = 0;
                Tuple<ushort, uint> manifest;
                try {
                    while (offset < bytes.Length) {
                        int count = held.Read(bytes, offset, Math.Min(65536, bytes.Length - offset));
                        if (count == 0) throw new InvalidOperationException("activation image is truncated");
                        offset += count;
                    }
                    manifest = KernelImage.PythonManifest(bytes);
                }
                finally { Array.Clear(bytes, 0, bytes.Length); }
                lines.Add("WINDOWS_STARTUP_MANIFEST resource_type=24 resource_id=1 language=" + manifest.Item1 + " bytes=" + manifest.Item2);
                var assemblyPaths = new List<Tuple<string, string>>();
                StartupRegistryAccess.Observe("host", lines, () => Deadline(clock), () => { });
                bool host = ObserveOne("host", python, manifest.Item1, lines, clock, assemblyPaths);
                if (!host) throw new InvalidOperationException("host activation-context positive control failed");
                ActivationAssemblyAccess.OpenFiles("host", assemblyPaths, lines, () => Deadline(clock)); Deadline(clock);
                Native.Check(Native.OpenProcessToken(child.process, 0xA, out token), "open exact activation primary token");
                Native.Check(DuplicateTokenEx(token, 0xC, IntPtr.Zero, 2, 2, out duplicate), "duplicate exact activation token");
                var context = new RegistryContext(token, duplicate, package);
                Native.Check(ImpersonateLoggedOnUser(duplicate), "enter exact activation LPAC context");
                impersonating = true; context.RequireThread();
                int registryStatus = StartupRegistryAccess.Observe("lpac", lines, () => Deadline(clock), context.RequireThread);
                ObserveOne("lpac", python, manifest.Item1, lines, clock, null);
                context.RequireThread(); Deadline(clock);
                ActivationAssemblyAccess.OpenFiles("lpac", assemblyPaths, lines, () => Deadline(clock));
                context.RequireThread(); Deadline(clock);
                return registryStatus;
            }
            catch (Exception failure) { primary = failure; throw; }
            finally {
                FinalizeComparison(primary, impersonating, RevertToSelf,
                    () => Environment.FailFast("Activation identity restoration failed; outer owner must reap and clean up."),
                    () => { foreach (string line in lines) Console.Out.WriteLine(line); Console.Out.Flush(); },
                    () => { if (duplicate != IntPtr.Zero) Native.Check(Native.CloseHandle(duplicate), "close activation duplicate token"); },
                    () => { if (token != IntPtr.Zero) Native.Check(Native.CloseHandle(token), "close activation primary token"); },
                    () => { if (held != null) held.Dispose(); });
            }
        }
        internal static void PreparePython(Native.ProcessInfo child, string python, string package, PythonActivationPreparation.Observation observation)
        {
            PythonActivationPreparation.Need(observation != null && observation.experiment == PythonActivationPreparation.Experiment.Token); observation.RequireFresh();
            ushort language = PythonCsrDispatch.PreparedLanguage(python);
            using (WindowsIdentity current = WindowsIdentity.GetCurrent(true))
                if (current != null) throw new InvalidOperationException("Python preparation host is already impersonating");
            IntPtr token = IntPtr.Zero, duplicate = IntPtr.Zero; bool impersonating = false;
            Exception primary = null; var lines = new List<string>(); var clock = Stopwatch.StartNew();
            try {
                Native.Check(Native.OpenProcessToken(child.process, 0xA, out token), "open exact Python preparation primary token");
                Native.Check(DuplicateTokenEx(token, 0xC, IntPtr.Zero, 2, 2, out duplicate), "duplicate exact Python preparation token");
                var context = new RegistryContext(token, duplicate, package);
                Native.Check(ImpersonateLoggedOnUser(duplicate), "enter exact Python preparation LPAC context");
                impersonating = true;
                PythonActivationPreparation.Prepare(observation, context.RequireThread, () => Deadline(clock),
                    () => ChildDefaultDacl.Read(token), () => ChildDefaultDacl.Read(duplicate),
                    () => ObserveOne("lpac", python, language, lines, clock, null));
            }
            catch (Exception failure) { primary = failure; throw; }
            finally {
                FinalizeComparison(primary, impersonating, RevertToSelf,
                    () => Environment.FailFast("Python preparation identity restoration failed; outer owner must reap and clean up."),
                    () => {
                        PythonActivationPreparation.Need(lines.Count == (observation.attempted ? 1 : 0));
                        if (observation.prepared && observation.attempted) observation.Activation(lines[0]);
                    },
                    () => { if (duplicate != IntPtr.Zero) Native.Check(Native.CloseHandle(duplicate), "close Python preparation duplicate token"); },
                    () => { if (token != IntPtr.Zero) Native.Check(Native.CloseHandle(token), "close Python preparation primary token"); });
            }
        }
        static bool ObserveOne(string label, string python, ushort language, List<string> lines, Stopwatch clock, List<Tuple<string, string>> assemblyPaths)
        {
            Deadline(clock); ActCtx context = Fixed(python, language);
            IntPtr handle = CreateActCtxW(ref context);
            uint error = handle == Native.InvalidHandle ? unchecked((uint)Marshal.GetLastWin32Error()) : 0;
            try {
                lines.Add(Outcome(label, handle, error)); Deadline(clock);
                if (assemblyPaths != null && handle != Native.InvalidHandle)
                    assemblyPaths.AddRange(ActivationAssemblyAccess.Query(handle, python, lines));
                Deadline(clock); return handle != Native.InvalidHandle;
            }
            finally { if (handle != Native.InvalidHandle && handle != IntPtr.Zero) ReleaseActCtx(handle); }
        }
        static void CheckFinalization()
        {
            var order = new List<string>(); var lines = new List<string> { "fixed buffered metadata" };
            bool reverted = false;
            FinalizeComparison(null, true, () => { order.Add("revert"); reverted = true; return true; },
                () => { throw new InvalidOperationException("unexpected fail-fast"); },
                () => { if (!reverted || lines.Count != 1) throw new InvalidOperationException("output preceded reversion"); order.Add(lines[0]); },
                () => order.Add("first cleanup"), () => order.Add("second cleanup"));
            if (String.Join(",", order) != "revert,first cleanup,second cleanup,fixed buffered metadata")
                throw new InvalidOperationException("activation finalization order differs");
            var fatal = new IOException("fixed fail-fast");
            foreach (bool throws in new [] { false, true }) {
                order.Clear(); Exception caught = null;
                try {
                    FinalizeComparison(null, true, () => { order.Add("revert"); if (throws) throw new IOException("fixed revert failure"); return false; },
                        () => { order.Add("fail-fast"); throw fatal; }, () => order.Add("emit"), () => order.Add("cleanup"));
                }
                catch (Exception failure) { caught = failure; }
                if (!Object.ReferenceEquals(caught, fatal) || String.Join(",", order) != "revert,fail-fast")
                    throw new InvalidOperationException("failed reversion allowed finalization");
            }
            order.Clear(); bool refused = false;
            try { FinalizeComparison(null, true, () => false, () => order.Add("fail-fast"), () => order.Add("emit"), () => order.Add("cleanup")); }
            catch (InvalidOperationException) { refused = true; }
            if (!refused || String.Join(",", order) != "fail-fast") throw new InvalidOperationException("returning fail-fast allowed output");
            var primary = new IOException("fixed operation"); var cleanup = new IOException("fixed cleanup"); var reporting = new IOException("fixed reporting");
            foreach (bool impersonating in new [] { false, true }) {
                order.Clear(); AggregateException caught = null;
                try {
                    FinalizeComparison(primary, impersonating, () => { order.Add("revert"); return true; },
                        () => { throw fatal; }, () => { order.Add("emit"); throw reporting; },
                        () => { order.Add("first cleanup"); throw cleanup; }, () => order.Add("second cleanup"));
                }
                catch (AggregateException failure) { caught = failure; }
                if (caught == null || caught.InnerExceptions.Count != 3 || !Object.ReferenceEquals(caught.InnerExceptions[0], primary) ||
                    !Object.ReferenceEquals(caught.InnerExceptions[1], cleanup) || !Object.ReferenceEquals(caught.InnerExceptions[2], reporting) ||
                    String.Join(",", order) != (impersonating ? "revert," : "") + "first cleanup,second cleanup,emit")
                    throw new InvalidOperationException("activation finalization lost ordered failures");
            }
        }
        public static void CheckValidation()
        {
            if (IntPtr.Size != 8 || Marshal.SizeOf(typeof(ActCtx)) != 56)
                throw new InvalidOperationException("activation context requires Windows x64 ABI");
            string[] fields = { "size", "flags", "source", "architecture", "language", "assemblyDirectory", "resource", "application", "module" };
            int[] offsets = { 0, 4, 8, 16, 18, 24, 32, 40, 48 };
            for (int index = 0; index < fields.Length; index++)
                if (Marshal.OffsetOf(typeof(ActCtx), fields[index]).ToInt32() != offsets[index])
                    throw new InvalidOperationException("activation context field offset differs");
            var value = Fixed(Path.Combine(Path.GetTempPath(), "python.exe"), 1033);
            if (value.flags != 0x2E || value.size != 56 || value.language != 1033 || value.architecture != 0 ||
                value.module != IntPtr.Zero || value.resource != new IntPtr(1) || value.application != value.source ||
                value.assemblyDirectory != Path.GetDirectoryName(value.source)) throw new InvalidOperationException("activation fixed call contract differs");
            if (Outcome("lpac", Native.InvalidHandle, 5) != "WINDOWS_STARTUP_ACTIVATION context=lpac resource_type=24 resource_id=1 created=False win32_error=5 activated=False child_equivalence_claimed=False cause_claimed=False" ||
                !Outcome("host", new IntPtr(1), 0).Contains("created=True win32_error=0"))
                throw new InvalidOperationException("activation result formatting differs");
            bool refused = false;
            try { Outcome("host", IntPtr.Zero, 0); } catch (InvalidOperationException) { refused = true; }
            if (!refused) throw new InvalidOperationException("activation null result was accepted");
            CheckFinalization();
            var primary = new IOException("fixed primary"); var cleanup = new IOException("fixed cleanup");
            var failures = new List<Exception>(); int attempts = 0;
            Attempt(failures, () => { attempts++; throw cleanup; }); Attempt(failures, () => attempts++);
            try { Finish(primary, failures); }
            catch (AggregateException failure) {
                if (attempts == 2 && failure.InnerExceptions.Count == 2 && Object.ReferenceEquals(failure.InnerExceptions[0], primary) &&
                    Object.ReferenceEquals(failure.InnerExceptions[1], cleanup)) return;
                throw;
            }
            throw new InvalidOperationException("activation cleanup failure was hidden");
        }
    }
}
