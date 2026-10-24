using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace ScientificSecurity
{
    // Fixed CI preparation tools only; never used to launch reviewed code.
    public static partial class TrustedSetup
    {
        public static string Run(string executable, string[] arguments, string cwd)
        { return RunFixed(executable, arguments, cwd, false); }
        internal static string RunSelfActivation(string python, SelfActivationRole role = SelfActivationRole.Original)
        {
            string executable = SelfActivationFixture.PreparedImage(python, role);
            return RunFixed(executable, new string[0], Path.GetDirectoryName(executable), true, role);
        }
        internal static string RunExplicitEntry(string python, Action<string> retainMetadata)
        {
            string image = SelfActivationFixture.PreparedImage(python, SelfActivationRole.ExplicitId2);
            return RunFixed(image, new string[0], Path.GetDirectoryName(image), true, SelfActivationRole.ExplicitId2, python, retainMetadata);
        }
        internal static string RunAutomaticResource(string python, Action<string> retainMetadata)
        {
            string image = SelfActivationFixture.PreparedImage(python, SelfActivationRole.ExplicitId2);
            return RunFixed(image, new string[0], Path.GetDirectoryName(image), true, SelfActivationRole.ExplicitId2, python, retainMetadata, true);
        }
        internal static string RunCsrDispatch(string python, Action<string> retainMetadata)
        {
            string image = SelfActivationFixture.PreparedImage(python, SelfActivationRole.ExplicitId2);
            return RunFixed(image, new string[0], Path.GetDirectoryName(image), true, SelfActivationRole.ExplicitId2,
                python, retainMetadata, true, dispatch: true);
        }
        internal static string RunModuleCsrDispatch(string python, Action<string> retainMetadata)
        {
            string image = ModuleActivationFixture.PreparedImage(python, true);
            return RunFixed(image, new string[0], Path.GetDirectoryName(image), true,
                entryPython: python, retainMetadata: retainMetadata, resource: true, dispatch: true, moduleDispatch: true);
        }
        internal static string RunDllRequest(string python)
        {
            string image = ChildActivationFixture.DllPreparedImage(python);
            return RunFixed(image, new string[0], Path.GetDirectoryName(image), false, dllRequest: true);
        }
        static string RunFixed(string executable, string[] arguments, string cwd, bool selfActivation, SelfActivationRole role = SelfActivationRole.Original, string entryPython = null, Action<string> retainMetadata = null, bool resource = false, bool dllRequest = false, bool dispatch = false, bool moduleDispatch = false, bool pythonDispatch = false)
        {
            SelfActivationFixture.RequireKnownRole(role);
            if (pythonDispatch && (!dispatch || !resource || !selfActivation || moduleDispatch || dllRequest ||
                role != SelfActivationRole.Original || entryPython == null || retainMetadata == null))
                throw new ArgumentException("Python CSR host requires its separate fixed role");
            if (moduleDispatch && (!dispatch || !resource || !selfActivation || dllRequest || role != SelfActivationRole.Original || entryPython == null || retainMetadata == null))
                throw new ArgumentException("module CSR host requires its separate fixed role");
            if (dispatch && !resource) throw new ArgumentException("dispatch host requires fixed resource transport");
            if (dllRequest) {
                ChildActivationFixture.RequireDllRole(true, selfActivation, role != SelfActivationRole.Original, entryPython != null, resource, retainMetadata != null);
                RequireDllLaunch(executable, arguments, cwd);
                selfActivation = true; // Reuse the same strict fixed-diagnostic process/cleanup limits.
            }
            if (resource && entryPython == null || entryPython != null && (!selfActivation || role != (moduleDispatch || pythonDispatch ? SelfActivationRole.Original : SelfActivationRole.ExplicitId2) || retainMetadata == null) ||
                entryPython == null && retainMetadata != null) throw new ArgumentException("entry host requires fixed ExplicitId2 metadata retention");
            if (!Path.IsPathFullyQualified(executable) || !Path.IsPathFullyQualified(cwd))
                throw new ArgumentException("trusted setup requires fully qualified executable and working directory");
            executable = Path.GetFullPath(executable);
            cwd = Path.GetFullPath(cwd);
            string name = Path.GetFileName(executable).ToLowerInvariant();
            bool compilerPreparation = new [] { "cl.exe", "link.exe", "vswhere.exe", "dumpbin.exe", "rc.exe" }.Contains(name);
            if (role != SelfActivationRole.Original && !selfActivation) throw new ArgumentException("activation role requires the fixed internal launch");
            if (pythonDispatch) PythonCsrDispatch.RequireLaunch(executable, arguments, cwd);
            else if (moduleDispatch) RequireModuleDispatchLaunch(executable, arguments, cwd);
            else if (selfActivation && !dllRequest) RequireSelfLaunch(executable, arguments, cwd, role);
            if (compilerPreparation || selfActivation) { NativeFixture.Plain(executable); NativeFixture.Plain(cwd); }
            if (!selfActivation && !compilerPreparation && !new [] { "git.exe", "icacls.exe", "fsutil.exe", "csc.exe", "pwsh.exe" }.Contains(name))
                throw new ArgumentException("unsupported trusted CI preparation tool");
            bool executableExists = File.Exists(executable), cwdExists = Directory.Exists(cwd);
            Console.Out.WriteLine(name == "dumpbin.exe" || selfActivation ?
                "WINDOWS_SETUP_PATH tool=" + name + " executable_exists=" + executableExists + " cwd_exists=" + cwdExists :
                "WINDOWS_SETUP_PATH executable=" + Quote(executable) + " cwd=" + Quote(cwd)
                + " executable_exists=" + executableExists + " cwd_exists=" + cwdExists);
            Console.Out.Flush();
            if (!executableExists || !cwdExists)
                throw new ArgumentException("trusted setup executable or working directory does not exist after native path normalization");
            IntPtr job = IntPtr.Zero, attrs = IntPtr.Zero;
            IntPtr list = IntPtr.Zero, input = IntPtr.Zero, environment = IntPtr.Zero;
            Capture output = null, error = null;
            var child = new Native.ProcessInfo(); bool started = false, resumed = false;
            Exception primaryFailure = null;
            var clock = new Stopwatch();
            LoaderTrace loader = entryPython == null ? null : new LoaderTrace(false, false, false, false, resource ? null : entryPython, resource ? entryPython : null, dispatch, moduleDispatch, pythonDispatch);
            try
            {
                EmitStage(name, "prepare");
                job = Native.CreateJobObject(IntPtr.Zero, null); Native.Check(job != IntPtr.Zero, "create trusted setup job");
                var limits = new Native.ExtendedLimits();
                limits.basic.flags = 0x2000 | 8 | 4; limits.basic.processes = selfActivation ? 1U : 16U;
                limits.basic.jobTime = (selfActivation ? 10L : 60L) * 10000000L;
                if (selfActivation) {
                    limits.basic.flags |= 0x200 | 0x100;
                    limits.processMemory = new UIntPtr(384UL * 1024 * 1024);
                    limits.jobMemory = new UIntPtr(512UL * 1024 * 1024);
                }
                Native.SetJob(job, 9, limits);
                if (selfActivation) {
                    Native.SetJob(job, 15, new Native.CpuLimits { flags = 5, rate = 1000 });
                    var actual = Native.QueryJob<Native.ExtendedLimits>(job, 9);
                    var cpu = Native.QueryJob<Native.CpuLimits>(job, 15);
                    if (actual.basic.flags != limits.basic.flags || actual.basic.processes != 1 || actual.basic.jobTime != limits.basic.jobTime ||
                        actual.processMemory != limits.processMemory || actual.jobMemory != limits.jobMemory || cpu.flags != 5 || cpu.rate != 1000)
                        throw new InvalidOperationException("fixed host activation Job limits differ");
                }
                output = new Capture(selfActivation); error = new Capture(selfActivation);
                var sa = new Native.SecurityAttributes { size = (uint)Marshal.SizeOf(typeof(Native.SecurityAttributes)), inherit = 1 };
                input = Native.CreateFileW("NUL", 0x80000000, 3, ref sa, 3, 0x80, IntPtr.Zero);
                Native.Check(input != Native.InvalidHandle, "open trusted setup stdin");
                IntPtr bytes = IntPtr.Zero; Native.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref bytes);
                if (bytes == IntPtr.Zero) throw new InvalidOperationException("setup attribute size unavailable");
                attrs = Marshal.AllocHGlobal(bytes);
                Native.Check(Native.InitializeProcThreadAttributeList(attrs, 1, 0, ref bytes), "initialize setup attributes");
                list = Marshal.AllocHGlobal(3 * IntPtr.Size);
                Marshal.WriteIntPtr(list, 0, input); Marshal.WriteIntPtr(list, IntPtr.Size, output.Writer);
                Marshal.WriteIntPtr(list, 2 * IntPtr.Size, error.Writer);
                Native.Check(Native.UpdateProcThreadAttribute(attrs, 0, new IntPtr(0x20002), list,
                    new IntPtr(3 * IntPtr.Size), IntPtr.Zero, IntPtr.Zero), "allowlist trusted setup handles");
                var startup = new Native.StartupEx(); startup.startup.cb = (uint)Marshal.SizeOf(typeof(Native.StartupEx));
                startup.attributes = attrs; startup.startup.flags = 0x100; startup.startup.input = input;
                startup.startup.output = output.Writer; startup.startup.error = error.Writer;
                string command = String.Join(" ", new [] { executable }.Concat(arguments).Select(Quote));
                if (compilerPreparation || selfActivation) {
                    string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
                    if (String.IsNullOrEmpty(systemRoot) || !Path.IsPathFullyQualified(systemRoot))
                        throw new InvalidOperationException("compiler setup requires an absolute trusted Windows root");
                    var fixedEnvironment = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
                        { "SystemRoot", systemRoot }, { "WINDIR", systemRoot }, { "TEMP", cwd }, { "TMP", cwd },
                        { "PATH", Path.GetDirectoryName(executable) + ";" + Path.Combine(systemRoot, "System32") }
                    };
                    if (name == "vswhere.exe") {
                        string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                        NativeFixture.Plain(programData);
                        if (!Directory.Exists(programData))
                            throw new InvalidOperationException("VS discovery requires the existing Windows common application-data directory");
                        fixedEnvironment.Add("ProgramData", Path.GetFullPath(programData));
                    }
                    environment = Marshal.StringToHGlobalUni(String.Join("\0", fixedEnvironment.Select(pair => pair.Key + "=" + pair.Value)) + "\0\0");
                }
                EmitStage(name, "create-before");
                Native.Check(Native.CreateProcessW(executable, new StringBuilder(command), IntPtr.Zero, IntPtr.Zero,
                    true, selfActivation ? SelfCreationFlags() | (loader == null ? 0U : 2U) : Native.ExtendedStartup | Native.Suspended | Native.NoWindow | (compilerPreparation ? Native.UnicodeEnvironment : 0U),
                    environment, cwd, ref startup, out child),
                    "create suspended trusted setup process tool=" + name + (name == "dumpbin.exe" || selfActivation ? "" : " cwd=" + cwd)); started = true;
                if (loader != null) loader.Arm(child);
                EmitStage(name, "create-after"); EmitStage(name, "assign-before");
                Native.Check(Native.AssignProcessToJobObject(job, child.process), "own trusted setup process before resume");
                if (loader != null) loader.PrepareHandles(ref child);
                EmitStage(name, "assign-after"); EmitStage(name, "resume-before");
                if (selfActivation) clock.Start();
                if (Native.ResumeThread(child.thread) == UInt32.MaxValue)
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "resume trusted setup process");
                resumed = true; EmitStage(name, "resume-after");
                output.CloseWriter(); error.CloseWriter();
                if (selfActivation) { IntPtr owned = input; input = IntPtr.Zero; Native.Check(Native.CloseHandle(owned), "close fixed host activation stdin"); }
                else { Native.CloseHandle(input); input = IntPtr.Zero; }
                if (loader != null) {
                    uint observedExit = loader.Observe();
                    string captured = output.Read(), capturedError = error.Read();
                    if (clock.Elapsed.TotalSeconds > 10) throw new TimeoutException("fixed entry host exceeded 10 seconds");
                    if (moduleDispatch && captured.Length > 256) throw new InvalidOperationException("module CSR host transport exceeded its bound");
                    return pythonDispatch ? PythonCsrDispatch.HostTransport(observedExit, captured, capturedError) :
                        moduleDispatch ? ModuleActivationFixture.Result(true, observedExit, captured, capturedError) :
                        SelfActivationFixture.Result(observedExit, captured, capturedError, SelfActivationRole.ExplicitId2);
                }
                if (!selfActivation) clock.Start();
                long previous = 0; double progress = 0;
                uint wait; bool firstWait = true;
                while ((wait = Native.WaitForSingleObject(child.process, 100)) == 0x102)
                {
                    if (firstWait) { EmitStage(name, "wait-first"); firstWait = false; }
                    long count = output.Length() + error.Length();
                    if (count > 1048576) throw new InvalidOperationException("trusted setup output exceeded 1 MiB");
                    if (count != previous) { previous = count; progress = clock.Elapsed.TotalSeconds; }
                    if (clock.Elapsed.TotalSeconds > (selfActivation ? 10 : 60) || clock.Elapsed.TotalSeconds - progress > 20)
                        throw new TimeoutException(selfActivation ? "fixed host activation exceeded 10 seconds" : "trusted setup command exceeded wall=60s idle=20s");
                }
                if (firstWait) EmitStage(name, "wait-first");
                EmitStage(name, "wait-complete");
                if (wait != 0) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "wait trusted setup process");
                uint exit; Native.Check(Native.GetExitCodeProcess(child.process, out exit), "read trusted setup exit code");
                EmitStage(name, "reap-before"); Reap(job); EmitStage(name, "reap-after");
                string text = output.Read(), diagnostics = error.Read();
                EmitStage(name, "capture-after");
                if (selfActivation) {
                    if (clock.Elapsed.TotalSeconds > 10) throw new TimeoutException("fixed host activation exceeded 10 seconds");
                    return dllRequest ? ChildActivationFixture.DllResult(exit, text, diagnostics) : SelfActivationFixture.Result(exit, text, diagnostics, role);
                }
                if (Encoding.UTF8.GetByteCount(text) + Encoding.UTF8.GetByteCount(diagnostics) > 1048576)
                    throw new InvalidOperationException("combined trusted setup output exceeded 1 MiB");
                if (name == "dumpbin.exe" && diagnostics.Length != 0)
                    throw new InvalidOperationException("trusted setup dumpbin.exe emitted stderr exit=" + exit + " static output withheld");
                if (exit != 0) throw new InvalidOperationException("trusted setup " + name + " failed exit=" + exit +
                    (name == "dumpbin.exe" ? " static output withheld" : " " + diagnostics + " " + text));
                return text;
            }
            catch (Exception failure) { primaryFailure = failure; throw; }
            finally
            {
                FinishCleanup(primaryFailure,
                    () => EmitStage(name, "cleanup-before"),
                    () => { if (started && loader != null) {
                        Native.ProcessInfo retained = child;
                        loader.SuppressOriginalAliases(ref child); loader.TerminateAndDrain(job, retained);
                    } else if (started && !resumed) {
                        bool terminated = Native.TerminateProcess(child.process, 125);
                        if (selfActivation) Native.Check(terminated, "terminate suspended fixed host activation");
                    } },
                    () => { if (job != IntPtr.Zero) {
                        if (loader == null) Reap(job);
                        else {
                            Native.Check(Native.TerminateJobObject(job, 125), "terminate fixed entry host Job");
                            Sandbox.AwaitActivationJobZero(() => Native.QueryJob<Native.Accounting>(job, 1).activeProcesses,
                                loader.RemainingActivationCleanup, Thread.Sleep);
                        }
                    } },
                    () => { if (loader != null && started) loader.ConfirmDestroyed();
                        else if (selfActivation && started) Native.Check(Native.WaitForSingleObject(child.process, 0) == 0, "qualify fixed host activation process destruction"); },
                    () => { if (output != null) output.Dispose(); },
                    () => { if (error != null) error.Dispose(); },
                    () => { if (child.thread != IntPtr.Zero) CloseOwned(child.thread, selfActivation); },
                    () => { if (child.process != IntPtr.Zero) CloseOwned(child.process, selfActivation); },
                    () => { if (input != IntPtr.Zero && input != Native.InvalidHandle) CloseOwned(input, selfActivation); },
                    () => { if (attrs != IntPtr.Zero) Native.DeleteProcThreadAttributeList(attrs); },
                    () => { if (attrs != IntPtr.Zero) Marshal.FreeHGlobal(attrs); },
                    () => { if (list != IntPtr.Zero) Marshal.FreeHGlobal(list); },
                    () => { if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment); },
                    () => { if (job != IntPtr.Zero) CloseOwned(job, selfActivation); },
                    () => EmitStage(name, "cleanup-after"));
                if (loader != null) {
                    try { retainMetadata(dispatch ? loader.DispatchMetadata() : resource ? loader.ResourceMetadata() : loader.EntryMetadata()); }
                    catch (Exception reporting) {
                        if (primaryFailure != null) throw new AggregateException("fixed entry host observation/reporting failed", primaryFailure, reporting);
                        throw;
                    }
                }
            }
        }
        static void CloseOwned(IntPtr handle, bool strict)
        {
            bool closed = Native.CloseHandle(handle);
            if (strict) Native.Check(closed, "close fixed host activation handle");
        }
        static uint SelfCreationFlags()
        { return Native.ExtendedStartup | Native.Suspended | Native.UnicodeEnvironment | 8U; }
        static void RequireSelfLaunch(string executable, string[] arguments, string cwd, SelfActivationRole role = SelfActivationRole.Original)
        {
            SelfActivationFixture.RequireKnownRole(role);
            if (arguments == null || arguments.Length != 0 || Path.GetFileName(executable) != SelfActivationFixture.ImageName(role) ||
                Path.GetDirectoryName(executable) != cwd || Path.GetFileName(cwd) != "python")
                throw new ArgumentException("unsupported fixed host activation launch");
        }
        static void RequireModuleDispatchLaunch(string executable, string[] arguments, string cwd)
        {
            if (executable == null || cwd == null || !Path.IsPathFullyQualified(executable) || !Path.IsPathFullyQualified(cwd) ||
                arguments == null || arguments.Length != 0 || Path.GetFileName(executable) != "startup-module.exe" ||
                Path.GetDirectoryName(executable) != cwd || Path.GetFileName(cwd) != "module-id2")
                throw new ArgumentException("unsupported fixed module CSR host launch");
        }
        internal static void CheckModuleDispatchValidation()
        {
            string image = Path.Combine(Path.GetFullPath("."), "python", "module-id2", "startup-module.exe");
            string cwd = Path.GetDirectoryName(image);
            RequireModuleDispatchLaunch(image, new string[0], cwd);
            foreach (Action action in new Action[] {
                () => RequireModuleDispatchLaunch(image, null, cwd),
                () => RequireModuleDispatchLaunch(image, new [] { "private-sentinel" }, cwd),
                () => RequireModuleDispatchLaunch(image, new string[0], Path.GetDirectoryName(cwd)),
                () => RequireModuleDispatchLaunch(image.Replace("module-id2", "module-plain"), new string[0], cwd.Replace("module-id2", "module-plain")),
                () => RequireModuleDispatchLaunch(image.Replace("startup-module.exe", "startup-explicit-id2.exe"), new string[0], cwd),
                () => RunFixed(null, null, null, false, moduleDispatch: true),
                () => RunFixed(null, null, null, true, entryPython: "fixed", retainMetadata: _ => { }, resource: true, moduleDispatch: true),
                () => RunFixed(null, null, null, true, SelfActivationRole.ExplicitId2, "fixed", _ => { }, true, dispatch: true, moduleDispatch: true)
            }) {
                bool refused = false;
                try { action(); } catch (ArgumentException error) { refused = !error.Message.Contains("private-sentinel"); }
                if (!refused) throw new InvalidOperationException("module CSR host role was not isolated");
            }
            if (Stage("startup-module.exe", "create-before") != "WINDOWS_SETUP_STAGE tool=startup-module.exe stage=create-before")
                throw new InvalidOperationException("module CSR host stage differs");
        }
        static void RequireDllLaunch(string executable, string[] arguments, string cwd)
        {
            if (executable == null || cwd == null || !Path.IsPathFullyQualified(executable) || !Path.IsPathFullyQualified(cwd) ||
                arguments == null || arguments.Length != 0 || Path.GetFileName(executable) != "startup-dll-resource.exe" ||
                Path.GetDirectoryName(executable) != cwd || Path.GetFileName(cwd) != "python")
                throw new ArgumentException("unsupported fixed DLL resource host launch");
        }
        static void FinishCleanup(Exception primary, params Action[] actions)
        {
            var failures = new List<Exception>();
            foreach (Action action in actions) {
                try { action(); } catch (Exception failure) { failures.Add(failure); }
            }
            if (failures.Count != 0) {
                if (primary != null) failures.Insert(0, primary);
                throw new AggregateException("trusted setup operation/cleanup failed", failures);
            }
        }
        static string Stage(string tool, string stage)
        {
            if (!new [] { "cl.exe", "link.exe", "vswhere.exe", "dumpbin.exe", "rc.exe", "git.exe", "icacls.exe", "fsutil.exe", "csc.exe", "pwsh.exe", "startup-self-activation.exe", "startup-manual-activation.exe", "startup-explicit-id2.exe", "startup-dll-resource.exe", "startup-module.exe", "python.exe" }.Contains(tool) ||
                !new [] { "prepare", "create-before", "create-after", "assign-before", "assign-after", "resume-before", "resume-after",
                    "wait-first", "wait-complete", "reap-before", "reap-after", "capture-after", "cleanup-before", "cleanup-after" }.Contains(stage))
                throw new InvalidOperationException("unsupported trusted setup stage label");
            return "WINDOWS_SETUP_STAGE tool=" + tool + " stage=" + stage;
        }
        static void EmitStage(string tool, string stage)
        { EmitStage(tool, stage, Console.Out); }
        static void EmitStage(string tool, string stage, TextWriter writer)
        { writer.WriteLine(Stage(tool, stage)); writer.Flush(); }
        public static void CheckValidation()
        {
            Capture.CheckStrictCleanup();
            string dllImage = Path.Combine(Path.GetFullPath("."), "python", "startup-dll-resource.exe");
            RequireDllLaunch(dllImage, new string[0], Path.GetDirectoryName(dllImage));
            foreach (Action invalid in new Action[] {
                () => RequireDllLaunch(dllImage, new [] { "private-sentinel" }, Path.GetDirectoryName(dllImage)),
                () => RequireDllLaunch(dllImage, null, Path.GetDirectoryName(dllImage)),
                () => RequireDllLaunch(dllImage, new string[0], Path.GetDirectoryName(Path.GetDirectoryName(dllImage))),
                () => RequireDllLaunch(dllImage.Replace("startup-dll-resource", "startup-activation"), new string[0], Path.GetDirectoryName(dllImage)),
                () => RunFixed(dllImage, new string[0], Path.GetDirectoryName(dllImage), true, dllRequest: true),
                () => Run(dllImage, new string[0], Path.GetDirectoryName(dllImage))
            }) {
                bool refused = false;
                try { invalid(); } catch (ArgumentException) { refused = true; } catch (InvalidOperationException) { refused = true; }
                if (!refused) throw new InvalidOperationException("DLL request escaped its closed internal host route");
            }
            if (Stage("startup-dll-resource.exe", "create-before") != "WINDOWS_SETUP_STAGE tool=startup-dll-resource.exe stage=create-before")
                throw new InvalidOperationException("fixed DLL request stage differs");
            string image = Path.Combine(Path.GetFullPath("."), "python", "startup-self-activation.exe");
            RequireSelfLaunch(image, new string[0], Path.GetDirectoryName(image));
            string manualImage = Path.Combine(Path.GetDirectoryName(image), "startup-manual-activation.exe");
            RequireSelfLaunch(manualImage, new string[0], Path.GetDirectoryName(image), SelfActivationRole.Manual);
            foreach (Action crossRole in new Action[] {
                () => RequireSelfLaunch(image, new string[0], Path.GetDirectoryName(image), SelfActivationRole.Manual),
                () => RequireSelfLaunch(manualImage, new string[0], Path.GetDirectoryName(image)),
                () => RequireSelfLaunch(manualImage, new [] { "private-sentinel" }, Path.GetDirectoryName(image), SelfActivationRole.Manual),
                () => RequireSelfLaunch(manualImage, new string[0], Path.GetDirectoryName(Path.GetDirectoryName(image)), SelfActivationRole.Manual)
            }) {
                bool refused = false; try { crossRole(); } catch (ArgumentException) { refused = true; }
                if (!refused) throw new InvalidOperationException("fixed activation accepted a different role");
            }
            string explicitImage = Path.Combine(Path.GetDirectoryName(image), "startup-explicit-id2.exe");
            RequireSelfLaunch(explicitImage, new string[0], Path.GetDirectoryName(image), SelfActivationRole.ExplicitId2);
            foreach (SelfActivationRole role in new [] { SelfActivationRole.Original, SelfActivationRole.Manual, SelfActivationRole.ExplicitId2 }) {
                foreach (string other in new [] { image, manualImage, explicitImage }) {
                    if (Path.GetFileName(other) == SelfActivationFixture.ImageName(role)) continue;
                    bool refused = false;
                    try { RequireSelfLaunch(other, new string[0], Path.GetDirectoryName(image), role); } catch (ArgumentException) { refused = true; }
                    if (!refused) throw new InvalidOperationException("fixed activation cross-role launch accepted");
                }
            }
            foreach (Action invalid in new Action[] {
                () => RequireSelfLaunch(explicitImage, null, Path.GetDirectoryName(image), SelfActivationRole.ExplicitId2),
                () => RequireSelfLaunch(explicitImage, new [] { "private-sentinel" }, Path.GetDirectoryName(image), SelfActivationRole.ExplicitId2),
                () => RequireSelfLaunch(explicitImage, new string[0], Path.GetDirectoryName(Path.GetDirectoryName(image)), SelfActivationRole.ExplicitId2)
            }) {
                bool refused = false; try { invalid(); } catch (ArgumentException) { refused = true; }
                if (!refused) throw new InvalidOperationException("explicit ID2 activation accepted an unrelated launch");
            }
            foreach (int invalid in new [] { -1, 3, Int32.MaxValue }) {
                bool refused = false;
                try { RunFixed(null, null, null, true, (SelfActivationRole)invalid); } catch (ArgumentException) { refused = true; }
                if (!refused) throw new InvalidOperationException("undefined activation role reached launch effects");
            }
            if (Stage("startup-explicit-id2.exe", "create-before") != "WINDOWS_SETUP_STAGE tool=startup-explicit-id2.exe stage=create-before")
                throw new InvalidOperationException("fixed explicit ID2 activation stage differs");
            if (Stage("startup-manual-activation.exe", "create-before") != "WINDOWS_SETUP_STAGE tool=startup-manual-activation.exe stage=create-before")
                throw new InvalidOperationException("fixed manual activation stage differs");
            if (SelfCreationFlags() != 0x0008040C || Stage("startup-self-activation.exe", "create-before") !=
                "WINDOWS_SETUP_STAGE tool=startup-self-activation.exe stage=create-before")
                throw new InvalidOperationException("fixed host activation launch contract differs");
            foreach (Action invalid in new Action[] {
                () => RequireSelfLaunch(image, new [] { "private-sentinel" }, Path.GetDirectoryName(image)),
                () => RequireSelfLaunch(image, new string[0], Path.GetDirectoryName(Path.GetDirectoryName(image))),
                () => RequireSelfLaunch(Path.ChangeExtension(image, ".dll"), new string[0], Path.GetDirectoryName(image)),
                () => RequireSelfLaunch(image, null, Path.GetDirectoryName(image))
            }) {
                bool refused = false;
                try { invalid(); } catch (ArgumentException failure) {
                    if (failure.Message.Contains("private-sentinel")) throw;
                    refused = true;
                }
                if (!refused) throw new InvalidOperationException("fixed host activation accepted an unrelated launch");
            }
            if (Stage("rc.exe", "create-before") != "WINDOWS_SETUP_STAGE tool=rc.exe stage=create-before")
                throw new InvalidOperationException("resource compiler stage literal differs");
            if (Stage("csc.exe", "create-before") != "WINDOWS_SETUP_STAGE tool=csc.exe stage=create-before")
                throw new InvalidOperationException("trusted setup stage literal differs");
            foreach (var bad in new [] { Tuple.Create("C:\\private\\csc.exe", "create-before"), Tuple.Create("csc.exe", "secret") }) {
                bool rejected = false;
                try { Stage(bad.Item1, bad.Item2); } catch (InvalidOperationException) { rejected = true; }
                if (!rejected) throw new InvalidOperationException("trusted setup stage accepted private metadata");
            }
            foreach (bool flush in new [] { false, true }) {
                var primary = new TimeoutException("fixed operation fixture");
                var cleanup = new IOException("fixed cleanup fixture");
                using (var writer = new FailingStageWriter(flush)) {
                    int attempts = 0; AggregateException combined = null;
                    try {
                        FinishCleanup(primary,
                            () => EmitStage("csc.exe", "cleanup-before", writer),
                            () => { attempts++; throw cleanup; },
                            () => attempts++,
                            () => EmitStage("csc.exe", "cleanup-after", writer));
                    }
                    catch (AggregateException failure) { combined = failure; }
                    if (attempts != 2 || writer.Writes != 2 || writer.Flushes != (flush ? 2 : 0) ||
                        combined == null || combined.InnerExceptions.Count != 4 ||
                        !Object.ReferenceEquals(combined.InnerExceptions[0], primary) ||
                        !Object.ReferenceEquals(combined.InnerExceptions[1], writer.Failure) ||
                        !Object.ReferenceEquals(combined.InnerExceptions[2], cleanup) ||
                        !Object.ReferenceEquals(combined.InnerExceptions[3], writer.Failure))
                        throw new InvalidOperationException("trusted setup marker failure replaced operation or skipped cleanup");
                }
                Exception retained = null;
                try { try { throw primary; } finally { FinishCleanup(primary, () => { }); } }
                catch (Exception failure) { retained = failure; }
                if (!Object.ReferenceEquals(retained, primary))
                    throw new InvalidOperationException("successful cleanup replaced original operation failure");
            }
        }
        sealed class FailingStageWriter : TextWriter
        {
            readonly bool failFlush;
            internal readonly IOException Failure = new IOException("fixed marker fixture");
            internal int Writes, Flushes;
            internal FailingStageWriter(bool flush) { failFlush = flush; }
            public override Encoding Encoding { get { return Encoding.UTF8; } }
            public override void WriteLine(string value) { Writes++; if (!failFlush) throw Failure; }
            public override void Flush() { Flushes++; throw Failure; }
        }
        static void Reap(IntPtr job)
        {
            Native.Check(Native.TerminateJobObject(job, 125), "terminate trusted setup job");
            var deadline = Stopwatch.StartNew();
            while (Native.QueryJob<Native.Accounting>(job, 1).activeProcesses != 0) {
                if (deadline.Elapsed.TotalSeconds > 5) throw new TimeoutException("trusted setup job cleanup exceeded bound");
                Thread.Sleep(20);
            }
        }
        internal static string Quote(string value)
        {
            var text = new StringBuilder("\""); int slashes = 0;
            foreach (char c in value) {
                if (c == '\\') { slashes++; continue; }
                text.Append('\\', c == '"' ? slashes * 2 + 1 : slashes); text.Append(c); slashes = 0;
            }
            text.Append('\\', slashes * 2); return text.Append('"').ToString();
        }
    }
}
