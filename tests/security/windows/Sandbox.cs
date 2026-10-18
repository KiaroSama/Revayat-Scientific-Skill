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
    public static class Sandbox
    {
        public static string PackageSid(string moniker)
        {
            IntPtr sid;
            int result = Native.DeriveAppContainerSidFromAppContainerName(moniker, out sid);
            if (result != 0) Marshal.ThrowExceptionForHR(result);
            try { return new System.Security.Principal.SecurityIdentifier(sid).Value; }
            finally { Native.FreeSid(sid); }
        }

        // Only the fixed probe and fixed regression entry are launchable; no arbitrary command API.
        public static string Run(string python, string root, string scratch, string powershell,
                                 string chromium, string moniker, string profileFolder, bool preflight, int tcpPort, int udpPort, bool wallProbe = false, bool loaderProbe = false, bool nativeFixture = false, bool pythonClone = false, bool activationProbe = false, bool activationTrace = false)
        {
            return RunFixed(python, root, scratch, powershell, chromium, moniker, profileFolder, preflight, tcpPort, udpPort,
                wallProbe, loaderProbe, nativeFixture, pythonClone, activationProbe, activationTrace, false, null);
        }
        public static string ObserveActivation(string python, string root, string scratch, string powershell,
                                               string chromium, string moniker, string profileFolder, int tcpPort, int udpPort, int expectedRegistryStatus)
        {
            return RunFixed(python, root, scratch, powershell, chromium, moniker, profileFolder, true, tcpPort, udpPort,
                false, false, false, false, true, false, false, expectedRegistryStatus);
        }
        public static uint ObservePreflightExit(string python, string root, string scratch, string powershell,
                                               string chromium, string moniker, string profileFolder, int tcpPort, int udpPort, int expectedRegistryStatus)
        {
            try {
                RunFixed(python, root, scratch, powershell, chromium, moniker, profileFolder, true, tcpPort, udpPort,
                    false, false, false, false, false, false, true, expectedRegistryStatus);
                return 0;
            }
            catch (PreflightExit failure) { return failure.Code; }
        }
        internal static string ObserveDefaultActivation(string python, string root, string scratch, string powershell,
                                                       string chromium, string moniker, string profileFolder, int tcpPort, int udpPort, int expectedRegistryStatus)
        {
            return RunFixed(python, root, scratch, powershell, chromium, moniker, profileFolder, true, tcpPort, udpPort,
                false, false, false, false, false, false, false, expectedRegistryStatus, true);
        }
        internal static string ObserveModuleActivation(string python, string root, string scratch, string powershell,
                                                      string chromium, string moniker, string profileFolder, int tcpPort, int udpPort, int expectedRegistryStatus, bool manifest)
        {
            return RunFixed(python, root, scratch, powershell, chromium, moniker, profileFolder, true, tcpPort, udpPort,
                false, false, false, false, false, false, false, expectedRegistryStatus, false, manifest ? 2 : 1);
        }
        internal static string ObserveModuleCallback(string python, string root, string scratch, string powershell,
                                                     string chromium, string moniker, string profileFolder, int tcpPort, int udpPort, uint expectedExit)
        {
            return RunFixed(python, root, scratch, powershell, chromium, moniker, profileFolder, true, tcpPort, udpPort,
                false, false, false, false, false, false, false, 0, false, 3, expectedExit);
        }
        internal static string ObserveSelfActivation(string python, string root, string scratch, string powershell,
                                                    string chromium, string moniker, string profileFolder, int tcpPort, int udpPort, int expectedRegistryStatus)
        {
            SelfActivationFixture.RequireHostPositive(python);
            return RunFixed(python, root, scratch, powershell, chromium, moniker, profileFolder, true, tcpPort, udpPort,
                false, false, false, false, false, false, false, expectedRegistryStatus, false, 0, null, true);
        }
        internal static string ObserveManualActivation(string python, string root, string scratch, string powershell,
                                                      string chromium, string moniker, string profileFolder, int tcpPort, int udpPort, int expectedRegistryStatus, SelfActivationRole role = SelfActivationRole.Manual)
        {
            SelfActivationFixture.RequireKnownRole(role);
            if (role == SelfActivationRole.Original) throw new ArgumentException("independent activation requires a distinct fixed role");
            SelfActivationFixture.RequireHostPositive(python, role);
            return RunFixed(python, root, scratch, powershell, chromium, moniker, profileFolder, true, tcpPort, udpPort,
                false, false, false, false, false, false, false, expectedRegistryStatus, false, 0, null, true, role);
        }
        internal static string ObserveExplicitEntry(string python, string root, string scratch, string powershell,
            string chromium, string moniker, string profileFolder, int tcpPort, int udpPort)
        {
            SelfActivationFixture.RequireEntryHostPositive(python);
            return RunFixed(python, root, scratch, powershell, chromium, moniker, profileFolder, true, tcpPort, udpPort,
                false, false, false, false, false, false, false, unchecked((int)0xC0000022), false, 0, null, true, SelfActivationRole.ExplicitId2, true);
        }
        sealed class PreflightExit : InvalidOperationException
        {
            internal readonly uint Code;
            internal PreflightExit(uint code) : base("fixed ordinary preflight returned a nonzero exit") { Code = code; }
        }
        static bool RequireModuleRole(int role, int? expectedRegistry, uint? expectedExit)
        {
            bool callback = role == 3;
            if (role < 0 || role > 3 || callback != expectedExit.HasValue ||
                callback && (expectedRegistry != 0 || (expectedExit.Value & 0x80000000) == 0))
                throw new ArgumentException("unsupported fixed module activation role");
            return callback;
        }
        static void RequireRegistryCondition(int actual, int expected)
        {
            if ((expected != 0 && expected != unchecked((int)0xC0000022)) || (expected == 0 ? actual < 0 : actual != expected))
                throw new InvalidOperationException("fixed registry differential condition was not observed");
        }
        static void RequireExit(uint exit, string phase, bool observe, string errors, string text)
        {
            if (exit == 0) return;
            if (observe) { if (phase != "preflight") throw new InvalidOperationException("exit observation is not ordinary preflight"); throw new PreflightExit(exit); }
            throw new InvalidOperationException("Windows " + phase + " failed exit=" + exit + " " + errors + " " + text);
        }
        static string RunFixed(string python, string root, string scratch, string powershell,
                               string chromium, string moniker, string profileFolder, bool preflight, int tcpPort, int udpPort,
                               bool wallProbe, bool loaderProbe, bool nativeFixture, bool pythonClone, bool activationProbe, bool activationTrace, bool observeExit, int? expectedRegistryStatus, bool defaultActivation = false, int moduleRole = 0, uint? callbackExit = null, bool selfActivation = false, SelfActivationRole selfRole = SelfActivationRole.Original, bool selfEntry = false)
        {
            SelfActivationFixture.RequireKnownRole(selfRole);
            if (selfEntry && (!selfActivation || selfRole != SelfActivationRole.ExplicitId2)) throw new ArgumentException("entry observation requires fixed ExplicitId2");
            if (selfRole != SelfActivationRole.Original && !selfActivation) throw new ArgumentException("activation role requires the fixed self diagnostic");
            bool callback = RequireModuleRole(moduleRole, expectedRegistryStatus, callbackExit);
            if (selfActivation) SelfActivationFixture.RequireRole(preflight, wallProbe, loaderProbe, nativeFixture, pythonClone,
                activationProbe, activationTrace, observeExit, defaultActivation, moduleRole != 0);
            if (moduleRole != 0) ModuleActivationFixture.RequireRole(preflight, wallProbe, loaderProbe, nativeFixture, pythonClone, activationProbe, activationTrace, observeExit, defaultActivation);
            if (defaultActivation) DefaultActivationFixture.RequireRole(preflight, wallProbe, loaderProbe, nativeFixture, pythonClone, activationProbe, activationTrace, observeExit);
            if (observeExit && (!preflight || wallProbe || loaderProbe || nativeFixture || pythonClone || activationProbe || activationTrace))
                throw new ArgumentException("exit observation requires fixed ordinary trusted preflight");
            ChildActivationFixture.RequireDiagnosticRole(preflight, wallProbe, loaderProbe, nativeFixture, pythonClone, activationProbe, activationTrace);
            if (loaderProbe && (!preflight || wallProbe))
                throw new ArgumentException("loader tracing is restricted to the separate fixed trusted pass phase");
            if (nativeFixture && !loaderProbe) throw new ArgumentException("native fixture is a fixed loader diagnostic only");
            if (pythonClone && (!loaderProbe || nativeFixture)) throw new ArgumentException("Python clone is a separate fixed pass-code diagnostic only");
            python = Path.GetFullPath(python); root = Path.GetFullPath(root);
            scratch = Path.GetFullPath(scratch); powershell = Path.GetFullPath(powershell);
            string probe = preflight ? Path.Combine(root, "tests", "security", "windows", "KernelProbe.py")
                                     : Path.Combine(root, "tests", "security", "windows_probe.py");
            string phase = loaderProbe ? (nativeFixture ? "native-loader-trace" : (pythonClone ? "python-clone-loader-trace" : "python-loader-trace")) : (wallProbe ? "wall" : (preflight ? "preflight" : "regressions"));
            string launchCwd = preflight ? Path.GetDirectoryName(python) : scratch;
            var arguments = new List<string> { python, "-I", "-B", "-X", "utf8", probe, root, scratch, powershell };
            if (preflight) { arguments.Add(tcpPort.ToString()); arguments.Add(udpPort.ToString()); arguments.Add(profileFolder); }
            if (wallProbe) arguments.Add("wall-tree");
            string executable = python;
            if (loaderProbe) arguments = new List<string> { python, "-I", "-B", "-c", "pass" };
            if (nativeFixture) {
                executable = Path.Combine(Path.GetDirectoryName(python), "startup-native.exe");
                NativeFixture.Validate(executable);
                arguments = new List<string> { executable };
            }
            if (pythonClone) {
                executable = Path.Combine(Path.GetDirectoryName(python), "startup-python.exe");
                arguments = new List<string> { executable, "-I", "-B", "-c", "pass" };
            }
            if (activationProbe || activationTrace) {
                executable = Path.Combine(Path.GetDirectoryName(python), "startup-activation.exe");
                arguments = new List<string> { executable };
                phase = activationTrace ? "child-activation-trace" : "child-activation";
            }
            if (defaultActivation) {
                executable = DefaultActivationFixture.PreparedImage(python);
                arguments = new List<string> { executable };
                phase = "default-activation";
            }
            if (moduleRole != 0) {
                executable = ModuleActivationFixture.PreparedImage(python, moduleRole >= 2);
                arguments = new List<string> { executable }; launchCwd = Path.GetDirectoryName(executable);
                phase = callback ? "module-callback-trace" : (moduleRole == 2 ? "module-id2" : "module-plain");
            }
            if (selfActivation) {
                executable = SelfActivationFixture.PreparedImage(python, selfRole);
                arguments = new List<string> { executable };
                phase = SelfActivationFixture.Stem(selfRole);
            }
            string command = String.Join(" ", arguments.Select(Quote));
            string home = Path.Combine(scratch, "home"), temp = Path.Combine(scratch, "temp");
            var environment = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
                { "SystemRoot", Environment.GetEnvironmentVariable("SystemRoot") },
                { "WINDIR", Environment.GetEnvironmentVariable("SystemRoot") },
                { "PATH", Path.GetDirectoryName(python) + ";" + Path.GetDirectoryName(powershell) },
                { "HOME", home }, { "USERPROFILE", home }, { "LOCALAPPDATA", home }, { "APPDATA", home },
                { "TEMP", temp }, { "TMP", temp }, { "PYTHONIOENCODING", "utf-8" },
                { "REVAYAT_CHROMIUM", chromium }, { "DOTNET_CLI_HOME", home },
                { "XDG_CACHE_HOME", Path.Combine(home, "cache") }
            };
            string block = String.Join("\0", environment.Select(pair => pair.Key + "=" + pair.Value)) + "\0\0";
            IntPtr job = IntPtr.Zero, sid = IntPtr.Zero, attrs = IntPtr.Zero, env = IntPtr.Zero, processDescriptor = IntPtr.Zero;
            var values = new List<IntPtr>();
            var handles = new List<IntPtr>();
            Native.ProcessInfo process = new Native.ProcessInfo();
            bool started = false, resumed = false, wallExpired = false, callbackStarted = false, entryStarted = false;
            Exception primaryFailure = null;
            Capture outputCapture = null, errorCapture = null;
            LoaderTrace loader = loaderProbe || activationTrace || callback || selfEntry ? new LoaderTrace(nativeFixture, pythonClone, activationTrace, callback, selfEntry ? python : null) : null;
            IDisposable activationLease = null;
            var activationClock = new Stopwatch();
            try
            {
                if (activationProbe || activationTrace) activationLease = ChildActivationFixture.Hold(python);
                if (defaultActivation) activationLease = DefaultActivationFixture.Hold(python);
                if (selfActivation) activationLease = SelfActivationFixture.Hold(python, selfRole);
                if (moduleRole != 0) activationLease = ModuleActivationFixture.Hold(python, moduleRole >= 2);
                job = Native.CreateJobObject(IntPtr.Zero, null);
                Native.Check(job != IntPtr.Zero, "create owned job");
                var limits = new Native.ExtendedLimits();
                limits.basic.flags = 0x2000 | 0x200 | 0x100 | 8 | 4;
                limits.basic.processes = 8;
                limits.basic.jobTime = 30L * 10000000L;
                limits.processMemory = new UIntPtr(384UL * 1024 * 1024);
                limits.jobMemory = new UIntPtr(512UL * 1024 * 1024);
                Native.SetJob(job, 9, limits);
                Native.SetJob(job, 15, new Native.CpuLimits { flags = 5, rate = 1000 });
                Native.ExtendedLimits actual = Native.QueryJob<Native.ExtendedLimits>(job, 9);
                Native.CpuLimits cpu = Native.QueryJob<Native.CpuLimits>(job, 15);
                if (actual.basic.flags != limits.basic.flags || actual.basic.processes != 8 ||
                    actual.jobMemory != limits.jobMemory || actual.processMemory != limits.processMemory ||
                    actual.basic.jobTime != limits.basic.jobTime || cpu.flags != 5 || cpu.rate != 1000)
                    throw new InvalidOperationException("kernel job resource values differ from required limits");
                int hr = Native.DeriveAppContainerSidFromAppContainerName(moniker, out sid);
                if (hr != 0) Marshal.ThrowExceptionForHR(hr);
                IntPtr size = IntPtr.Zero;
                Native.InitializeProcThreadAttributeList(IntPtr.Zero, 3, 0, ref size);
                if (size == IntPtr.Zero) throw new InvalidOperationException("attribute allocation size unavailable");
                attrs = Marshal.AllocHGlobal(size);
                Native.Check(Native.InitializeProcThreadAttributeList(attrs, 3, 0, ref size), "initialize attributes");
                IntPtr security = Native.Structure(new Native.SecurityCapabilities { sid = sid });
                values.Add(security);
                Attribute(attrs, 0x20009, security, Marshal.SizeOf(typeof(Native.SecurityCapabilities)));
                IntPtr lpac = Marshal.AllocHGlobal(4); values.Add(lpac); Marshal.WriteInt32(lpac, 1);
                Attribute(attrs, 0x2000F, lpac, 4);
                var sa = new Native.SecurityAttributes { size = (uint)Marshal.SizeOf(typeof(Native.SecurityAttributes)), inherit = 1 };
                outputCapture = new Capture(selfActivation); errorCapture = new Capture(selfActivation);
                IntPtr output = outputCapture.Writer, error = errorCapture.Writer;
                IntPtr input = Native.CreateFileW("NUL", 0x80000000, 3, ref sa, 3, 0x80, IntPtr.Zero);
                Native.Check(input != Native.InvalidHandle, "open standard input"); handles.Add(input);
                IntPtr list = Marshal.AllocHGlobal(3 * IntPtr.Size); values.Add(list);
                Marshal.WriteIntPtr(list, 0, input); Marshal.WriteIntPtr(list, IntPtr.Size, output); Marshal.WriteIntPtr(list, 2 * IntPtr.Size, error);
                Attribute(attrs, 0x20002, list, 3 * IntPtr.Size);
                var startup = new Native.StartupEx();
                startup.startup.cb = (uint)Marshal.SizeOf(typeof(Native.StartupEx));
                startup.startup.flags = 0x100; startup.startup.input = input;
                startup.startup.output = output; startup.startup.error = error; startup.attributes = attrs;
                env = Marshal.StringToHGlobalUni(block);
                // Default process DACL belongs to the parent user. Grant only this package the
                // same-object rights needed by CPython's bounded child-process wait/termination.
                string package = PackageSid(moniker);
                uint descriptorBytes;
                Native.Check(Native.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + package + ")S:(ML;;NW;;;LW)",
                    1, out processDescriptor, out descriptorBytes), "construct own process security descriptor");
                IntPtr processAttributes = Native.Structure(new Native.SecurityAttributes {
                    size = (uint)Marshal.SizeOf(typeof(Native.SecurityAttributes)), descriptor = processDescriptor });
                values.Add(processAttributes);
                Console.Out.WriteLine("WINDOWS_LPAC_PATH executable=" + Quote(executable) + " cwd=" + Quote(launchCwd)
                    + " desired_scratch=" + Quote(scratch) + " phase=" + phase
                    + " probe=" + Quote(probe) + " executable_exists=" + File.Exists(executable)
                    + " cwd_exists=" + Directory.Exists(launchCwd) + " scratch_exists=" + Directory.Exists(scratch)
                    + " probe_exists=" + File.Exists(probe));
                Console.Out.Flush();
                if (!File.Exists(executable) || !Directory.Exists(launchCwd) || !Directory.Exists(scratch) || !File.Exists(probe))
                    throw new InvalidOperationException("prepared LPAC executable, working directory or fixed probe is absent");
                using (OwnedToken restricted = OwnedToken.Create()) {
                    bool created = OwnedToken.CreateProcessAsUserW(restricted.Handle, executable, new StringBuilder(command), processAttributes, processAttributes, true,
                        CreationFlags(loaderProbe || activationTrace || callback || selfEntry),
                        env, launchCwd, ref startup, out process);
                    started = created;
                    if (created && loader != null) loader.Arm(process);
                    Native.Check(created, "create suspended LPAC child from owned restricted LUA primary");
                    Native.Check(Native.AssignProcessToJobObject(job, process.process), "assign owned resource job before token preparation");
                }
                if (loader != null) loader.PrepareHandles(ref process);
                Profile.SealRegistry(process.process, moniker, package);
                TokenPolicy.Prepare(process.process, Path.GetPathRoot(scratch), package);
                Profile.RequireReadOnlyRegistry(process.process, moniker, package);
                if (preflight && !wallProbe && !loaderProbe) {
                    StartupAccess.Observe(process, python);
                    StartupImageAccess.Observe(process, python, package);
                    int registryStatus = StartupActivationAccess.Observe(process, python, package);
                    if (expectedRegistryStatus.HasValue) RequireRegistryCondition(registryStatus, expectedRegistryStatus.Value);
                    StartupAccess.RequireOwnQueries(process, false);
                }
                OwnProcessAccess.Repair(process);
                StartupAccess.RequireOwnQueries(process, true);
                if (preflight && !wallProbe && !loaderProbe && !activationProbe && !activationTrace)
                    StartupTokenAccess.Observe(process, package);
                if (nativeFixture) {
                    string metadata = TokenDefaultMetadata.Observe(process.process);
                    Console.Out.WriteLine(metadata); Console.Out.Flush();
                }
                if (activationProbe || defaultActivation || moduleRole != 0 || selfActivation) activationClock.Start();
                if (Native.ResumeThread(process.thread) == UInt32.MaxValue)
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "resume contained child");
                resumed = true;
                if (selfActivation) {
                    while (handles.Count != 0) {
                        IntPtr owned = handles[handles.Count - 1]; handles.RemoveAt(handles.Count - 1);
                        Native.Check(Native.CloseHandle(owned), "close fixed contained activation stdin");
                    }
                } else { foreach (IntPtr handle in handles) Native.CloseHandle(handle); handles.Clear(); }
                outputCapture.CloseWriter(); errorCapture.CloseWriter();
                if (loader != null) {
                    callbackStarted = callback; entryStarted = selfEntry;
                    uint tracedExit = loader.Observe();
                    if (selfEntry) {
                        string entryOutput = outputCapture.Read(), entryError = errorCapture.Read();
                        if (activationClock.Elapsed.TotalSeconds > 10) throw new TimeoutException("fixed entry child exceeded 10 seconds");
                        return SelfActivationFixture.Result(tracedExit, entryOutput, entryError, SelfActivationRole.ExplicitId2);
                    }
                    if (!callback) Native.Check(Native.WaitForSingleObject(process.process, 5000) == 0, "wait for continued loader diagnostic process exit");
                    string capturedOutput = outputCapture.Read(), capturedErrors = errorCapture.Read();
                    if (callback) return ModuleActivationFixture.CompareCallback(callbackExit.Value, tracedExit, capturedOutput, capturedErrors);
                    if (activationTrace) {
                        ChildActivationFixture.RequireTransport(tracedExit, capturedOutput, capturedErrors);
                        return capturedOutput; // The existing finally qualifies Job-zero, destruction and all owned cleanup before return.
                    }
                    string captured = capturedOutput + capturedErrors;
                    if (Encoding.UTF8.GetByteCount(captured) > 1048576)
                        throw new InvalidOperationException("loader worker output exceeded 1 MiB");
                    return "LOADER_TRACE_EXIT=0x" + tracedExit.ToString("X8");
                }
                var clock = Stopwatch.StartNew();
                long previous = 0; double progress = 0; double? wallStarted = null;
                while (Native.WaitForSingleObject(process.process, 100) == 0x102)
                {
                    if ((activationProbe || defaultActivation || moduleRole != 0 || selfActivation) && activationClock.Elapsed.TotalSeconds > 10)
                        throw new TimeoutException("fixed child activation exceeded 10 seconds");
                    long length = outputCapture.Length() + errorCapture.Length();
                    if (length > 1048576) throw new InvalidOperationException("worker standard output exceeded 1 MiB");
                    if (length != previous) { previous = length; progress = clock.Elapsed.TotalSeconds; }
                    if (wallProbe && !wallStarted.HasValue && outputCapture.HasWallTreeMarker()
                        && Native.QueryJob<Native.Accounting>(job, 1).activeProcesses >= 2)
                        wallStarted = clock.Elapsed.TotalSeconds;
                    if (wallProbe && wallStarted.HasValue && clock.Elapsed.TotalSeconds - wallStarted.Value > 2) {
                        wallExpired = true;
                        throw new TimeoutException("verified wall-tree deadline exceeded");
                    }
                    if (clock.Elapsed.TotalSeconds > 60 || clock.Elapsed.TotalSeconds - progress > 20)
                        throw new TimeoutException("owned Windows worker wall/idle ceiling exceeded before verified wall-tree");
                }
                uint exit; Native.Check(Native.GetExitCodeProcess(process.process, out exit), "read worker exit");
                ReapJob(job);
                string text = outputCapture.Read(), errors = errorCapture.Read();
                if (Encoding.UTF8.GetByteCount(text) + Encoding.UTF8.GetByteCount(errors) > 1048576)
                    throw new InvalidOperationException("combined worker output exceeded 1 MiB");
                if (activationProbe) {
                    if (activationClock.Elapsed.TotalSeconds > 10) throw new TimeoutException("fixed child activation exceeded 10 seconds");
                    ChildActivationFixture.RequireTransport(exit, text, errors);
                    return text;
                }
                if (defaultActivation) {
                    if (activationClock.Elapsed.TotalSeconds > 10) throw new TimeoutException("fixed default activation exceeded 10 seconds");
                    return DefaultActivationFixture.Result(exit, text, errors);
                }
                if (selfActivation) {
                    if (activationClock.Elapsed.TotalSeconds > 10) throw new TimeoutException("fixed self activation exceeded 10 seconds");
                    return SelfActivationFixture.Result(exit, text, errors, selfRole);
                }
                if (moduleRole != 0) {
                    if (activationClock.Elapsed.TotalSeconds > 10) throw new TimeoutException("fixed module activation exceeded 10 seconds");
                    return ModuleActivationFixture.Result(moduleRole == 2, exit, text, errors);
                }
                RequireExit(exit, phase, observeExit, errors, text);
                if (!String.IsNullOrWhiteSpace(errors)) throw new InvalidOperationException("unexpected worker error output: " + errors);
                if (wallProbe) throw new InvalidOperationException("wall negative control exited before owned deadline");
                return text;
            }
            catch (TimeoutException failure)
            {
                if (!wallProbe || !wallExpired || !resumed) { primaryFailure = failure; throw; }
                return "WALL_TREE_TERMINATED";
            }
            catch (Exception failure) { primaryFailure = failure; throw; }
            finally
            {
                var cleanupFailures = new List<Exception>();
                AttemptCleanup(cleanupFailures, () => {
                    if (started && loader != null) {
                        Native.ProcessInfo retained = process;
                        loader.SuppressOriginalAliases(ref process);
                        loader.TerminateAndDrain(job, retained);
                    }
                    else if (started && !resumed) Native.Check(Native.TerminateProcess(process.process, 125), "terminate suspended child");
                });
                bool reaped = false;
                AttemptCleanup(cleanupFailures, () => {
                    if (job != IntPtr.Zero) ReapJob(job, (activationTrace || callback || selfEntry) && started ? (Func<uint>)loader.RemainingActivationCleanup : null);
                    reaped = true;
                });
                bool destroyed = false;
                if (reaped && started && loader != null)
                    AttemptCleanup(cleanupFailures, () => { loader.ConfirmDestroyed(); destroyed = true; });
                AttemptCleanup(cleanupFailures, () => { if (outputCapture != null) outputCapture.Dispose(); });
                AttemptCleanup(cleanupFailures, () => { if (errorCapture != null) errorCapture.Dispose(); });
                AttemptCleanup(cleanupFailures, () => { if (process.thread != IntPtr.Zero) Native.Check(Native.CloseHandle(process.thread), "close owned child thread"); });
                AttemptCleanup(cleanupFailures, () => { if (process.process != IntPtr.Zero) Native.Check(Native.CloseHandle(process.process), "close owned child process"); });
                foreach (IntPtr handle in handles)
                    AttemptCleanup(cleanupFailures, () => Native.Check(Native.CloseHandle(handle), "close owned standard handle"));
                AttemptCleanup(cleanupFailures, () => {
                    if (attrs != IntPtr.Zero) {
                        try { Native.DeleteProcThreadAttributeList(attrs); }
                        finally { Marshal.FreeHGlobal(attrs); }
                    }
                });
                foreach (IntPtr value in values) AttemptCleanup(cleanupFailures, () => Marshal.FreeHGlobal(value));
                AttemptCleanup(cleanupFailures, () => { if (env != IntPtr.Zero) Marshal.FreeHGlobal(env); });
                AttemptCleanup(cleanupFailures, () => { if (processDescriptor != IntPtr.Zero && Native.LocalFree(processDescriptor) != IntPtr.Zero)
                    throw new InvalidOperationException("owned process descriptor cleanup failed"); });
                AttemptCleanup(cleanupFailures, () => { if (sid != IntPtr.Zero && Native.FreeSid(sid) != IntPtr.Zero)
                    throw new InvalidOperationException("owned package SID cleanup failed"); });
                AttemptCleanup(cleanupFailures, () => { if (job != IntPtr.Zero) Native.Check(Native.CloseHandle(job), "close owned job"); });
                AttemptCleanup(cleanupFailures, () => { if (activationLease != null) activationLease.Dispose(); });
                Exception completionFailure = selfEntry ? ExplicitEntryComparison.FinishTrace(primaryFailure, cleanupFailures, entryStarted, destroyed,
                    loader.EntryMetadata, line => { Console.Out.WriteLine(line); Console.Out.Flush(); }) : CompletionFailure(primaryFailure, cleanupFailures, callbackStarted, destroyed);
                if (completionFailure != null) throw completionFailure;
            }
        }
        static void AttemptCleanup(List<Exception> failures, Action action)
        {
            try { action(); } catch (Exception failure) { failures.Add(failure); }
        }
        internal static Exception CompletionFailure(Exception primary, List<Exception> cleanup, bool callbackStarted, bool destroyed)
        {
            if (cleanup.Count != 0) return CleanupFailure(primary, cleanup);
            return callbackStarted && destroyed && primary != null ? new QualifiedModuleCallbackFailure(primary) : null;
        }
        static AggregateException CleanupFailure(Exception primary, List<Exception> cleanup)
        {
            var failures = new List<Exception>();
            if (primary != null) failures.Add(primary);
            failures.AddRange(cleanup);
            return new AggregateException("owned Windows operation/cleanup failed", failures);
        }
        // NO_WINDOW still enters console allocation; detached workers use only the three explicit handles.
        static uint CreationFlags(bool debug)
        { return Native.ExtendedStartup | Native.Suspended | 8U | Native.UnicodeEnvironment | (debug ? 2U : 0U); }
        internal static void CheckCleanupValidation()
        {
            foreach (int invalid in new [] { -1, 3, Int32.MaxValue }) {
                bool refused = false;
                try { ObserveManualActivation(null, null, null, null, null, null, null, 0, 0, 0, (SelfActivationRole)invalid); }
                catch (ArgumentException) { refused = true; }
                if (!refused) throw new InvalidOperationException("undefined activation role reached contained launch effects");
            }
            RequireExit(0, "preflight", false, "", ""); RequireExit(0, "preflight", true, "", "");
            foreach (uint code in new uint[] { 1, 0xC0000022, UInt32.MaxValue }) {
                bool ordinary = false, typed = false;
                try { RequireExit(code, "preflight", false, "", ""); } catch (PreflightExit) { throw; } catch (InvalidOperationException) { ordinary = true; }
                try { RequireExit(code, "preflight", true, "", ""); } catch (PreflightExit failure) { typed = failure.Code == code; }
                if (!ordinary || !typed) throw new InvalidOperationException("ordinary exit observation weakened failure semantics");
            }
            foreach (int status in new [] { 0, 1, 0x40000003 }) RequireRegistryCondition(status, 0);
            RequireRegistryCondition(unchecked((int)0xC0000022), unchecked((int)0xC0000022));
            foreach (int[] item in new [] { new [] { -1, 0 }, new [] { 0, unchecked((int)0xC0000022) }, new [] { 0, 1 } }) {
                bool refused = false;
                try { RequireRegistryCondition(item[0], item[1]); } catch (InvalidOperationException) { refused = true; }
                if (!refused) throw new InvalidOperationException("registry differential condition was not qualified");
            }
            if (CreationFlags(false) != 0x0008040C || CreationFlags(true) != 0x0008040E)
                throw new InvalidOperationException("contained launch lost detached, suspended, Unicode or fixed debug flags");
            if (!RequireModuleRole(3, 0, 0xC0150002) || RequireModuleRole(0, null, null) ||
                RequireModuleRole(1, 0, null) || RequireModuleRole(2, 0, null))
                throw new InvalidOperationException("fixed module role separation failed");
            foreach (int role in new [] { -1, 0, 1, 2, 4 }) {
                bool refused = false;
                try { RequireModuleRole(role, 0, 0xC0150002); } catch (ArgumentException) { refused = true; }
                if (!refused) throw new InvalidOperationException("callback exit was accepted by an unrelated role");
            }
            foreach (uint? code in new uint?[] { null, 0, 121, 0x7FFFFFFF }) {
                bool refused = false;
                try { RequireModuleRole(3, 0, code); } catch (ArgumentException) { refused = true; }
                if (!refused) throw new InvalidOperationException("callback role accepted an unqualified exit");
            }
            foreach (int? registry in new int?[] { null, 1, unchecked((int)0xC0000022) }) {
                bool refused = false;
                try { RequireModuleRole(3, registry, 0xC0150002); } catch (ArgumentException) { refused = true; }
                if (!refused) throw new InvalidOperationException("callback role escaped the modified registry condition");
            }
            var primary = new InvalidOperationException("fixed primary fixture");
            foreach (bool callback in new [] { false, true })
                foreach (bool destroyed in new [] { false, true }) {
                    Exception result = CompletionFailure(primary, new List<Exception>(), callback, destroyed);
                    var qualified = result as QualifiedModuleCallbackFailure;
                    if (callback && destroyed ? qualified == null || !Object.ReferenceEquals(qualified.Original, primary) : result != null)
                        throw new InvalidOperationException("diagnostic failure was not qualified by complete destruction");
                    if (CompletionFailure(null, new List<Exception>(), callback, destroyed) != null)
                        throw new InvalidOperationException("successful cleanup invented a diagnostic failure");
                    var failure = new InvalidOperationException("fixed cleanup");
                    var group = CompletionFailure(primary, new List<Exception> { failure }, callback, destroyed) as AggregateException;
                    if (group == null || group.InnerExceptions.Count != 2 || !Object.ReferenceEquals(group.InnerExceptions[0], primary) ||
                        !Object.ReferenceEquals(group.InnerExceptions[1], failure))
                        throw new InvalidOperationException("uncertain cleanup became a qualified diagnostic result");
                }
            var cleanup = new List<Exception>(); int attempts = 0;
            AttemptCleanup(cleanup, () => { attempts++; throw new InvalidOperationException("fixed cleanup one"); });
            AttemptCleanup(cleanup, () => { attempts++; throw new InvalidOperationException("fixed cleanup two"); });
            AttemptCleanup(cleanup, () => attempts++);
            AggregateException combined = CleanupFailure(primary, cleanup);
            if (attempts != 3 || combined.InnerExceptions.Count != 3 || !Object.ReferenceEquals(combined.InnerExceptions[0], primary) ||
                !Object.ReferenceEquals(combined.InnerExceptions[1], cleanup[0]) ||
                !Object.ReferenceEquals(combined.InnerExceptions[2], cleanup[1]) || CleanupFailure(null, cleanup).InnerExceptions.Count != 2)
                throw new InvalidOperationException("owned cleanup did not preserve primary/order or attempt every phase");
        }
        internal static void AwaitActivationJobZero(Func<uint> active, Func<uint> remaining, Action<int> pause)
        {
            while (active() != 0) {
                uint milliseconds = remaining();
                if (milliseconds == 0) throw new InvalidOperationException("activation job exceeded the shared cleanup deadline");
                pause((int)Math.Min(20U, milliseconds)); // bounded kernel-state polling using only the shared remainder
            }
        }
        static void ReapJob(IntPtr job, Func<uint> remaining = null)
        {
            Native.Check(Native.TerminateJobObject(job, 125), "terminate complete owned job");
            if (remaining != null) {
                AwaitActivationJobZero(() => Native.QueryJob<Native.Accounting>(job, 1).activeProcesses, remaining, Thread.Sleep);
                return;
            }
            var deadline = Stopwatch.StartNew();
            while (Native.QueryJob<Native.Accounting>(job, 1).activeProcesses != 0) {
                if (deadline.Elapsed.TotalSeconds > 5) throw new InvalidOperationException("owned Windows job still has active processes");
                Thread.Sleep(20); // bounded kernel-state polling
            }
        }
        static void Attribute(IntPtr list, long name, IntPtr value, int bytes)
        { Native.Check(Native.UpdateProcThreadAttribute(list, 0, new IntPtr(name), value, new IntPtr(bytes), IntPtr.Zero, IntPtr.Zero), "set security attribute"); }
        static string Quote(string argument)
        {
            var result = new StringBuilder("\""); int slashes = 0;
            foreach (char c in argument) {
                if (c == '\\') { slashes++; continue; }
                if (c == '"') { result.Append('\\', slashes * 2 + 1); result.Append(c); slashes = 0; continue; }
                result.Append('\\', slashes); slashes = 0; result.Append(c);
            }
            result.Append('\\', slashes * 2); return result.Append('"').ToString();
        }
    }
}
