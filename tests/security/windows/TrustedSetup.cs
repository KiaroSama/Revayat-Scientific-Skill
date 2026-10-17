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
    public static class TrustedSetup
    {
        public static string Run(string executable, string[] arguments, string cwd)
        {
            if (!Path.IsPathFullyQualified(executable) || !Path.IsPathFullyQualified(cwd))
                throw new ArgumentException("trusted setup requires fully qualified executable and working directory");
            executable = Path.GetFullPath(executable);
            cwd = Path.GetFullPath(cwd);
            string name = Path.GetFileName(executable).ToLowerInvariant();
            bool compilerPreparation = new [] { "cl.exe", "link.exe", "vswhere.exe", "dumpbin.exe", "rc.exe" }.Contains(name);
            if (compilerPreparation) { NativeFixture.Plain(executable); NativeFixture.Plain(cwd); }
            if (!compilerPreparation && !new [] { "git.exe", "icacls.exe", "fsutil.exe", "csc.exe", "pwsh.exe" }.Contains(name))
                throw new ArgumentException("unsupported trusted CI preparation tool");
            bool executableExists = File.Exists(executable), cwdExists = Directory.Exists(cwd);
            Console.Out.WriteLine(name == "dumpbin.exe" ?
                "WINDOWS_SETUP_PATH tool=dumpbin.exe executable_exists=" + executableExists + " cwd_exists=" + cwdExists :
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
            try
            {
                EmitStage(name, "prepare");
                job = Native.CreateJobObject(IntPtr.Zero, null); Native.Check(job != IntPtr.Zero, "create trusted setup job");
                var limits = new Native.ExtendedLimits();
                limits.basic.flags = 0x2000 | 8 | 4; limits.basic.processes = 16;
                limits.basic.jobTime = 60L * 10000000L;
                Native.SetJob(job, 9, limits);
                output = new Capture(); error = new Capture();
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
                if (compilerPreparation) {
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
                    true, Native.ExtendedStartup | Native.Suspended | Native.NoWindow | (compilerPreparation ? Native.UnicodeEnvironment : 0U),
                    environment, cwd, ref startup, out child),
                    "create suspended trusted setup process tool=" + name + (name == "dumpbin.exe" ? "" : " cwd=" + cwd)); started = true;
                EmitStage(name, "create-after"); EmitStage(name, "assign-before");
                Native.Check(Native.AssignProcessToJobObject(job, child.process), "own trusted setup process before resume");
                EmitStage(name, "assign-after"); EmitStage(name, "resume-before");
                if (Native.ResumeThread(child.thread) == UInt32.MaxValue)
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "resume trusted setup process");
                resumed = true; EmitStage(name, "resume-after");
                output.CloseWriter(); error.CloseWriter(); Native.CloseHandle(input); input = IntPtr.Zero;
                var clock = Stopwatch.StartNew(); long previous = 0; double progress = 0;
                uint wait; bool firstWait = true;
                while ((wait = Native.WaitForSingleObject(child.process, 100)) == 0x102)
                {
                    if (firstWait) { EmitStage(name, "wait-first"); firstWait = false; }
                    long count = output.Length() + error.Length();
                    if (count > 1048576) throw new InvalidOperationException("trusted setup output exceeded 1 MiB");
                    if (count != previous) { previous = count; progress = clock.Elapsed.TotalSeconds; }
                    if (clock.Elapsed.TotalSeconds > 60 || clock.Elapsed.TotalSeconds - progress > 20)
                        throw new TimeoutException("trusted setup command exceeded wall=60s idle=20s");
                }
                if (firstWait) EmitStage(name, "wait-first");
                EmitStage(name, "wait-complete");
                if (wait != 0) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "wait trusted setup process");
                uint exit; Native.Check(Native.GetExitCodeProcess(child.process, out exit), "read trusted setup exit code");
                EmitStage(name, "reap-before"); Reap(job); EmitStage(name, "reap-after");
                string text = output.Read(), diagnostics = error.Read();
                EmitStage(name, "capture-after");
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
                    () => { if (started && !resumed) Native.TerminateProcess(child.process, 125); },
                    () => { if (job != IntPtr.Zero) Reap(job); },
                    () => { if (output != null) output.Dispose(); },
                    () => { if (error != null) error.Dispose(); },
                    () => { if (child.thread != IntPtr.Zero) Native.CloseHandle(child.thread); },
                    () => { if (child.process != IntPtr.Zero) Native.CloseHandle(child.process); },
                    () => { if (input != IntPtr.Zero && input != Native.InvalidHandle) Native.CloseHandle(input); },
                    () => { if (attrs != IntPtr.Zero) Native.DeleteProcThreadAttributeList(attrs); },
                    () => { if (attrs != IntPtr.Zero) Marshal.FreeHGlobal(attrs); },
                    () => { if (list != IntPtr.Zero) Marshal.FreeHGlobal(list); },
                    () => { if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment); },
                    () => { if (job != IntPtr.Zero) Native.CloseHandle(job); },
                    () => EmitStage(name, "cleanup-after"));
            }
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
            if (!new [] { "cl.exe", "link.exe", "vswhere.exe", "dumpbin.exe", "rc.exe", "git.exe", "icacls.exe", "fsutil.exe", "csc.exe", "pwsh.exe" }.Contains(tool) ||
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
