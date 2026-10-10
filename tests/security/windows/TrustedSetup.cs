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
            if (!new [] { "git.exe", "icacls.exe", "fsutil.exe", "csc.exe", "pwsh.exe" }.Contains(name))
                throw new ArgumentException("unsupported trusted CI preparation tool");
            if (!File.Exists(executable) || !Directory.Exists(cwd))
                throw new ArgumentException("trusted setup executable or working directory does not exist after native path normalization");
            IntPtr job = IntPtr.Zero, attrs = IntPtr.Zero;
            IntPtr list = IntPtr.Zero, input = IntPtr.Zero;
            Capture output = null, error = null;
            var child = new Native.ProcessInfo(); bool started = false, resumed = false;
            try
            {
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
                // CI-only prepared paths, never command arguments or document contents.
                Console.Out.WriteLine("WINDOWS_SETUP_PATH executable=" + Quote(executable) + " cwd=" + Quote(cwd));
                Console.Out.Flush();
                Native.Check(Native.CreateProcessW(executable, new StringBuilder(command), IntPtr.Zero, IntPtr.Zero,
                    true, Native.ExtendedStartup | Native.Suspended | Native.NoWindow, IntPtr.Zero, cwd, ref startup, out child),
                    "create suspended trusted setup process tool=" + name + " cwd=" + cwd); started = true;
                Native.Check(Native.AssignProcessToJobObject(job, child.process), "own trusted setup process before resume");
                if (Native.ResumeThread(child.thread) == UInt32.MaxValue)
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "resume trusted setup process");
                resumed = true; output.CloseWriter(); error.CloseWriter(); Native.CloseHandle(input); input = IntPtr.Zero;
                var clock = Stopwatch.StartNew(); long previous = 0; double progress = 0;
                uint wait;
                while ((wait = Native.WaitForSingleObject(child.process, 100)) == 0x102)
                {
                    long count = output.Length() + error.Length();
                    if (count > 1048576) throw new InvalidOperationException("trusted setup output exceeded 1 MiB");
                    if (count != previous) { previous = count; progress = clock.Elapsed.TotalSeconds; }
                    if (clock.Elapsed.TotalSeconds > 60 || clock.Elapsed.TotalSeconds - progress > 20)
                        throw new TimeoutException("trusted setup command exceeded wall=60s idle=20s");
                }
                if (wait != 0) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "wait trusted setup process");
                uint exit; Native.Check(Native.GetExitCodeProcess(child.process, out exit), "read trusted setup exit code");
                Reap(job);
                string text = output.Read(), diagnostics = error.Read();
                if (Encoding.UTF8.GetByteCount(text) + Encoding.UTF8.GetByteCount(diagnostics) > 1048576)
                    throw new InvalidOperationException("combined trusted setup output exceeded 1 MiB");
                if (exit != 0) throw new InvalidOperationException("trusted setup " + name + " failed exit=" + exit + " " + diagnostics + " " + text);
                return text;
            }
            finally
            {
                try {
                    if (started && !resumed) Native.TerminateProcess(child.process, 125);
                    if (job != IntPtr.Zero) Reap(job);
                }
                finally {
                    try { if (output != null) output.Dispose(); }
                    finally {
                        try { if (error != null) error.Dispose(); }
                        finally {
                            if (child.thread != IntPtr.Zero) Native.CloseHandle(child.thread);
                            if (child.process != IntPtr.Zero) Native.CloseHandle(child.process);
                            if (input != IntPtr.Zero && input != Native.InvalidHandle) Native.CloseHandle(input);
                            if (attrs != IntPtr.Zero) { Native.DeleteProcThreadAttributeList(attrs); Marshal.FreeHGlobal(attrs); }
                            if (list != IntPtr.Zero) Marshal.FreeHGlobal(list);
                            if (job != IntPtr.Zero) Native.CloseHandle(job);
                        }
                    }
                }
            }
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
        static string Quote(string value)
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
