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
                                 string chromium, string moniker, bool preflight, int tcpPort, int udpPort, bool wallProbe = false)
        {
            string probe = preflight ? Path.Combine(root, "tests", "security", "windows", "KernelProbe.py")
                                     : Path.Combine(root, "tests", "security", "windows_probe.py");
            string phase = wallProbe ? "wall" : (preflight ? "preflight" : "regressions");
            var arguments = new List<string> { python, "-I", "-B", "-X", "utf8", probe, root, scratch, powershell };
            if (preflight) { arguments.Add(tcpPort.ToString()); arguments.Add(udpPort.ToString()); }
            if (wallProbe) arguments.Add("wall-tree");
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
            bool started = false, resumed = false;
            Capture outputCapture = null, errorCapture = null;
            try
            {
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
                outputCapture = new Capture(); errorCapture = new Capture();
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
                Native.Check(Native.CreateProcessW(python, new StringBuilder(command), processAttributes, processAttributes, true,
                    Native.ExtendedStartup | Native.Suspended | Native.NoWindow | Native.UnicodeEnvironment,
                    env, scratch, ref startup, out process), "create suspended LPAC child");
                started = true;
                SetUserOwner(process.process);
                Native.Check(Native.AssignProcessToJobObject(job, process.process), "assign owned resource job before resume");
                if (Native.ResumeThread(process.thread) == UInt32.MaxValue)
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "resume contained child");
                resumed = true;
                foreach (IntPtr handle in handles) Native.CloseHandle(handle);
                handles.Clear(); outputCapture.CloseWriter(); errorCapture.CloseWriter();
                var clock = Stopwatch.StartNew();
                long previous = 0; double progress = 0;
                while (Native.WaitForSingleObject(process.process, 100) == 0x102)
                {
                    long length = outputCapture.Length() + errorCapture.Length();
                    if (length > 1048576) throw new InvalidOperationException("worker standard output exceeded 1 MiB");
                    if (length != previous) { previous = length; progress = clock.Elapsed.TotalSeconds; }
                    if (clock.Elapsed.TotalSeconds > (wallProbe ? 2 : 60) || clock.Elapsed.TotalSeconds - progress > 20)
                        throw new TimeoutException("owned Windows worker wall/idle ceiling exceeded");
                }
                uint exit; Native.Check(Native.GetExitCodeProcess(process.process, out exit), "read worker exit");
                ReapJob(job);
                string text = outputCapture.Read(), errors = errorCapture.Read();
                if (Encoding.UTF8.GetByteCount(text) + Encoding.UTF8.GetByteCount(errors) > 1048576)
                    throw new InvalidOperationException("combined worker output exceeded 1 MiB");
                if (exit != 0) throw new InvalidOperationException("Windows " + phase + " failed exit=" + exit + " " + errors + " " + text);
                if (!String.IsNullOrWhiteSpace(errors)) throw new InvalidOperationException("unexpected worker error output: " + errors);
                if (wallProbe) throw new InvalidOperationException("wall negative control exited before owned deadline");
                return text;
            }
            catch (TimeoutException)
            {
                if (!wallProbe) throw;
                return "WALL_TREE_TERMINATED";
            }
            finally
            {
                try
                {
                    if (started && !resumed) Native.Check(Native.TerminateProcess(process.process, 125), "terminate suspended child");
                    if (job != IntPtr.Zero) ReapJob(job);
                }
                finally
                {
                    try { if (outputCapture != null) outputCapture.Dispose(); }
                    finally
                    {
                        try { if (errorCapture != null) errorCapture.Dispose(); }
                        finally
                        {
                            if (process.thread != IntPtr.Zero) Native.CloseHandle(process.thread);
                            if (process.process != IntPtr.Zero) Native.CloseHandle(process.process);
                            foreach (IntPtr handle in handles) Native.CloseHandle(handle);
                            if (attrs != IntPtr.Zero) { Native.DeleteProcThreadAttributeList(attrs); Marshal.FreeHGlobal(attrs); }
                            foreach (IntPtr value in values) Marshal.FreeHGlobal(value);
                            if (env != IntPtr.Zero) Marshal.FreeHGlobal(env);
                            if (processDescriptor != IntPtr.Zero) Native.LocalFree(processDescriptor);
                            if (sid != IntPtr.Zero) Native.FreeSid(sid);
                            if (job != IntPtr.Zero) Native.CloseHandle(job);
                        }
                    }
                }
            }
        }
        static void ReapJob(IntPtr job)
        {
            Native.Check(Native.TerminateJobObject(job, 125), "terminate complete owned job");
            var deadline = Stopwatch.StartNew();
            while (Native.QueryJob<Native.Accounting>(job, 1).activeProcesses != 0) {
                if (deadline.Elapsed.TotalSeconds > 5) throw new InvalidOperationException("owned Windows job still has active processes");
                Thread.Sleep(20); // bounded kernel-state polling
            }
        }
        static void SetUserOwner(IntPtr process)
        {
            IntPtr token = IntPtr.Zero, data = IntPtr.Zero, owner = IntPtr.Zero;
            try
            {
                Native.Check(Native.OpenProcessToken(process, 0x88, out token), "open child owner token");
                uint size;
                Native.GetTokenInformation(token, 1, IntPtr.Zero, 0, out size);
                if (size == 0) throw new InvalidOperationException("child user SID unavailable");
                data = Marshal.AllocHGlobal((int)size);
                Native.Check(Native.GetTokenInformation(token, 1, data, size, out size), "query child user SID");
                owner = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(owner, Marshal.ReadIntPtr(data));
                Native.Check(Native.SetTokenInformation(token, 4, owner, (uint)IntPtr.Size), "set child file owner to quota user SID");
            }
            finally
            {
                if (owner != IntPtr.Zero) Marshal.FreeHGlobal(owner);
                if (data != IntPtr.Zero) Marshal.FreeHGlobal(data);
                if (token != IntPtr.Zero) Native.CloseHandle(token);
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
