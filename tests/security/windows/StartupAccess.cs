using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace ScientificSecurity
{
    // Trusted preflight-only observations, not acceptance controls or permission repairs.
    internal static class StartupAccess
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool DuplicateTokenEx(IntPtr token, uint access, IntPtr attributes, int level, int kind, out IntPtr duplicate);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool ImpersonateLoggedOnUser(IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool RevertToSelf();
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenThread(uint access, bool inherit, uint tid);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CreateFileW(string path, uint access, uint sharing, IntPtr attributes, uint disposition, uint flags, IntPtr template);

        internal static void Observe(Native.ProcessInfo child, string python)
        {
            string runtime = Path.GetDirectoryName(python);
            string system = Environment.GetFolderPath(Environment.SpecialFolder.System);
            // Fixed CPython 3.11/core-runtime dependencies; no directory scan or target imports.
            var files = new [] {
                Tuple.Create("python-exe", python),
                Tuple.Create("python311", Path.Combine(runtime, "python311.dll")),
                Tuple.Create("vcruntime140", Path.Combine(runtime, "vcruntime140.dll")),
                Tuple.Create("vcruntime140-1", Path.Combine(runtime, "vcruntime140_1.dll")),
                Tuple.Create("ntdll", Path.Combine(system, "ntdll.dll")),
                Tuple.Create("kernel32", Path.Combine(system, "kernel32.dll")),
                Tuple.Create("kernelbase", Path.Combine(system, "KernelBase.dll")),
                Tuple.Create("ucrtbase", Path.Combine(system, "ucrtbase.dll")),
                Tuple.Create("ws2-32", Path.Combine(system, "ws2_32.dll")),
                Tuple.Create("bcrypt", Path.Combine(system, "bcrypt.dll")),
                Tuple.Create("version", Path.Combine(system, "version.dll")),
                Tuple.Create("pathcch", Path.Combine(system, "pathcch.dll")),
                Tuple.Create("advapi32", Path.Combine(system, "advapi32.dll")),
                Tuple.Create("shell32", Path.Combine(system, "shell32.dll")),
                Tuple.Create("ole32", Path.Combine(system, "ole32.dll")),
                Tuple.Create("oleaut32", Path.Combine(system, "oleaut32.dll"))
            };
            var observations = new List<string>(14);
            IntPtr token = IntPtr.Zero, duplicate = IntPtr.Zero;
            bool impersonating = false;
            try {
                Native.Check(Native.OpenProcessToken(child.process, 0xA, out token), "open exact suspended startup diagnostic token");
                Native.Check(DuplicateTokenEx(token, 0xC, IntPtr.Zero, 2, 2, out duplicate), "duplicate exact startup impersonation token");
                Native.Check(ImpersonateLoggedOnUser(duplicate), "enter actual suspended LPAC startup context");
                impersonating = true;
                ObserveHandle("own-process-query", 0x1000, OpenProcess(0x1000, false, child.pid), IntPtr.Zero, observations);
                ObserveHandle("own-thread-query", 0x800, OpenThread(0x800, false, child.tid), IntPtr.Zero, observations);
                foreach (var file in files)
                    ObserveHandle(file.Item1, 0xA0000000, CreateFileW(file.Item2, 0xA0000000, 7,
                        IntPtr.Zero, 3, 0x80, IntPtr.Zero), Native.InvalidHandle, observations);
            }
            finally {
                try {
                    if (impersonating && !RevertToSelf())
                        Environment.FailFast("Startup diagnostic identity restoration failed; outer owner must reap and clean up.");
                }
                finally {
                    try { if (duplicate != IntPtr.Zero) Native.Check(Native.CloseHandle(duplicate), "close startup impersonation token"); }
                    finally { if (token != IntPtr.Zero) Native.Check(Native.CloseHandle(token), "close startup source token"); }
                }
            }
            // Never log while impersonating; labels disclose neither paths nor file contents.
            foreach (string observation in observations) Console.Out.WriteLine(observation);
            Console.Out.Flush();
        }
        internal static void RequireOwnQueries(Native.ProcessInfo child, bool expectedAllowed)
        {
            IntPtr token = IntPtr.Zero, duplicate = IntPtr.Zero;
            bool impersonating = false;
            try {
                Native.Check(Native.OpenProcessToken(child.process, 0xA, out token), "open own-query control token");
                Native.Check(DuplicateTokenEx(token, 0xC, IntPtr.Zero, 2, 2, out duplicate), "duplicate own-query control token");
                Native.Check(ImpersonateLoggedOnUser(duplicate), "enter own-query actual LPAC context");
                impersonating = true;
                RequireQueryHandle(OpenProcess(0x1000, false, child.pid), expectedAllowed);
                RequireQueryHandle(OpenThread(0x800, false, child.tid), expectedAllowed);
            }
            finally {
                try {
                    if (impersonating && !RevertToSelf())
                        Environment.FailFast("Own-query identity restoration failed; outer owner must reap and clean up.");
                }
                finally {
                    try { if (duplicate != IntPtr.Zero) Native.Check(Native.CloseHandle(duplicate), "close own-query impersonation token"); }
                    finally { if (token != IntPtr.Zero) Native.Check(Native.CloseHandle(token), "close own-query source token"); }
                }
            }
            Console.Out.WriteLine("WINDOWS_OWN_QUERY_CONTROL expected_allowed=" + expectedAllowed + " process_control_passed=true thread_control_passed=true");
            Console.Out.Flush();
        }
        static void RequireQueryHandle(IntPtr handle, bool expectedAllowed)
        {
            bool opened = handle != IntPtr.Zero;
            int error = opened ? 0 : Marshal.GetLastWin32Error();
            try {
                if (opened != expectedAllowed || (!opened && error != 5))
                    throw new InvalidOperationException("own-query same-token native access control differs");
            }
            finally { if (opened) Native.Check(Native.CloseHandle(handle), "close own-query real handle"); }
        }
        static void ObserveHandle(string label, uint access, IntPtr handle, IntPtr invalid, List<string> observations)
        {
            int error = handle == invalid ? Marshal.GetLastWin32Error() : 0;
            bool opened = handle != invalid;
            try {
                observations.Add("WINDOWS_STARTUP_ACCESS label=" + label + " desired_access=0x" + access.ToString("X8")
                    + " opened=" + opened + " native_error=" + error);
            }
            finally { if (opened) Native.Check(Native.CloseHandle(handle), "close fixed startup diagnostic handle"); }
        }
    }
}
