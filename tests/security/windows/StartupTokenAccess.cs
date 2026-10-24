using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace ScientificSecurity
{
    // Post-repair token-object access only, not an explanation of earlier activation or child startup.
    public static class StartupTokenAccess
    {
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool DuplicateTokenEx(
            IntPtr token, uint access, IntPtr attributes, int level, int kind, out IntPtr duplicate);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool ImpersonateLoggedOnUser(IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool RevertToSelf();

        static bool Valid(IntPtr handle)
        { return handle != IntPtr.Zero && handle != Native.InvalidHandle; }
        static string Outcome(string context, bool opened, IntPtr handle, uint error)
        {
            if ((context != "host" && context != "lpac") ||
                (opened ? !Valid(handle) || error != 0 : handle != IntPtr.Zero || error == 0))
                throw new InvalidOperationException("token-query result/context/handle is inconsistent");
            return "WINDOWS_STARTUP_TOKEN context=" + context + " desired_access=0x" + Native.TokenQuery.ToString("X8") +
                " opened=" + opened + " win32_error=" + error + " cause_claimed=False child_equivalence_claimed=False";
        }
        static void Attempt(List<Exception> failures, Action action)
        { try { action(); } catch (Exception failure) { failures.Add(failure); } }
        static void Finish(Exception primary, List<Exception> failures)
        {
            if (failures.Count == 0) return;
            if (primary != null) failures.Insert(0, primary);
            throw new AggregateException("fixed token-query operation/cleanup failed", failures);
        }
        static void Deadline(Stopwatch clock)
        { if (clock.Elapsed.TotalSeconds > 10) throw new TimeoutException("fixed token-query comparison exceeded 10 seconds"); }
        static void Close(ref IntPtr handle)
        {
            IntPtr owned = handle; handle = IntPtr.Zero;
            if (Valid(owned)) Native.Check(Native.CloseHandle(owned), "close fixed token-query handle");
        }
        static bool ObserveOne(string label, Native.ProcessInfo child, ref IntPtr query, List<string> lines, Stopwatch clock)
        {
            Deadline(clock);
            bool opened = Native.OpenProcessToken(child.process, Native.TokenQuery, out query);
            uint error = opened ? 0 : unchecked((uint)Marshal.GetLastWin32Error());
            lines.Add(Outcome(label, opened, query, error));
            Deadline(clock); return opened;
        }
        internal static void Observe(Native.ProcessInfo child, string package)
        {
            using (WindowsIdentity current = WindowsIdentity.GetCurrent(true))
                if (current != null) throw new InvalidOperationException("token-query host is already impersonating");
            IntPtr primaryToken = IntPtr.Zero, duplicate = IntPtr.Zero, query = IntPtr.Zero;
            bool impersonating = false; Exception primary = null;
            var lines = new List<string>(2); var clock = Stopwatch.StartNew();
            try {
                Deadline(clock);
                Native.Check(Native.OpenProcessToken(child.process, 0xA, out primaryToken), "open exact token-query primary");
                if (!Valid(primaryToken)) throw new InvalidOperationException("token-query primary handle is invalid");
                Deadline(clock);
                Native.Check(DuplicateTokenEx(primaryToken, 0xC, IntPtr.Zero, 2, 2, out duplicate), "duplicate exact token-query context");
                if (!Valid(duplicate)) throw new InvalidOperationException("token-query duplicate handle is invalid");
                var context = new RegistryContext(primaryToken, duplicate, package); Deadline(clock);
                if (!ObserveOne("host", child, ref query, lines, clock))
                    throw new InvalidOperationException("host token-query positive control failed");
                Close(ref query); Deadline(clock);
                Native.Check(ImpersonateLoggedOnUser(duplicate), "enter exact token-query LPAC context");
                impersonating = true; context.RequireThread(); Deadline(clock);
                ObserveOne("lpac", child, ref query, lines, clock);
                context.RequireThread(); Deadline(clock);
            }
            catch (Exception failure) { primary = failure; throw; }
            finally {
                var failures = new List<Exception>();
                if (impersonating && !RevertToSelf())
                    Environment.FailFast("Token-query identity restoration failed; outer owner must reap and clean up.");
                Attempt(failures, () => Close(ref query));
                Attempt(failures, () => Close(ref duplicate));
                Attempt(failures, () => Close(ref primaryToken));
                Attempt(failures, () => { foreach (string line in lines) Console.Out.WriteLine(line); Console.Out.Flush(); });
                Finish(primary, failures);
            }
        }
        public static void CheckValidation()
        {
            if (Native.TokenQuery != 8 ||
                Outcome("host", true, new IntPtr(1), 0) !=
                    "WINDOWS_STARTUP_TOKEN context=host desired_access=0x00000008 opened=True win32_error=0 cause_claimed=False child_equivalence_claimed=False" ||
                Outcome("lpac", false, IntPtr.Zero, 5) !=
                    "WINDOWS_STARTUP_TOKEN context=lpac desired_access=0x00000008 opened=False win32_error=5 cause_claimed=False child_equivalence_claimed=False")
                throw new InvalidOperationException("fixed token-query result formatting differs");
            foreach (Action invalid in new Action[] {
                () => Outcome("private-sentinel", true, new IntPtr(1), 0),
                () => Outcome("host", true, IntPtr.Zero, 0),
                () => Outcome("host", true, Native.InvalidHandle, 0),
                () => Outcome("host", true, new IntPtr(1), 5),
                () => Outcome("lpac", false, new IntPtr(1), 5),
                () => Outcome("lpac", false, Native.InvalidHandle, 5),
                () => Outcome("lpac", false, IntPtr.Zero, 0)
            }) {
                bool refused = false;
                try { invalid(); }
                catch (InvalidOperationException failure) {
                    if (failure.Message.Contains("private-sentinel"))
                        throw new InvalidOperationException("token-query refusal leaked a private label");
                    refused = true;
                }
                if (!refused) throw new InvalidOperationException("inconsistent token-query result was accepted");
            }
            var primary = new IOException("fixed primary");
            var first = new IOException("fixed first cleanup");
            var second = new IOException("fixed second cleanup");
            var failures = new List<Exception>(); int attempts = 0;
            Attempt(failures, () => { attempts++; throw first; });
            Attempt(failures, () => { attempts++; throw second; });
            Attempt(failures, () => attempts++);
            Finish(primary, new List<Exception>());
            try { Finish(primary, failures); }
            catch (AggregateException failure) {
                if (attempts == 3 && failure.InnerExceptions.Count == 3 &&
                    Object.ReferenceEquals(failure.InnerExceptions[0], primary) &&
                    Object.ReferenceEquals(failure.InnerExceptions[1], first) &&
                    Object.ReferenceEquals(failure.InnerExceptions[2], second)) return;
                throw;
            }
            throw new InvalidOperationException("token-query cleanup lost primary/order or an attempt");
        }
    }
}
