using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Principal;

namespace ScientificSecurity
{
    public static partial class StartupActivationAccess
    {
        static void RequirePreparationHost()
        {
            using (WindowsIdentity current = WindowsIdentity.GetCurrent(true))
                if (current != null) throw new InvalidOperationException("host preparation thread is impersonating");
        }
        static void LeavePreparation(ref bool impersonating)
        {
            FinalizeComparison(null, impersonating, RevertToSelf,
                () => Environment.FailFast("Host preparation identity restoration failed; outer owner must reap and clean up."), () => { });
            impersonating = false;
        }
        internal static void PrepareHostPython(Native.ProcessInfo child, string python, string package,
            PythonActivationPreparation.Observation observation)
        {
            PythonActivationPreparation.Need(observation != null && observation.host); observation.RequireFresh();
            ushort language = PythonCsrDispatch.PreparedLanguage(python); RequirePreparationHost();
            IntPtr token = IntPtr.Zero, duplicate = IntPtr.Zero; bool impersonating = false;
            Exception primary = null; var lines = new List<string>(); var clock = Stopwatch.StartNew();
            try {
                Native.Check(Native.OpenProcessToken(child.process, 0xA, out token), "open exact host preparation primary token");
                Native.Check(DuplicateTokenEx(token, 0xC, IntPtr.Zero, 2, 2, out duplicate), "duplicate exact host preparation token");
                Native.Check(ImpersonateLoggedOnUser(duplicate), "enter initial host preparation LPAC qualification");
                impersonating = true;
                PythonActivationPreparation.PrepareHost(observation, () => new RegistryContext(token, duplicate, package).RequireThread(), () => Deadline(clock),
                    () => ChildDefaultDacl.Read(token), () => ChildDefaultDacl.Read(duplicate),
                    () => ObserveOne("host", python, language, lines, clock, null),
                    () => LeavePreparation(ref impersonating), RequirePreparationHost,
                    () => {
                        Native.Check(ImpersonateLoggedOnUser(duplicate), "reenter exact host preparation LPAC qualification");
                        impersonating = true;
                    });
            }
            catch (Exception failure) { primary = failure; throw; }
            finally {
                FinalizeComparison(primary, impersonating, RevertToSelf,
                    () => Environment.FailFast("Host preparation identity restoration failed; outer owner must reap and clean up."),
                    () => {
                        PythonActivationPreparation.Need(lines.Count == (observation.attempted ? 1 : 0));
                        if (observation.prepared && observation.attempted) observation.Activation(lines[0]);
                    },
                    () => { if (duplicate != IntPtr.Zero) Native.Check(Native.CloseHandle(duplicate), "close host preparation duplicate token"); },
                    () => { if (token != IntPtr.Zero) Native.Check(Native.CloseHandle(token), "close host preparation primary token"); });
            }
        }
    }
}
