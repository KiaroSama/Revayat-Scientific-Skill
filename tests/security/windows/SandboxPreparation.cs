using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

namespace ScientificSecurity
{
    public static partial class Sandbox
    {
        static void PrepareContained(Native.ProcessInfo process, string python, string scratch, string moniker, string package,
            bool preflight, bool wallProbe, bool loaderProbe, bool activationProbe, bool activationTrace, bool nativeFixture,
            bool pythonCondition, bool pythonDispatch, int? expectedRegistryStatus, DefaultDaclComparison.Observation defaultDacl,
            PythonActivationPreparation.Observation preparation, RegistryDiagnostic registryStartup)
        {
            bool passComparison = preparation != null || registryStartup != null;
            Profile.SealRegistry(process.process, moniker, package);
            TokenPolicy.Prepare(process.process, Path.GetPathRoot(scratch), package);
            Profile.RequireReadOnlyRegistry(process.process, moniker, package);
            if (preflight && !wallProbe && !loaderProbe && defaultDacl == null && !passComparison) {
                StartupAccess.Observe(process, python);
                StartupImageAccess.Observe(process, python, package);
                int registryStatus = StartupActivationAccess.Observe(process, python, package);
                if (expectedRegistryStatus.HasValue) RequireRegistryCondition(registryStatus, expectedRegistryStatus.Value);
                StartupAccess.RequireOwnQueries(process, false);
            }
            PrepareOwnProcessAccess(process, registryStartup != null);
            StartupAccess.RequireOwnQueries(process, true);
            Stopwatch defaultClock = defaultDacl == null ? null : Stopwatch.StartNew();
            if (pythonCondition || defaultDacl != null || pythonDispatch || preparation != null)
                RequireRegistryCondition(StartupRegistryAccess.ObserveChild(process, package), expectedRegistryStatus.Value);
            if (registryStartup != null) StartupActivationAccess.PrepareRegistryStartup(process, package, registryStartup);
            if (preparation != null) {
                if (preparation.host || preparation.compound) StartupActivationAccess.PrepareHostPython(process, python, package, preparation);
                else StartupActivationAccess.PreparePython(process, python, package, preparation);
            }
            if (defaultDacl != null)
                defaultDacl.opened = DefaultDaclControl.Prepare(process, package,
                    defaultDacl.condition == DefaultDaclComparison.Condition.UserAllow, defaultClock, out defaultDacl.baseline);
            if (preflight && !wallProbe && !loaderProbe && !activationProbe && !activationTrace && defaultDacl == null && !passComparison)
                StartupTokenAccess.Observe(process, package);
            if (nativeFixture) {
                string metadata = TokenDefaultMetadata.Observe(process.process);
                Console.Out.WriteLine(metadata); Console.Out.Flush();
            }
        }
        static List<string> RegistryArguments(string python, string root, RegistryDiagnostic observation)
        {
            if (observation is RegistryAuthorityComparison.Observation && !(observation is RegistryAuthorityComparison.PythonObservation))
                return new List<string> { RegistryAuthorityFixture.Image(python) };
            if (observation is RegistryAuthorityComparison.PythonObservation) {
                PythonCsrDispatch.PreparedImage(python);
                return new List<string> { python, "-I", "-B", "-X", "utf8", Path.Combine(root, "tests", "security", "windows", "RegistryAuthorityProbe.py") };
            }
            var arguments = new List<string> { python, "-I", "-B", "-c", "pass" };
            PythonCsrDispatch.RequireLaunch(python, arguments.GetRange(1, arguments.Count - 1).ToArray(), Path.GetDirectoryName(python));
            return arguments;
        }
        internal static void ObserveRegistryAuthority(string python, string root, string scratch, string powershell,
            string chromium, string moniker, string profileFolder, int tcpPort, int udpPort, RegistryAuthorityComparison.Observation observation)
        {
            if (observation == null) throw new ArgumentNullException("observation");
            observation.RequireFresh();
            RunFixed(python, root, scratch, powershell, chromium, moniker, profileFolder, true, tcpPort, udpPort,
                false, false, false, false, false, false, false, 0, registryStartup: observation);
            observation.Complete();
        }
    }
}
