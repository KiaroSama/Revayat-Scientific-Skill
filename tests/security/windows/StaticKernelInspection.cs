using System;
using System.Globalization;
using System.IO;

namespace ScientificSecurity
{
    // Fixed same-run file inspection only. The inspected DLL is never loaded or executed here.
    public static class StaticKernelInspection
    {
        static string expectedIdentity, expectedActivationIdentity;
        public static void RunFixed(string state)
        {
            if (expectedIdentity != null) throw new InvalidOperationException("static KernelBase inspection is already bound for this run");
            string phase = "input-path";
            try {
                NativeFixture.Plain(state);
                string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "kernelbase.dll");
                NativeFixture.Plain(path);
                phase = "held-open";
                using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                    phase = "held-read"; byte[] bytes = ReadHeld(stream);
                    phase = "image"; var image = KernelImage.FromStatic(bytes);
                    phase = "identity"; string identity = image.KernelBaseIdentity();
                    phase = "slice"; var slice = image.EntrySlice();
                    phase = "tool-discovery"; var tools = NativeFixture.CompilerTools(state);
                    string dumpbin = Path.Combine(Path.GetDirectoryName(tools.Item1), "dumpbin.exe"); NativeFixture.Plain(dumpbin);
                    string range = "/RANGE:0x" + slice.Start.ToString("X", CultureInfo.InvariantCulture) + ",0x" +
                        (slice.Start + slice.Length - 1).ToString("X", CultureInfo.InvariantCulture);
                    phase = "tool"; string text = TrustedSetup.Run(dumpbin, new [] { "/NOLOGO", "/NOPDB", "/DISASM:BYTES", range, path }, state);
                    phase = "post-path"; NativeFixture.Plain(path);
                    phase = "posthash"; RequireSame(identity, KernelImage.FromStatic(ReadHeld(stream)).KernelBaseIdentity());
                    phase = "qualifier"; var view = image.QualifyStatic(text);
                    phase = "observation-profile";
                    try { image.RequireObservationStatic(view); }
                    catch (Exception failure) { ReportObservationFailure(failure, identity, line => { Console.Error.WriteLine(line); Console.Error.Flush(); }); throw; }
                    expectedIdentity = identity; // Bind only after successful post-tool same-held-file and fixed-profile checks.
                    phase = "evidence-output";
                    Console.Out.WriteLine("WINDOWS_STATIC_KERNEL phase=entry-slice module=kernelbase.dll records=" + view.Records +
                        " unsupported_lines=" + view.Unsupported + " evidence=" + (view.Unsupported == 0 ? "qualified-records" : "partial") +
                        " slice_bytes=" + slice.Length + " complete_slice_claimed=False cause_claimed=False abi_claimed=False");
                    Console.Out.Write(view.Text); Console.Out.Flush();
                    phase = "held-close";
                }
            }
            catch (Exception) when (ReportFailurePhase(phase)) { throw; }
            catch (IOException) { throw new InvalidOperationException("static KernelBase held-file inspection I/O failed; details withheld"); }
            catch (UnauthorizedAccessException) { throw new InvalidOperationException("static KernelBase held-file inspection access failed; details withheld"); }
        }
        public static void RunActivationWorker(string state)
        {
            string phase = "input-path";
            try {
                NativeFixture.Plain(state);
                string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "kernel32.dll");
                NativeFixture.Plain(path);
                phase = "held-open";
                using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                    phase = "held-read"; var image = KernelImage.FromActivationWorker(ReadHeld(stream));
                    phase = "identity"; string identity = image.ActivationWorkerIdentity();
                    phase = "fixed-export"; var slice = image.ActivationWorkerSlice();
                    phase = "tool-discovery"; var tools = NativeFixture.CompilerTools(state);
                    string dumpbin = Path.Combine(Path.GetDirectoryName(tools.Item1), "dumpbin.exe"); NativeFixture.Plain(dumpbin);
                    string range = "/RANGE:0x" + slice.Start.ToString("X", CultureInfo.InvariantCulture) + ",0x" +
                        (slice.Start + slice.Length - 1).ToString("X", CultureInfo.InvariantCulture);
                    phase = "tool"; string text = TrustedSetup.Run(dumpbin, new [] { "/NOLOGO", "/NOPDB", "/DISASM:BYTES", range, path }, state);
                    phase = "post-path"; NativeFixture.Plain(path);
                    phase = "posthash"; RequireSame(identity, KernelImage.FromActivationWorker(ReadHeld(stream)).ActivationWorkerIdentity());
                    phase = "qualifier"; var view = image.QualifyStatic(text, slice);
                    phase = "module-callback-profile";
                    QualifyActivation(() => image.RequireModuleCallbackProfile(), identity,
                        line => { Console.Error.WriteLine(line); Console.Error.Flush(); }, () => expectedActivationIdentity = identity);
                    phase = "evidence-output";
                    Console.Out.WriteLine("WINDOWS_STATIC_ACTIVATION " + identity);
                    Console.Out.WriteLine("WINDOWS_STATIC_ACTIVATION phase=worker-slice module=kernel32.dll export=CreateActCtxWWorker records=" + view.Records +
                        " unsupported_lines=" + view.Unsupported + " evidence=" + (view.Unsupported == 0 ? "qualified-records" : "partial") +
                        " slice_bytes=" + slice.Length + " runtime_host_claimed=False complete_slice_claimed=False cause_claimed=False abi_claimed=False");
                    Console.Out.Write(view.Text); Console.Out.Flush();
                    phase = "held-close";
                }
            }
            catch (Exception failure) { throw new ActivationFailure(phase, failure); }
        }
        internal static void BindActivationLoad(KernelImage image)
        {
            if (expectedActivationIdentity == null) throw new InvalidOperationException("activation static identity was not qualified");
            RequireSame(expectedActivationIdentity, image.ActivationWorkerIdentity());
        }
        // Keep the original graph outside InnerException: the generic PowerShell reporter prints that chain's messages.
        sealed class ActivationFailure : Exception
        {
            internal readonly string Phase;
            internal readonly Exception Original;
            internal readonly System.Collections.Generic.List<Exception> ReportingFailures = new System.Collections.Generic.List<Exception>();
            internal ActivationFailure(string phase, Exception original)
                : base("fixed activation-worker static inspection failed; details withheld")
            { Phase = phase; Original = original; }
        }
        static ActivationFailure FindActivationFailure(Exception failure)
        {
            for (int wrappers = 0; failure != null && !(failure is ActivationFailure) && wrappers < 4; wrappers++)
                failure = failure.InnerException;
            return failure as ActivationFailure;
        }
        public static void RetainActivationReportingFailure(Exception failure, Exception reportingFailure)
        {
            var carrier = FindActivationFailure(failure);
            if (carrier == null || reportingFailure == null)
                throw new InvalidOperationException("fixed activation reporting failure has no owning operation");
            carrier.ReportingFailures.Add(reportingFailure);
        }
        public static string ActivationFailureReport(Exception failure)
        {
            var carrier = FindActivationFailure(failure);
            if (carrier == null) return null;
            var output = new System.Text.StringBuilder("WINDOWS_STATIC_ACTIVATION failure_phase=" + carrier.Phase + "\n");
            var pending = new System.Collections.Generic.Stack<Tuple<Exception, int>>();
            pending.Push(Tuple.Create(carrier.Original, 0));
            int visited = 0, causes = 0; bool truncated = false;
            while (pending.Count != 0 && visited < 32 && causes < 16) {
                var item = pending.Pop(); visited++;
                var aggregate = item.Item1 as AggregateException;
                if (aggregate != null && aggregate.InnerExceptions.Count != 0) {
                    if (item.Item2 >= 4) { truncated = true; continue; }
                    int count = Math.Min(aggregate.InnerExceptions.Count, 32 - visited - pending.Count);
                    if (count != aggregate.InnerExceptions.Count) truncated = true;
                    for (int index = count - 1; index >= 0; index--)
                        pending.Push(Tuple.Create(aggregate.InnerExceptions[index], item.Item2 + 1));
                    continue;
                }
                string category = item.Item1 is TimeoutException ? "timeout" :
                    item.Item1 is System.ComponentModel.Win32Exception ? "os_error" :
                    item.Item1 is UnauthorizedAccessException ? "access_error" :
                    item.Item1 is IOException ? "io_error" :
                    item.Item1 is InvalidOperationException ? "contract_error" : "unknown_failure";
                output.Append("WINDOWS_STATIC_ACTIVATION cause_index=").Append(causes++)
                    .Append(" category=").Append(category);
                var native = item.Item1 as System.ComponentModel.Win32Exception;
                if (native != null) output.Append(" winerror=").Append(unchecked((uint)native.NativeErrorCode).ToString(CultureInfo.InvariantCulture));
                output.Append('\n');
            }
            output.Append("WINDOWS_STATIC_ACTIVATION failure_causes=").Append(causes)
                .Append(" truncated=").Append(truncated || pending.Count != 0);
            return output.ToString();
        }
        static void QualifyActivation(Action qualify, string identity, Action<string> emit, Action bind)
        {
            try { qualify(); }
            catch (Exception failure) { ReportObservationFailure(failure, identity, emit, true); throw; }
            bind();
        }
        static void ReportObservationFailure(Exception primary, string identity, Action<string> emit, bool activation = false)
        {
            try { emit((activation ? "WINDOWS_STATIC_ACTIVATION" : "WINDOWS_STATIC_KERNEL") + " profile_accepted=False " + identity); }
            catch (Exception reporting) { throw new AggregateException("static profile qualification/reporting failed", primary, reporting); }
        }
        static bool ReportFailurePhase(string phase)
        {
            Console.Error.WriteLine("WINDOWS_STATIC_KERNEL failure_phase=" + phase); Console.Error.Flush();
            return false; // Observe the fixed stage without catching, replacing or exposing the original exception.
        }
        static byte[] ReadHeld(FileStream stream)
        {
            if (stream.Length < 256 || stream.Length > 16 * 1024 * 1024)
                throw new InvalidOperationException("static KernelBase file exceeds fixed image bound");
            stream.Position = 0; byte[] bytes = new byte[(int)stream.Length]; int offset = 0;
            while (offset < bytes.Length) {
                int read = stream.Read(bytes, offset, Math.Min(65536, bytes.Length - offset));
                if (read == 0) throw new InvalidOperationException("static held KernelBase file read was truncated");
                offset += read;
            }
            if (stream.ReadByte() != -1 || stream.Length != bytes.Length)
                throw new InvalidOperationException("static held KernelBase file length changed");
            return bytes;
        }
        static void RequireSame(string expected, string actual)
        {
            if (String.IsNullOrEmpty(expected) || !String.Equals(expected, actual, StringComparison.Ordinal))
                throw new InvalidOperationException("static KernelBase same-run file identity is unavailable or changed");
        }
        internal static uint BindLoad(KernelImage image)
        {
            RequireSame(expectedIdentity, image.KernelBaseIdentity());
            uint site = image.RequireObservationProfile();
            Console.Out.WriteLine("WINDOWS_STATIC_KERNEL phase=load-binding identity_equal=True fixed_profile=True"); Console.Out.Flush();
            return site;
        }
        public static void CheckValidation()
        {
            var timeout = new TimeoutException("private-timeout-sentinel");
            var cleanup = new IOException("private-cleanup-sentinel");
            var nativeCleanup = new System.ComponentModel.Win32Exception(5, "private-native-sentinel");
            var original = new AggregateException("private-group-sentinel", timeout, cleanup, nativeCleanup);
            var carrier = new ActivationFailure("tool", original);
            if (!Object.ReferenceEquals(carrier.Original, original) || carrier.InnerException != null ||
                !Object.ReferenceEquals(original.InnerExceptions[0], timeout) ||
                !Object.ReferenceEquals(original.InnerExceptions[1], cleanup) ||
                !Object.ReferenceEquals(original.InnerExceptions[2], nativeCleanup))
                throw new InvalidOperationException("fixed activation failure lost original ordered outcomes");
            string report = ActivationFailureReport(new Exception("private-wrapper-sentinel", carrier));
            const string expected = "WINDOWS_STATIC_ACTIVATION failure_phase=tool\n" +
                "WINDOWS_STATIC_ACTIVATION cause_index=0 category=timeout\n" +
                "WINDOWS_STATIC_ACTIVATION cause_index=1 category=io_error\n" +
                "WINDOWS_STATIC_ACTIVATION cause_index=2 category=os_error winerror=5\n" +
                "WINDOWS_STATIC_ACTIVATION failure_causes=3 truncated=False";
            Exception propagated = null;
            try { throw carrier; } catch (Exception failure) { propagated = failure; }
            var reportingFailure = new IOException("private-reporting-sentinel");
            RetainActivationReportingFailure(new Exception("private-wrapper-sentinel", carrier), reportingFailure);
            if (carrier.ReportingFailures.Count != 1 || !Object.ReferenceEquals(carrier.ReportingFailures[0], reportingFailure) ||
                !Object.ReferenceEquals(carrier.Original, original) || ActivationFailureReport(carrier) != expected)
                throw new InvalidOperationException("fixed activation reporting failure replaced original outcomes");
            if (report != expected || !Object.ReferenceEquals(propagated, carrier) || carrier.ToString().Contains("sentinel") ||
                ActivationFailureReport(new Exception("private-unrelated-sentinel")) != null)
                throw new InvalidOperationException("fixed activation failure reporting lost status, order or privacy");
            var cleanupOnly = new ActivationFailure("held-close", new AggregateException("private-cleanups", cleanup, nativeCleanup));
            string cleanupReport = ActivationFailureReport(cleanupOnly);
            if (!cleanupReport.Contains("cause_index=0 category=io_error\nWINDOWS_STATIC_ACTIVATION cause_index=1 category=os_error winerror=5") ||
                cleanupReport.Contains("primary") || cleanupReport.Contains("private"))
                throw new InvalidOperationException("fixed activation cleanup-only reporting invented a primary role");
            var many = new Exception[40]; for (int index = 0; index < many.Length; index++) many[index] = timeout;
            string wide = ActivationFailureReport(new ActivationFailure("tool", new AggregateException(many)));
            Exception nested = timeout;
            for (int depth = 0; depth < 5; depth++) nested = new AggregateException(nested);
            string deep = ActivationFailureReport(new ActivationFailure("tool", nested));
            if (!wide.EndsWith("failure_causes=16 truncated=True", StringComparison.Ordinal) ||
                !deep.EndsWith("failure_causes=0 truncated=True", StringComparison.Ordinal) || wide.Contains("private") || deep.Contains("private"))
                throw new InvalidOperationException("fixed activation failure reporting exceeded traversal bounds");
            byte[] bytes = KernelImage.StaticFixture(); var image = KernelImage.FromStatic(bytes);
            string identity = image.KernelBaseIdentity();
            RequireSame(identity, KernelImage.FromStatic((byte[])bytes.Clone()).KernelBaseIdentity());
            string workerIdentity = KernelImage.FromActivationWorker(bytes).ActivationWorkerIdentity();
            RequireSame(workerIdentity, KernelImage.FromActivationWorker((byte[])bytes.Clone()).ActivationWorkerIdentity());
            byte[] workerDrift = (byte[])bytes.Clone(); workerDrift[0x700] ^= 1;
            bool workerRefused = false;
            try { RequireSame(workerIdentity, KernelImage.FromActivationWorker(workerDrift).ActivationWorkerIdentity()); }
            catch (InvalidOperationException) { workerRefused = true; }
            if (!workerRefused) throw new InvalidOperationException("static activation-worker binding accepted changed held bytes");
            byte[] changed = (byte[])bytes.Clone(); changed[0x700] ^= 1;
            foreach (string invalid in new [] { null, "", identity + " ", KernelImage.FromStatic(changed).KernelBaseIdentity() }) {
                bool refused = false;
                try { RequireSame(identity, invalid); } catch (InvalidOperationException) { refused = true; }
                if (!refused) throw new InvalidOperationException("static same-run image binding accepted a missing or changed identity");
            }
            bool crossProfileRefused = false;
            try { RequireSame("phase=image-identity module=kernelbase.dll sha256=f4acdac5f1dc54b20c84a51ad0f507f421f5d1170e276a5a75d4e7dcf88750e2 pdb_guid=0b01ed22-aa49-026d-b0b3-95e011af2a5e pdb_age=1 pdb_name=kernelbase.pdb pe_timestamp=2900858579 image_size=4120576 file_size=4129456",
                "phase=image-identity module=kernelbase.dll sha256=96c0459f0d73d728e5c13a10d83d840f56913ef7281d17370a5e1eb197faa450 pdb_guid=cabdac12-ca43-8c8b-4dc4-b60b7499c804 pdb_age=1 pdb_name=kernelbase.pdb pe_timestamp=1038034819 image_size=4116480 file_size=4171392"); }
            catch (InvalidOperationException) { crossProfileRefused = true; }
            if (!crossProfileRefused) throw new InvalidOperationException("static LOAD binding switched supported profiles");
            crossProfileRefused = false;
            try { RequireSame("phase=image-identity module=kernel32.dll sha256=347f1ac1b7dbec710cf06fb3f67d131bceebbc19076bc77daacd31cfe452b496 pe_timestamp=4227614027 image_size=823296 file_size=836208",
                "phase=image-identity module=kernel32.dll sha256=601aaacb3bdcbea24aec832d08a2f12ec7046183b6f40d18d61458d5e7008991 pe_timestamp=1269129758 image_size=823296 file_size=853648"); }
            catch (InvalidOperationException) { crossProfileRefused = true; }
            if (!crossProfileRefused) throw new InvalidOperationException("static LOAD binding switched supported kernel32 profiles");
            var qualification = new InvalidOperationException("fixed profile refusal");
            var reportFailure = new IOException("fixed identity reporting");
            string reported = null;
            ReportObservationFailure(qualification, identity, line => reported = line);
            if (reported != "WINDOWS_STATIC_KERNEL profile_accepted=False " + identity)
                throw new InvalidOperationException("refused static identity metadata differs");
            AggregateException combined = null;
            try { ReportObservationFailure(qualification, identity, _ => { throw reportFailure; }); }
            catch (AggregateException failure) { combined = failure; }
            if (combined == null || combined.InnerExceptions.Count != 2 ||
                !Object.ReferenceEquals(combined.InnerExceptions[0], qualification) || !Object.ReferenceEquals(combined.InnerExceptions[1], reportFailure))
                throw new InvalidOperationException("static identity reporting replaced qualification failure");
            string order = ""; bool bound = false; Exception propagatedQualification = null;
            try { QualifyActivation(() => { order += "qualify,"; throw qualification; }, workerIdentity,
                line => { reported = line; order += "report,"; }, () => bound = true); }
            catch (Exception failure) { propagatedQualification = failure; }
            if (bound || order != "qualify,report," || !Object.ReferenceEquals(propagatedQualification, qualification) ||
                reported != "WINDOWS_STATIC_ACTIVATION profile_accepted=False " + workerIdentity)
                throw new InvalidOperationException("refused activation profile was bound or lost exact metadata");
            combined = null;
            try { QualifyActivation(() => { throw qualification; }, workerIdentity, _ => { throw reportFailure; }, () => bound = true); }
            catch (AggregateException failure) { combined = failure; }
            if (bound || combined == null || combined.InnerExceptions.Count != 2 ||
                !Object.ReferenceEquals(combined.InnerExceptions[0], qualification) || !Object.ReferenceEquals(combined.InnerExceptions[1], reportFailure))
                throw new InvalidOperationException("activation refusal reporting lost primary failure or bound identity");
            order = "";
            QualifyActivation(() => order += "qualify,", workerIdentity, _ => { throw new InvalidOperationException("unexpected success report"); },
                () => { order += "bind,"; bound = true; });
            if (!bound || order != "qualify,bind,") throw new InvalidOperationException("activation identity binding preceded qualification");
            bool missing = false;
            try { RequireSame(null, identity); } catch (InvalidOperationException) { missing = true; }
            if (!missing) throw new InvalidOperationException("static image binding accepted an absent preparation identity");
        }
    }
}
