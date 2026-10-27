using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace ScientificSecurity
{
    // One standard-tool capture around the existing trusted authority launch.
    public sealed class SxsTraceCapture
    {
        static SxsTraceCapture current, prepared;
        readonly string run, state, folder, python, package;
        readonly StorageLifecycle storage = new StorageLifecycle();
        bool attempted, bound;
        sealed class StorageLifecycle
        {
            bool attempted, ready, sealAttempted, sealedStorage, entered;
            internal void Prepare(Action action) { Need(!attempted); attempted = true; action(); ready = true; }
            internal void Seal(Action action) { Need(ready && !sealAttempted && !entered); sealAttempted = true; action(); sealedStorage = true; }
            internal void Enter(Action action) { Need(ready && sealedStorage && !entered); entered = true; action(); }
        }
        enum BoundaryStage { PrepareStorage, AfterSeal, Enter }
        static void Boundary(BoundaryStage stage, Action action)
        {
            string label;
            switch (stage) {
                case BoundaryStage.PrepareStorage: label = "storage-initialize"; break;
                case BoundaryStage.AfterSeal: label = "storage-after-seal"; break;
                case BoundaryStage.Enter: label = "storage-enter"; break;
                default: throw new InvalidOperationException("unsupported fixed SxS storage boundary");
            }
            try { action(); } catch (Exception error) { throw SxsTraceSession.Safe(error, label); }
        }
        public static bool StarterReaped { get; private set; } = true;
        internal static void StarterFinished() { StarterReaped = true; }
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool DuplicateTokenEx(IntPtr token, uint access, IntPtr attributes, int level, int kind, out IntPtr duplicate);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool ImpersonateLoggedOnUser(IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool RevertToSelf();
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CreateFileW(string path, uint access, uint sharing, IntPtr attributes, uint disposition, uint flags, IntPtr template);
        static void Need(bool value) { SxsTraceSession.Need(value); }
        SxsTraceCapture(string run, string state, string volume, string python, string package)
        {
            this.run = run; this.state = SxsTraceSession.State(run, state);
            folder = SxsTraceSession.Folder(run, volume); this.python = python; this.package = package;
        }
        internal static void RequireFolder(string path)
        { Need(current != null && String.Equals(path, current.folder, StringComparison.Ordinal)); SxsTraceSession.Plain(path); }
        static Exception Combine(Exception first, Exception later)
        { return first == null ? later : later == null ? first : new AggregateException("fixed SxS operation/finalization failed", first, later); }
        internal static void Execute(Action operation, Action stop, Action parse)
        {
            Exception primary = null; bool stopped = false;
            try { operation(); } catch (Exception error) { primary = error; }
            try { stop(); stopped = true; } catch (Exception error) { primary = Combine(primary, SxsTraceSession.Safe(error, "stop")); }
            if (stopped) try { parse(); } catch (Exception error) { primary = Combine(primary, SxsTraceSession.Safe(error, "parse")); }
            if (primary != null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw();
        }
        internal static void Acquired(Func<IDisposable> acquire, Action initialize, Action execute)
        {
            IDisposable lease = null; Exception primary = null;
            try { lease = acquire(); initialize(); }
            catch (Exception error) { primary = SxsTraceSession.Safe(error, "acquire"); }
            if (primary == null) try { execute(); } catch (Exception error) { primary = error; }
            try { if (lease != null) lease.Dispose(); }
            catch (Exception error) { primary = Combine(primary, SxsTraceSession.Safe(error, "release")); }
            if (primary != null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw();
        }
        static void SameInputs(string[] expected, string[] actual)
        { Need(expected.Length == 5 && actual.Length == 5 && expected.Zip(actual, (a, b) => a != null && String.Equals(a, b, StringComparison.Ordinal)).All(value => value)); }
        void Matches(string run, string state, string volume, string python, string package)
        {
            SameInputs(new [] { this.run, this.state, folder, this.python, this.package },
                new [] { run, SxsTraceSession.State(run, state), SxsTraceSession.Folder(run, volume), python, package });
        }
        public static void PrepareStorage(string run, string state, string volume, string python, string package)
        {
            Boundary(BoundaryStage.PrepareStorage, () => {
                Need(prepared == null && current == null);
                prepared = new SxsTraceCapture(run, state, volume, python, package);
                prepared.storage.Prepare(prepared.Prepare);
            });
        }
        public static void RequireStorageAfterSeal(string run, string state, string volume, string python, string package)
        {
            Boundary(BoundaryStage.AfterSeal, () => {
                Need(prepared != null); prepared.Matches(run, state, volume, python, package);
                prepared.storage.Seal(prepared.RequireStorage);
            });
        }
        public static void Run(string run, string state, string volume, string python, string package, Action operation)
        {
            SxsTraceCapture capture = null;
            try {
                Acquired(SxsTraceSession.Exclusive,
                    () => Boundary(BoundaryStage.Enter, () => {
                        Need(current == null && prepared != null && operation != null);
                        capture = prepared; capture.Matches(run, state, volume, python, package);
                        capture.storage.Enter(capture.RequireStorage); current = capture;
                    }),
                    () => Execute(operation,
                        () => SxsTraceSession.Stop(run, state, StarterReaped, capture.bound),
                        () => { if (capture.bound) capture.Parse(); }));
            }
            finally { if (capture != null && Object.ReferenceEquals(current, capture)) current = null; }
        }
        static void RequireCanary(byte[] bytes)
        { Need(bytes != null && bytes.SequenceEqual(Encoding.UTF8.GetBytes("fixed SxS host control"))); }
        void RequireStorage()
        {
            string canary = Path.Combine(folder, "canary");
            StorageStep(StorageStage.DirectoryReadback, () => RequirePolicy(folder, true));
            StorageStep(StorageStage.FileReadback, () => RequirePolicy(canary, false));
            StorageStep(StorageStage.Canary, () => {
                using (var file = new FileStream(canary, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                    Need(file.Length > 0 && file.Length <= 64); var bytes = new byte[(int)file.Length]; int offset = 0;
                    while (offset < bytes.Length) { int read = file.Read(bytes, offset, bytes.Length - offset); Need(read > 0); offset += read; }
                    Need(file.ReadByte() == -1); RequireCanary(bytes);
                }
            });
        }
        enum StorageStage { Path, Host, Policy, Create, Canary, DirectoryReadback, FileReadback }
        enum PolicyPredicate { Owner, Rules, Canonical, Protected, Propagation, Inherited, Inheritance, Package, OwnerRights, Allow, Distinct }
        sealed class PolicyFailure : InvalidOperationException
        {
            internal readonly PolicyPredicate Predicate;
            internal PolicyFailure(PolicyPredicate predicate) : base("fixed SxS storage policy rejected predicate=" + PolicyName(predicate))
            { Predicate = predicate; }
        }
        static string PolicyName(PolicyPredicate predicate)
        {
            switch (predicate) {
                case PolicyPredicate.Owner: return "owner";
                case PolicyPredicate.Rules: return "rules";
                case PolicyPredicate.Canonical: return "canonical";
                case PolicyPredicate.Protected: return "protected";
                case PolicyPredicate.Propagation: return "propagation";
                case PolicyPredicate.Inherited: return "inherited";
                case PolicyPredicate.Inheritance: return "inheritance";
                case PolicyPredicate.Package: return "package";
                case PolicyPredicate.OwnerRights: return "owner-rights";
                case PolicyPredicate.Allow: return "allow";
                case PolicyPredicate.Distinct: return "distinct";
                default: throw new InvalidOperationException("unsupported fixed SxS policy predicate");
            }
        }
        static string StorageName(StorageStage stage)
        {
            switch (stage) {
                case StorageStage.Path: return "path";
                case StorageStage.Host: return "host";
                case StorageStage.Policy: return "policy";
                case StorageStage.Create: return "create";
                case StorageStage.Canary: return "canary";
                case StorageStage.DirectoryReadback: return "directory-readback";
                case StorageStage.FileReadback: return "file-readback";
                default: throw new InvalidOperationException("unsupported fixed SxS storage stage");
            }
        }
        static void StorageStep(StorageStage stage, Action operation)
        {
            string name = StorageName(stage);
            try { operation(); }
            catch (Exception error) {
                if (error is SxsTraceSession.PrivateFailure) throw;
                Exception safe;
                try {
                    string native = error.GetType() == typeof(System.ComponentModel.Win32Exception) ?
                        unchecked((uint)((System.ComponentModel.Win32Exception)error).NativeErrorCode).ToString("X8") : "unavailable";
                    string predicate = error.GetType() == typeof(PolicyFailure) ? PolicyName(((PolicyFailure)error).Predicate) : "unavailable";
                    safe = new SxsTraceSession.PrivateFailure(error, "storage-" + name + " exception_hresult=" +
                        unchecked((uint)error.HResult).ToString("X8") + " exception_win32=" + native + " policy_predicate=" + predicate);
                }
                catch { safe = SxsTraceSession.Safe(error, "storage-prepare"); }
                throw safe;
            }
        }
        static void PolicyNeed(bool value, PolicyPredicate predicate)
        { if (!value) throw new PolicyFailure(predicate); }
        void Prepare()
        {
            try {
                StorageStep(StorageStage.Path, () => { SxsTraceSession.Plain(folder, true); Need(!SxsTraceSession.Exists(folder)); });
                StorageStep(StorageStage.Host, () => {
                    using (WindowsIdentity host = WindowsIdentity.GetCurrent()) {
                        Need(host.User != null && !host.IsSystem);
                        StorageStep(StorageStage.Policy, () => {
                            var security = new DirectorySecurity(); security.SetAccessRuleProtection(true, false); security.SetOwner(host.User);
                            var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
                            foreach (string sid in new [] { package, "S-1-3-4" })
                                security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),
                                    sid == package ? FileSystemRights.FullControl : FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership,
                                    inheritance, PropagationFlags.None, AccessControlType.Deny));
                            foreach (SecurityIdentifier sid in new [] { host.User, new SecurityIdentifier("S-1-5-18") })
                                security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
                            CreateSealed(security, host.User.Value, package,
                                policy => StorageStep(StorageStage.Create, () => SxsTraceStorage.Create(folder, policy)));
                        });
                    }
                });
                string canary = Path.Combine(folder, "canary");
                StorageStep(StorageStage.Canary, () => {
                    using (WindowsIdentity host = WindowsIdentity.GetCurrent()) {
                        SxsCanaryOwner.Run(host.User, () => WriteCanary(
                            () => new FileStream(canary, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None),
                            stream => ((FileStream)stream).Flush(true)));
                    }
                });
                StorageStep(StorageStage.DirectoryReadback, () => RequirePolicy(folder, true));
                StorageStep(StorageStage.FileReadback, () => RequirePolicy(canary, false));
            }
            catch (Exception error) { throw SxsTraceSession.Safe(error, "storage-prepare"); }
        }
        static void WriteCanary(Func<Stream> create, Action<Stream> flush)
        {
            Stream stream = null; Exception primary = null;
            try {
                stream = create(); Need(stream != null);
                byte[] bytes = Encoding.UTF8.GetBytes("fixed SxS host control");
                stream.Write(bytes, 0, bytes.Length); flush(stream);
            }
            catch (Exception error) { primary = error; throw; }
            finally {
                var failures = new System.Collections.Generic.List<Exception>();
                StartupActivationAccess.Attempt(failures, () => { if (stream != null) stream.Dispose(); });
                StartupActivationAccess.Finish(primary, failures);
            }
        }
        internal static void CreateSealed(DirectorySecurity security, string owner, string package, Action<DirectorySecurity> create)
        { ValidatePolicy(security, true, owner, package); create(security); }
        internal static void ValidatePolicy(FileSystemSecurity security, bool directory, string owner, string package)
        {
            PolicyNeed(security.GetOwner(typeof(SecurityIdentifier)).Value == owner, PolicyPredicate.Owner);
            var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
            PolicyNeed(rules.Length == 4, PolicyPredicate.Rules);
            PolicyNeed(security.AreAccessRulesCanonical, PolicyPredicate.Canonical);
            PolicyNeed(!directory || security.AreAccessRulesProtected, PolicyPredicate.Protected);
            foreach (var rule in rules) {
                string sid = rule.IdentityReference.Value;
                PolicyNeed(rule.PropagationFlags == PropagationFlags.None, PolicyPredicate.Propagation);
                PolicyNeed(directory ? !rule.IsInherited : rule.IsInherited, PolicyPredicate.Inherited);
                PolicyNeed(rule.InheritanceFlags == (directory ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None), PolicyPredicate.Inheritance);
                if (sid == package) PolicyNeed(rule.AccessControlType == AccessControlType.Deny && rule.FileSystemRights == FileSystemRights.FullControl, PolicyPredicate.Package);
                else if (sid == "S-1-3-4") PolicyNeed(rule.AccessControlType == AccessControlType.Deny &&
                    rule.FileSystemRights == (FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership), PolicyPredicate.OwnerRights);
                else PolicyNeed((sid == owner || sid == "S-1-5-18") && rule.AccessControlType == AccessControlType.Allow && rule.FileSystemRights == FileSystemRights.FullControl, PolicyPredicate.Allow);
            }
            PolicyNeed(rules.Select(r => r.IdentityReference.Value).Distinct().Count() == 4, PolicyPredicate.Distinct);
        }
        void RequirePolicy(string path, bool directory)
        {
            SxsTraceSession.Plain(path);
            FileSystemSecurity security = directory ? (FileSystemSecurity)FileSystemAclExtensions.GetAccessControl(new DirectoryInfo(path), AccessControlSections.Access | AccessControlSections.Owner) :
                FileSystemAclExtensions.GetAccessControl(new FileInfo(path), AccessControlSections.Access | AccessControlSections.Owner);
            using (WindowsIdentity host = WindowsIdentity.GetCurrent()) ValidatePolicy(security, directory, host.User.Value, package);
        }
        internal static void StartAuthority(Native.ProcessInfo child, string package, Stopwatch clock)
        {
            Need(current != null && !current.attempted && current.package == package && clock.IsRunning);
            current.Start(child, clock);
        }
        void Start(Native.ProcessInfo child, Stopwatch clock)
        {
            IntPtr token = IntPtr.Zero, duplicate = IntPtr.Zero;
            bool impersonating = false; Exception primary = null;
            try {
                using (WindowsIdentity thread = WindowsIdentity.GetCurrent(true)) Need(thread == null);
                Native.Check(Native.OpenProcessToken(child.process, 0xA, out token), "open SxS storage control primary");
                Native.Check(DuplicateTokenEx(token, 0xC, IntPtr.Zero, 2, 2, out duplicate), "duplicate SxS storage control token");
                var context = new RegistryContext(token, duplicate, package);
                Native.Check(ImpersonateLoggedOnUser(duplicate), "enter exact SxS storage context"); impersonating = true;
                foreach (string path in new [] { folder, Path.Combine(folder, "canary") })
                    foreach (uint access in (path == folder ? new uint[] { 1, 2, 4, 0x40, 0x10000, 0x20000, 0x40000, 0x80000 } :
                        new uint[] { 1, 2, 0x10000, 0x20000, 0x40000, 0x80000 })) {
                        context.RequireThread(); Need(clock.Elapsed.TotalSeconds < 10);
                        IntPtr handle = CreateFileW(path, access, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
                        int error = Marshal.GetLastWin32Error();
                        try { Need(handle == Native.InvalidHandle && error == 5); }
                        finally { if (handle != Native.InvalidHandle && handle != IntPtr.Zero) Native.Check(Native.CloseHandle(handle), "close unexpected SxS access handle"); }
                    }
                context.RequireThread();
            }
            catch (Exception error) { primary = error; }
            finally {
                if (impersonating) {
                    bool reverted = false;
                    try { reverted = RevertToSelf(); } catch { Environment.FailFast("SxS storage context restoration threw; outer owner must recover."); }
                    if (!reverted) Environment.FailFast("SxS storage context restoration failed; outer owner must recover.");
                }
                foreach (IntPtr handle in new [] { duplicate, token })
                    try { if (handle != IntPtr.Zero) Native.Check(Native.CloseHandle(handle), "close SxS storage token"); }
                    catch (Exception error) { primary = Combine(primary, error); }
            }
            if (primary != null) throw SxsTraceSession.Safe(primary, "storage");
            try {
                StartSequence(() => 10 - clock.Elapsed.TotalSeconds,
                    () => { SxsTraceSession.Intent(run, state, Path.GetPathRoot(folder)); attempted = true; },
                    () => TrustedSetup.RunSxsTrace(folder, false, () => 10 - clock.Elapsed.TotalSeconds),
                    () => StarterReaped, () => { SxsTraceSession.Bind(run, state, Path.GetPathRoot(folder)); bound = true; });
                Console.Out.WriteLine("WINDOWS_SXS_TRACE started=True storage_denied=True cause_claimed=False"); Console.Out.Flush();
            }
            catch (Exception error) { throw SxsTraceSession.Safe(error, "start"); }
        }
        internal static void StartSequence(Func<double> remaining, Action intent, Action start, Func<bool> reaped, Action bind)
        {
            SxsTraceSession.At(SxsTraceSession.Stage.Initial, () => Need(remaining() > 0));
            SxsTraceSession.At(SxsTraceSession.Stage.Intent, intent);
            SxsTraceSession.At(SxsTraceSession.Stage.StartTool, () => { Need(remaining() > 0); start(); });
            SxsTraceSession.At(SxsTraceSession.Stage.PostTool, () => Need(reaped() && remaining() > 0));
            SxsTraceSession.At(SxsTraceSession.Stage.Bind, bind);
            SxsTraceSession.At(SxsTraceSession.Stage.PostBind, () => Need(remaining() > 0));
        }
        internal static void StarterBeginning() { StarterReaped = false; }
        void Parse()
        {
            RequirePolicy(Path.Combine(folder, "capture.etl"), false);
            SxsTraceEvidence.RequireLength(Path.Combine(folder, "capture.etl"), 8388608);
            Need(!SxsTraceSession.Exists(Path.Combine(folder, "capture.txt")));
            var clock = Stopwatch.StartNew(); TrustedSetup.RunSxsTrace(folder, true, () => 10 - clock.Elapsed.TotalSeconds);
            RequirePolicy(Path.Combine(folder, "capture.txt"), false);
            string evidence = SxsTraceEvidence.Read(Path.Combine(folder, "capture.txt"), Path.Combine(Path.GetDirectoryName(python), "DLLs", "_ctypes.pyd"));
            Console.Out.WriteLine(evidence); Console.Out.Flush();
        }
        static FileSystemSecurity PolicyFixture(bool directory, int corruption, string owner, string package)
        {
            var acl = new RawAcl(2, 4);
            AceFlags flags = directory ? AceFlags.ContainerInherit | AceFlags.ObjectInherit : AceFlags.Inherited;
            string[] ids = { package, "S-1-3-4", owner, "S-1-5-18" };
            for (int i = 0; i < ids.Length; i++) {
                if ((corruption == 3 || corruption == 5) && i == 1) continue;
                acl.InsertAce(acl.Count, new CommonAce(corruption == 4 && i == 1 ? flags | AceFlags.Inherited : flags,
                    i < 2 ? AceQualifier.AccessDenied : AceQualifier.AccessAllowed,
                    i == 1 ? 0xC0000 : 0x1F01FF, new SecurityIdentifier(ids[i]), false, null));
            }
            if (corruption == 5) acl.InsertAce(acl.Count, new CommonAce(flags | AceFlags.Inherited,
                AceQualifier.AccessDenied, 0xC0000, new SecurityIdentifier("S-1-3-4"), false, null));
            var descriptor = new RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent | ControlFlags.SelfRelative |
                (directory && corruption != 2 ? ControlFlags.DiscretionaryAclProtected : 0),
                new SecurityIdentifier(corruption == 1 ? "S-1-5-18" : owner), new SecurityIdentifier(owner), null, acl);
            byte[] bytes = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(bytes, 0);
            FileSystemSecurity policy = directory ? (FileSystemSecurity)new DirectorySecurity() : new FileSecurity();
            policy.SetSecurityDescriptorBinaryForm(bytes); return policy;
        }
        static void CheckStorageAndAcquisition()
        {
            const string owner = "S-1-5-21-1-2-3-1001", package = "S-1-15-2-1-2-3-4-5-6-7";
            var policy = (DirectorySecurity)PolicyFixture(true, 0, owner, package);
            int creations = 0; CreateSealed(policy, owner, package, _ => creations++); Need(creations == 1);
            for (int corruption = 1; corruption <= 4; corruption++) {
                var bad = (DirectorySecurity)PolicyFixture(true, corruption, owner, package);
                bool refused = false;
                try { CreateSealed(bad, owner, package, _ => creations++); } catch (InvalidOperationException) { refused = true; }
                Need(refused && creations == 1);
            }
            ValidatePolicy(PolicyFixture(false, 0, owner, package), false, owner, package);
            bool wrongOwner = false;
            try { ValidatePolicy(PolicyFixture(false, 1, owner, package), false, owner, package); } catch (InvalidOperationException) { wrongOwner = true; }
            Need(wrongOwner);
            var raw = new IOException("C:\\private-path-sentinel\\capture.etl");
            foreach (bool acquisition in new [] { true, false }) {
                Exception caught = null; bool executed = false;
                try { Acquired(() => { if (acquisition) throw raw; return null; },
                    () => { throw raw; }, () => executed = true); } catch (Exception error) { caught = error; }
                var safe = caught as SxsTraceSession.PrivateFailure;
                Need(safe != null && Object.ReferenceEquals(safe.Original, raw) && !executed && safe.InnerException == null && !safe.ToString().Contains("sentinel"));
            }
            for (int failure = 0; failure < 6; failure++) {
                string order = ""; int reads = 0; Exception caught = null;
                try { StartSequence(() => { reads++; return failure == 1 && reads == 1 || failure == 2 && reads == 2 || failure == 5 && reads == 3 ? 0 : 1; },
                    () => order += "i", () => { order += "s"; if (failure == 3) throw raw; },
                    () => failure != 4, () => order += "b"); } catch (Exception error) { caught = error; }
                Need(order == (failure == 1 ? "" : failure == 2 ? "i" : failure >= 3 ? "is" : "isb"));
                Need((caught == null) == (failure == 0));
            }
            int remainingReads = 0; Exception postTool = null;
            try { StartSequence(() => { remainingReads++; return 1; }, () => { }, () => { },
                () => false, () => { throw raw; }); }
            catch (Exception error) { postTool = error; }
            Need(remainingReads == 2 && postTool is SxsTraceSession.PrivateFailure &&
                postTool.Message == "fixed SxS trace failed stage=post-tool raw_error_withheld=True");
        }
        sealed class CustomWin32Failure : System.ComponentModel.Win32Exception
        { internal CustomWin32Failure() : base(99, "private-native-sentinel") { } }
        public static void CheckStorageFailureValidation()
        {
            const string owner = "S-1-5-21-1-2-3-1001", package = "S-1-15-2-1-2-3-4-5-6-7";
            Exception caught = null;
            try { ValidatePolicy(PolicyFixture(true, 1, owner, package), true, owner, package); }
            catch (Exception error) { caught = error; }
            Need(caught != null && caught.Message == "fixed SxS storage policy rejected predicate=owner");
            string[] stages = { "path", "host", "policy", "create", "canary", "directory-readback", "file-readback" };
            var errors = new Exception[] { new System.ComponentModel.Win32Exception(5, "C:\\private-path-sentinel"),
                new IOException("private-io-sentinel", unchecked((int)0x80070005)), new CustomWin32Failure() };
            string[] native = { "00000005", "unavailable", "unavailable" };
            string[] hresult = { "80004005", "80070005", "80004005" };
            for (int stage = 0; stage < stages.Length; stage++) {
                int calls = 0; StorageStep((StorageStage)stage, () => calls++); Need(calls == 1);
                for (int kind = 0; kind < errors.Length; kind++) {
                    Exception raw = errors[kind]; caught = null;
                    try { StorageStep((StorageStage)stage, () => { throw raw; }); } catch (Exception error) { caught = error; }
                    var safe = caught as SxsTraceSession.PrivateFailure;
                    Need(safe != null && Object.ReferenceEquals(safe.Original, raw) && safe.InnerException == null &&
                        safe.Message == "fixed SxS trace failed stage=storage-" + stages[stage] + " exception_hresult=" + hresult[kind] +
                        " exception_win32=" + native[kind] + " policy_predicate=unavailable raw_error_withheld=True" &&
                        !safe.ToString().Contains("sentinel") && safe.Message.Length <= 256);
                }
            }
            foreach (int stage in new [] { -1, 7, Int32.MaxValue }) {
                int calls = 0; bool refused = false;
                try { StorageStep((StorageStage)stage, () => calls++); } catch (InvalidOperationException) { refused = true; }
                Need(refused && calls == 0);
            }
            string[] predicates = { "owner", "rules", "canonical", "protected", "propagation", "inherited", "inheritance", "package", "owner-rights", "allow", "distinct" };
            for (int predicate = 0; predicate < predicates.Length; predicate++) {
                caught = null;
                try { StorageStep(StorageStage.Policy, () => PolicyNeed(false, (PolicyPredicate)predicate)); }
                catch (Exception error) { caught = error; }
                var safe = caught as SxsTraceSession.PrivateFailure;
                Need(safe != null && safe.Original.GetType() == typeof(PolicyFailure) &&
                    safe.Message.Contains("policy_predicate=" + predicates[predicate] + " raw_error_withheld=True"));
            }
            string[] first = { "owner", "protected", "rules", "canonical", "inherited" };
            for (int corruption = 1; corruption <= 5; corruption++) {
                caught = null;
                try { ValidatePolicy(PolicyFixture(true, corruption, owner, package), true, owner, package); }
                catch (Exception error) { caught = error; }
                Need(caught != null && caught.Message == "fixed SxS storage policy rejected predicate=" + first[corruption - 1]);
            }
            ValidatePolicy(PolicyFixture(true, 0, owner, package), true, owner, package);
            ValidatePolicy(PolicyFixture(false, 0, owner, package), false, owner, package);
            Exception original = null;
            try { Execute(() => StorageStep(StorageStage.Canary, () => { throw errors[1]; }),
                () => { throw errors[0]; }, () => { throw new InvalidOperationException("parse must not run"); }); }
            catch (Exception error) { original = error; }
            var aggregate = original as AggregateException;
            Need(aggregate != null && aggregate.InnerExceptions.Count == 2 &&
                Object.ReferenceEquals(((SxsTraceSession.PrivateFailure)aggregate.InnerExceptions[0]).Original, errors[1]) &&
                Object.ReferenceEquals(((SxsTraceSession.PrivateFailure)aggregate.InnerExceptions[1]).Original, errors[0]) &&
                !aggregate.ToString().Contains("sentinel"));
        }
        sealed class CanaryStream : MemoryStream
        {
            internal string order = "";
            internal int failure;
            internal readonly Exception error = new IOException("private-canary-sentinel");
            public override void Write(byte[] bytes, int offset, int count)
            {
                order += "w"; Need(offset == 0 && count == 22); RequireCanary(bytes);
                if ((failure & 1) != 0) throw error;
                base.Write(bytes, offset, count);
            }
            internal void FlushFixed() { order += "f"; if ((failure & 2) != 0) throw error; }
            protected override void Dispose(bool disposing)
            { order += "d"; base.Dispose(disposing); if ((failure & 4) != 0) throw error; }
        }
        static void CheckCanaryCreation()
        {
            SxsCanaryOwner.CheckValidation();
            for (int mode = 0; mode < 8; mode++) {
                var stream = new CanaryStream { failure = mode }; Exception caught = null; int acquired = 0;
                try { WriteCanary(() => { acquired++; if (mode == 3) throw stream.error; return stream; },
                    value => ((CanaryStream)value).FlushFixed()); }
                catch (Exception error) { caught = error; }
                Need(acquired == 1 && stream.order == (mode == 3 ? "" : (mode & 1) != 0 ? "wd" : "wfd"));
                if (mode == 0) Need(caught == null);
                else if ((mode & 4) != 0) {
                    var aggregate = caught as AggregateException;
                    Need(aggregate != null && aggregate.InnerExceptions.Count == ((mode & 3) == 0 ? 1 : 2) &&
                        aggregate.InnerExceptions.All(value => Object.ReferenceEquals(value, stream.error)));
                }
                else Need(Object.ReferenceEquals(caught, stream.error));
                if (mode == 3) stream.Dispose();
            }
        }
        static void CheckStorageLifecycle()
        {
            var raw = new IOException("C:\\private-boundary-sentinel\\canary");
            for (int phase = 0; phase < 3; phase++) {
                Exception caught = null;
                try { Boundary((BoundaryStage)phase, () => { throw raw; }); } catch (Exception error) { caught = error; }
                var safe = caught as SxsTraceSession.PrivateFailure;
                Need(safe != null && Object.ReferenceEquals(safe.Original, raw) && safe.InnerException == null && !safe.ToString().Contains("sentinel"));
            }
            foreach (int phase in new [] { -1, 3, Int32.MaxValue }) {
                bool refused = false; int calls = 0;
                try { Boundary((BoundaryStage)phase, () => calls++); } catch (InvalidOperationException) { refused = true; }
                Need(refused && calls == 0);
            }
            string[] inputs = { "run", "state", "volume", "python", "package" };
            SameInputs(inputs, inputs);
            for (int field = 0; field < 5; field++) {
                var other = (string[])inputs.Clone(); other[field] += "-foreign"; bool refused = false;
                try { SameInputs(inputs, other); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            for (int failure = -1; failure < 3; failure++) {
                var lifecycle = new StorageLifecycle(); string order = "";
                Action<int> step = stage => { order += stage; if (stage == failure) throw raw; };
                Exception caught = null;
                try { lifecycle.Prepare(() => step(0)); lifecycle.Seal(() => step(1)); lifecycle.Enter(() => step(2)); }
                catch (Exception error) { caught = error; }
                Need(order == (failure == 0 ? "0" : failure == 1 ? "01" : "012") && (failure < 0 ? caught == null : Object.ReferenceEquals(caught, raw)));
                foreach (Action retry in new Action[] { () => lifecycle.Prepare(() => order += "p"),
                    () => lifecycle.Seal(() => order += "s"), () => lifecycle.Enter(() => order += "e") }) {
                    bool refused = false; try { retry(); } catch (InvalidOperationException) { refused = true; } Need(refused);
                }
                Need(!order.Contains("p") && !order.Contains("s") && !order.Contains("e"));
            }
            var missing = new StorageLifecycle(); bool missingRefused = false;
            try { missing.Enter(() => { throw raw; }); } catch (InvalidOperationException) { missingRefused = true; } Need(missingRefused);
            RequireCanary(Encoding.UTF8.GetBytes("fixed SxS host control"));
            foreach (byte[] bytes in new [] { new byte[0], Encoding.UTF8.GetBytes("fixed SxS host control!"), new byte[65] }) {
                bool refused = false; try { RequireCanary(bytes); } catch (InvalidOperationException) { refused = true; } Need(refused);
            }
        }
        public static void CheckValidation()
        {
            CheckCanaryCreation(); CheckStorageLifecycle();
            SxsTraceSession.CheckValidation(); SxsTraceEvidence.CheckValidation(); SxsTraceStorage.CheckValidation();
            TrustedSetup.CheckSxsCompletion();
            CheckStorageAndAcquisition(); CheckStorageFailureValidation();
            var operation = new IOException("fixed operation"); var stop = new IOException("private-stop-sentinel");
            for (int mode = 0; mode < 4; mode++) {
                string order = ""; Exception caught = null;
                try { Execute(() => { order += "o"; if (mode > 0) throw operation; },
                    () => { order += "s"; if (mode == 2) throw stop; }, () => { order += "p"; if (mode == 3) throw stop; }); }
                catch (Exception failure) { caught = failure; }
                Need(order == (mode == 2 ? "os" : "osp"));
                if (mode == 0) Need(caught == null);
                if (mode == 1) Need(Object.ReferenceEquals(caught, operation));
                if (mode >= 2) Need(caught is AggregateException && Object.ReferenceEquals(((AggregateException)caught).InnerExceptions[0], operation) && !caught.ToString().Contains("sentinel"));
            }
        }
    }
}
