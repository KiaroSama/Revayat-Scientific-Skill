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
        static SxsTraceCapture current;
        readonly string run, state, folder, python, package;
        bool attempted, bound;
        public static bool StarterReaped { get; private set; } = true;
        internal static void StarterFinished() { StarterReaped = true; }
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool DuplicateTokenEx(IntPtr token, uint access, IntPtr attributes, int level, int kind, out IntPtr duplicate);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool ImpersonateLoggedOnUser(IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool RevertToSelf();
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CreateFileW(string path, uint access, uint sharing, IntPtr attributes, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CreateDirectoryW(string path, ref Native.SecurityAttributes attributes);
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
        public static void Run(string run, string state, string volume, string python, string package, Action operation)
        {
            SxsTraceCapture capture = null;
            try {
                Acquired(SxsTraceSession.Exclusive,
                    () => { Need(current == null && operation != null); capture = new SxsTraceCapture(run, state, volume, python, package); current = capture; },
                    () => Execute(() => { capture.Prepare(); operation(); },
                        () => SxsTraceSession.Stop(run, state, StarterReaped, capture.bound),
                        () => { if (capture.bound) capture.Parse(); }));
            }
            finally { if (capture != null && Object.ReferenceEquals(current, capture)) current = null; }
        }
        void Prepare()
        {
            try {
                SxsTraceSession.Plain(folder, true); Need(!SxsTraceSession.Exists(folder));
                using (WindowsIdentity host = WindowsIdentity.GetCurrent()) {
                    Need(host.User != null && !host.IsSystem);
                    var security = new DirectorySecurity(); security.SetAccessRuleProtection(true, false); security.SetOwner(host.User);
                    var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
                    foreach (string sid in new [] { package, "S-1-3-4" })
                        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),
                            sid == package ? FileSystemRights.FullControl : FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership,
                            inheritance, PropagationFlags.None, AccessControlType.Deny));
                    foreach (SecurityIdentifier sid in new [] { host.User, new SecurityIdentifier("S-1-5-18") })
                        security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
                    CreateSealed(security, host.User.Value, package, policy => {
                        byte[] bytes = policy.GetSecurityDescriptorBinaryForm(); IntPtr descriptor = Marshal.AllocHGlobal(bytes.Length);
                        try {
                            Marshal.Copy(bytes, 0, descriptor, bytes.Length);
                            var attributes = new Native.SecurityAttributes { size = (uint)Marshal.SizeOf(typeof(Native.SecurityAttributes)), descriptor = descriptor };
                            Native.Check(CreateDirectoryW(folder, ref attributes), "create fixed SxS directory with protected policy");
                        }
                        finally { Marshal.FreeHGlobal(descriptor); Array.Clear(bytes, 0, bytes.Length); }
                    });
                }
                string canary = Path.Combine(folder, "canary");
                using (var file = new FileStream(canary, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None)) {
                    byte[] bytes = Encoding.UTF8.GetBytes("fixed SxS host control"); file.Write(bytes, 0, bytes.Length); file.Flush(true);
                }
                RequirePolicy(folder, true); RequirePolicy(canary, false);
            }
            catch (Exception error) { throw SxsTraceSession.Safe(error, "storage-prepare"); }
        }
        internal static void CreateSealed(DirectorySecurity security, string owner, string package, Action<DirectorySecurity> create)
        { ValidatePolicy(security, true, owner, package); create(security); }
        internal static void ValidatePolicy(FileSystemSecurity security, bool directory, string owner, string package)
        {
            Need(security.GetOwner(typeof(SecurityIdentifier)).Value == owner);
            var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
            Need(rules.Length == 4 && security.AreAccessRulesCanonical && (!directory || security.AreAccessRulesProtected));
            foreach (var rule in rules) {
                string sid = rule.IdentityReference.Value;
                Need(rule.PropagationFlags == PropagationFlags.None && (directory ? !rule.IsInherited : rule.IsInherited));
                Need(rule.InheritanceFlags == (directory ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None));
                if (sid == package) Need(rule.AccessControlType == AccessControlType.Deny && rule.FileSystemRights == FileSystemRights.FullControl);
                else if (sid == "S-1-3-4") Need(rule.AccessControlType == AccessControlType.Deny &&
                    rule.FileSystemRights == (FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership));
                else Need((sid == owner || sid == "S-1-5-18") && rule.AccessControlType == AccessControlType.Allow && rule.FileSystemRights == FileSystemRights.FullControl);
            }
            Need(rules.Select(r => r.IdentityReference.Value).Distinct().Count() == 4);
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
            Need(remaining() > 0); intent(); Need(remaining() > 0); start();
            Need(reaped() && remaining() > 0); bind(); Need(remaining() > 0);
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
                if (corruption == 3 && i == 1) continue;
                acl.InsertAce(acl.Count, new CommonAce(corruption == 4 && i == 1 ? flags | AceFlags.Inherited : flags,
                    i < 2 ? AceQualifier.AccessDenied : AceQualifier.AccessAllowed,
                    i == 1 ? 0xC0000 : 0x1F01FF, new SecurityIdentifier(ids[i]), false, null));
            }
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
        }
        public static void CheckValidation()
        {
            SxsTraceSession.CheckValidation(); SxsTraceEvidence.CheckValidation(); CheckStorageAndAcquisition();
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
