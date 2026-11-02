using System;
using System.Collections.Generic;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace ScientificSecurity
{
    // Descriptor modeling and actual opens are separate observations, never admission or cause proof.
    public static class ScratchAccess
    {
        const uint Desired = 0x100020;
        sealed class Result
        {
            internal uint query, checkError, granted, openError;
            internal bool checkedAccess, allowed, opened;
            internal string policy = "unknown";
        }
        [StructLayout(LayoutKind.Sequential)] struct FileInformation
        { internal ulong volume, indexHigh, indexLow; }
        [StructLayout(LayoutKind.Sequential)] struct AttributeInformation
        { internal uint attributes, tag; }
        [StructLayout(LayoutKind.Sequential)] struct GenericMapping
        { internal uint read, write, execute, all; }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CreateFileW(string path, uint access, uint sharing, IntPtr attributes, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandleEx(IntPtr handle, int kind, out FileInformation information, uint bytes);
        [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
        static extern bool GetAttributes(IntPtr handle, int kind, out AttributeInformation information, uint bytes);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool DuplicateTokenEx(IntPtr token, uint access, IntPtr attributes, int level, int kind, out IntPtr duplicate);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool ImpersonateLoggedOnUser(IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool RevertToSelf();
        [DllImport("advapi32.dll")]
        static extern uint GetSecurityInfo(IntPtr handle, int kind, uint fields, out IntPtr owner, out IntPtr group,
            out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
        [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AccessCheck(IntPtr descriptor, IntPtr token, uint desired, ref GenericMapping mapping,
            IntPtr privileges, ref uint length, out uint granted, out bool allowed);
        sealed class DirectoryObservation
        {
            internal string path, label;
            internal IntPtr handle, openedHandle;
            internal FileInformation identity;
            internal Result result = new Result();
        }
        static FileInformation Identity(IntPtr handle)
        {
            FileInformation identity;
            Native.Check(GetFileInformationByHandleEx(handle, 18, out identity, 24), "query fixed scratch directory identity");
            return identity;
        }
        static void Pin(DirectoryObservation item)
        {
            NativeFixture.Plain(item.path);
            IntPtr handle = CreateFileW(item.path, 0x20080, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
            Native.Check(handle != Native.InvalidHandle && handle != IntPtr.Zero, "pin fixed scratch directory");
            item.handle = handle;
            AttributeInformation attributes;
            Native.Check(GetAttributes(handle, 9, out attributes, 8), "qualify plain scratch directory");
            Need((attributes.attributes & 0x410) == 0x10 && attributes.tag == 0);
            item.identity = Identity(handle);
        }
        static void Model(DirectoryObservation item, IntPtr token, SecurityIdentifier user, SecurityIdentifier package)
        {
            IntPtr descriptor = IntPtr.Zero, privileges = IntPtr.Zero;
            var failures = new List<Exception>(); Exception primary = null;
            try {
                IntPtr owner, group, dacl, sacl;
                uint status = GetSecurityInfo(item.handle, 1, 0x17, out owner, out group, out dacl, out sacl, out descriptor);
                item.result.query = status;
                if (status != 0) return;
                Need(descriptor != IntPtr.Zero);
                uint bytes = GetSecurityDescriptorLength(descriptor); Need(bytes >= 20 && bytes <= 65536);
                byte[] binary = new byte[bytes]; Marshal.Copy(descriptor, binary, 0, binary.Length);
                item.result.policy = Policy(binary, user, package);
                privileges = Marshal.AllocHGlobal(2048); uint length = 2048, granted; bool allowed;
                var mapping = new GenericMapping { read = 0x120089, write = 0x120116, execute = 0x1200A0, all = 0x1F01FF };
                bool completed = AccessCheck(descriptor, token, Desired, ref mapping, privileges, ref length, out granted, out allowed);
                uint error = completed && allowed ? 0U : unchecked((uint)Marshal.GetLastWin32Error());
                item.result.checkedAccess = completed; item.result.checkError = error;
                item.result.allowed = completed && allowed; item.result.granted = completed ? granted : 0;
                if (completed) Need(length <= 2048);
            }
            catch (Exception error) { primary = error; }
            finally {
                Attempt(failures, () => { if (privileges != IntPtr.Zero) Marshal.FreeHGlobal(privileges); });
                Attempt(failures, () => { if (descriptor != IntPtr.Zero) Need(Native.LocalFree(descriptor) == IntPtr.Zero); });
                Finish(primary, failures);
            }
        }
        static void Open(DirectoryObservation item)
        {
            IntPtr handle = CreateFileW(item.path, Desired, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
            uint error = handle == Native.InvalidHandle || handle == IntPtr.Zero ? unchecked((uint)Marshal.GetLastWin32Error()) : 0;
            item.result.opened = handle != Native.InvalidHandle && handle != IntPtr.Zero;
            item.result.openError = error;
            if (item.result.opened) item.openedHandle = handle;
        }
        internal static void Observe(Native.ProcessInfo process, string scratch, string package)
        {
            Need(Path.IsPathFullyQualified(scratch) && Path.GetFullPath(scratch) == Path.GetPathRoot(scratch));
            var items = new [] {
                new DirectoryObservation { path = scratch, label = "root" },
                new DirectoryObservation { path = Path.Combine(scratch, "temp"), label = "temp" }
            };
            var observations = new List<string>(); var failures = new List<Exception>(); Exception primary = null;
            IntPtr token = IntPtr.Zero, duplicate = IntPtr.Zero; bool impersonating = false;
            var clock = Stopwatch.StartNew();
            try {
                Deadline(clock);
                using (WindowsIdentity current = WindowsIdentity.GetCurrent(true)) Need(current == null);
                foreach (var item in items) { Deadline(clock); Pin(item); }
                Deadline(clock);
                Need(items[0].identity.volume == items[1].identity.volume);
                Native.Check(Native.OpenProcessToken(process.process, 0xA, out token), "open fixed scratch source token");
                Native.Check(DuplicateTokenEx(token, 0xC, IntPtr.Zero, 2, 2, out duplicate), "duplicate fixed scratch context");
                var context = new RegistryContext(token, duplicate, package);
                using (var identity = new WindowsIdentity(token))
                    foreach (var item in items) { Deadline(clock); Model(item, duplicate, identity.User, new SecurityIdentifier(package)); }
                Deadline(clock);
                Native.Check(ImpersonateLoggedOnUser(duplicate), "enter fixed scratch context"); impersonating = true;
                foreach (var item in items) { Deadline(clock); context.RequireThread(); Open(item); }
                context.RequireThread(); Deadline(clock);
            }
            catch (Exception error) { primary = error; }
            finally {
                if (impersonating) {
                    bool reverted = false;
                    try { reverted = RevertToSelf(); }
                    catch { Environment.FailFast("Scratch observation identity restoration threw; outer owner must recover."); }
                    if (!reverted) Environment.FailFast("Scratch observation identity restoration failed; outer owner must recover.");
                }
                Attempt(failures, () => { if (duplicate != IntPtr.Zero) Native.Check(Native.CloseHandle(duplicate), "close fixed scratch context token"); });
                Attempt(failures, () => { if (token != IntPtr.Zero) Native.Check(Native.CloseHandle(token), "close fixed scratch source token"); });
                foreach (var item in items) {
                    Attempt(failures, () => { if (item.openedHandle != IntPtr.Zero) Same(item.identity, Identity(item.openedHandle)); });
                    Attempt(failures, () => { if (item.openedHandle != IntPtr.Zero) Native.Check(Native.CloseHandle(item.openedHandle), "close fixed scratch access handle"); });
                    Attempt(failures, () => { if (item.handle != IntPtr.Zero) Same(item.identity, Identity(item.handle)); });
                    Attempt(failures, () => { if (item.handle != IntPtr.Zero) Native.Check(Native.CloseHandle(item.handle), "close fixed scratch identity handle"); });
                }
            }
            Finish(primary, failures);
            foreach (var item in items) observations.Add(Frame(item.label, item.result));
            foreach (string line in observations) Console.Out.WriteLine(line);
            Console.Out.Flush();
        }
        static void Deadline(Stopwatch clock)
        { if (clock.Elapsed.TotalSeconds > 10) throw new TimeoutException("fixed scratch observation exceeded 10 seconds"); }
        static void Need(bool value)
        { if (!value) throw new InvalidOperationException("fixed scratch access observation is invalid"); }
        static void Same(FileInformation expected, FileInformation actual)
        {
            Need(expected.volume == actual.volume &&
                expected.indexHigh == actual.indexHigh && expected.indexLow == actual.indexLow);
        }
        static string Frame(string label, Result result)
        {
            Need(label == "root" || label == "temp");
            Need(!result.allowed || result.checkedAccess);
            Need(result.checkedAccess || result.granted == 0);
            Need(!result.opened || result.openError == 0);
            return "WINDOWS_SCRATCH_ACCESS object=" + label + " desired=0x00100020 descriptor_error=0x" +
                result.query.ToString("X8") + " check_completed=" + result.checkedAccess + " allowed=" + result.allowed +
                " granted=0x" + result.granted.ToString("X8") + " check_error=0x" + result.checkError.ToString("X8") +
                " opened=" + result.opened + " open_error=0x" + result.openError.ToString("X8") + " " + result.policy +
                " identity_qualified=True context_verified=True cleanup_qualified=True cause_claimed=False child_equivalence_claimed=False";
        }
        static string Policy(byte[] bytes, SecurityIdentifier user, SecurityIdentifier package)
        {
            Need(bytes != null && bytes.Length >= 20 && bytes.Length <= 65536);
            var descriptor = new RawSecurityDescriptor(bytes, 0);
            Need(descriptor.Owner != null && descriptor.Group != null);
            uint allow = 0, deny = 0, ownerDeny = 0;
            if (descriptor.DiscretionaryAcl != null) {
                Need(descriptor.DiscretionaryAcl.Count <= 256);
                foreach (GenericAce entry in descriptor.DiscretionaryAcl) {
                    var ace = entry as CommonAce;
                    Need(ace != null && !ace.IsCallback);
                    if ((ace.AceFlags & AceFlags.InheritOnly) != 0) continue;
                    uint mask = unchecked((uint)ace.AccessMask);
                    if (ace.SecurityIdentifier == package) {
                        if (ace.AceQualifier == AceQualifier.AccessAllowed) allow |= mask;
                        if (ace.AceQualifier == AceQualifier.AccessDenied) deny |= mask;
                    }
                    if (ace.SecurityIdentifier.Value == "S-1-3-4" && ace.AceQualifier == AceQualifier.AccessDenied) ownerDeny |= mask;
                }
            }
            uint rid = 0, mandatory = 0; int labels = 0;
            if (descriptor.SystemAcl != null) {
                Need(descriptor.SystemAcl.Count <= 16);
                foreach (GenericAce entry in descriptor.SystemAcl) {
                    Need((int)entry.AceType == 17 && entry.BinaryLength == 20);
                    if ((entry.AceFlags & AceFlags.InheritOnly) != 0) continue;
                    byte[] ace = new byte[20]; entry.GetBinaryForm(ace, 0);
                    Need(ace[8] == 1 && ace[9] == 1 && ace[10] == 0 && ace[11] == 0 &&
                        ace[12] == 0 && ace[13] == 0 && ace[14] == 0 && ace[15] == 16 && ++labels == 1);
                    rid = BitConverter.ToUInt32(ace, 16); mandatory = BitConverter.ToUInt32(ace, 4);
                }
            }
            return "owner_user=" + (descriptor.Owner == user) + " dacl_present=" +
                ((descriptor.ControlFlags & ControlFlags.DiscretionaryAclPresent) != 0) + " dacl_null=" +
                (descriptor.DiscretionaryAcl == null) + " package_allow=0x" + allow.ToString("X8") +
                " package_deny=0x" + deny.ToString("X8") + " owner_deny=0x" + ownerDeny.ToString("X8") +
                " label_present=" + (labels == 1) + " label_rid=0x" + rid.ToString("X8") + " label_policy=0x" + mandatory.ToString("X8");
        }
        static void Finish(Exception primary, List<Exception> failures)
        {
            if (failures.Count == 0) {
                if (primary != null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw();
                return;
            }
            var all = new List<Exception>(); if (primary != null) all.Add(primary); all.AddRange(failures);
            throw new AggregateException("fixed scratch observation/cleanup failed", all);
        }
        static void Attempt(List<Exception> failures, Action action)
        { try { action(); } catch (Exception error) { failures.Add(error); } }
        public static void CheckValidation()
        {
            Need(Marshal.SizeOf(typeof(FileInformation)) == 24 && Marshal.SizeOf(typeof(AttributeInformation)) == 8);
            var expected = new FileInformation { volume = 1, indexHigh = 2, indexLow = 3 };
            Same(expected, expected);
            foreach (var actual in new [] {
                new FileInformation { volume = 4, indexHigh = 2, indexLow = 3 },
                new FileInformation { volume = 1, indexHigh = 4, indexLow = 3 },
                new FileInformation { volume = 1, indexHigh = 2, indexLow = 4 } }) {
                bool refused = false; try { Same(expected, actual); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            var user = new SecurityIdentifier("S-1-5-21-1-2-3-1000");
            var package = new SecurityIdentifier("S-1-15-2-1");
            string sddl = "O:" + user.Value + "G:SYD:P(D;;0x000C0000;;;OW)(A;;0x001301BF;;;" + package.Value + ")S:(ML;;NW;;;LW)";
            var sd = new RawSecurityDescriptor(sddl); byte[] bytes = new byte[sd.BinaryLength]; sd.GetBinaryForm(bytes, 0);
            string policy = Policy(bytes, user, package);
            Need(policy == "owner_user=True dacl_present=True dacl_null=False package_allow=0x001301BF " +
                "package_deny=0x00000000 owner_deny=0x000C0000 label_present=True label_rid=0x00001000 label_policy=0x00000001");
            foreach (bool allowed in new [] { false, true }) foreach (bool opened in new [] { false, true }) {
                var result = new Result { checkedAccess = true, allowed = allowed, granted = allowed ? Desired : 0,
                    opened = opened, openError = opened ? 0U : 5U, policy = policy };
                string frame = Frame("root", result);
                Need(frame.Contains("allowed=" + allowed) && frame.Contains("opened=" + opened) && frame.Length <= 1024 &&
                    !frame.Contains(user.Value) && !frame.Contains(package.Value) && frame.EndsWith("child_equivalence_claimed=False", StringComparison.Ordinal));
            }
            Need(Frame("temp", new Result { query = 5, openError = 5 }).Contains("descriptor_error=0x00000005 check_completed=False allowed=False granted=0x00000000"));
            foreach (Action invalid in new Action[] {
                () => Frame("private-path", new Result()), () => Frame("root", new Result { allowed = true }),
                () => Frame("root", new Result { granted = Desired }), () => Frame("root", new Result { opened = true, openError = 5 }),
                () => Policy(new byte[19], user, package), () => Policy(new byte[65537], user, package) }) {
                bool refused = false; try { invalid(); } catch (InvalidOperationException) { refused = true; } Need(refused);
            }
            var primary = new IOException("private-primary"); var cleanup = new IOException("private-cleanup");
            foreach (bool fail in new [] { false, true }) {
                var failures = new List<Exception>(); int attempts = 0; Exception caught = null;
                Attempt(failures, () => { attempts++; if (fail) throw cleanup; }); Attempt(failures, () => attempts++);
                try { Finish(primary, failures); } catch (Exception error) { caught = error; }
                Need(attempts == 2);
                if (!fail) Need(Object.ReferenceEquals(caught, primary));
                else {
                    var group = caught as AggregateException;
                    Need(group != null && group.InnerExceptions.Count == 2 && Object.ReferenceEquals(group.InnerExceptions[0], primary) &&
                        Object.ReferenceEquals(group.InnerExceptions[1], cleanup));
                }
            }
        }
    }
}
