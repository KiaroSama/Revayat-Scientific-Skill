using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace ScientificSecurity
{
    // Authority is intentional on this private positive only, never on a protected boundary.
    public sealed partial class PrivateCreatorFixture
    {
        static PrivateCreatorFixture current;
        readonly string run, scratch, package, user, folder;
        readonly Lifecycle lifecycle = new Lifecycle();
        IntPtr rootPin, pin;
        ScratchAccess.FileInformation rootIdentity, identity;
        string rootName;
        sealed class Lifecycle
        {
            bool attempted, prepared, sealAttempted, sealedPolicy, running, used, uncertain, removing;
            internal bool removed;
            internal void Prepare(Action action)
            { Need(!attempted); attempted = true; action(); prepared = true; }
            internal void Seal(Action action)
            { Need(prepared && !sealAttempted); sealAttempted = true; action(); sealedPolicy = true; }
            internal void Use(Action action)
            {
                Need(sealedPolicy && !running && !uncertain && !removing); running = true;
                try { action(); used = true; } catch { uncertain = true; throw; }
            }
            internal void End(bool clean)
            { uncertain |= !clean; running = false; }
            internal void Remove(Action action)
            { Need(sealedPolicy && used && !running && !uncertain && !removing); removing = true; action(); removed = true; }
            internal void Release(Action action)
            { Need(!running && !uncertain); action(); }
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CreateDirectoryW(string path, ref Native.SecurityAttributes security);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetFinalPathNameByHandleW(IntPtr handle, StringBuilder path, uint capacity, uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetFileAttributesW(string path);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetFileInformationByHandle(IntPtr handle, int kind, ref byte information, uint bytes);
        [DllImport("advapi32.dll")]
        static extern uint GetSecurityInfo(IntPtr handle, int kind, uint fields, out IntPtr owner, out IntPtr group,
            out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
        [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
        static void Need(bool value, [System.Runtime.CompilerServices.CallerLineNumber] int line = 0)
        { PolicyNeed(value, 0, 0, 0, 0, line); }
        static void PolicyNeed(bool value, uint field, uint first, uint second = 0, uint third = 0,
            [System.Runtime.CompilerServices.CallerLineNumber] int line = 0)
        {
            if (value) return;
            throw new InvalidOperationException(String.Format(System.Globalization.CultureInfo.InvariantCulture,
                "fixed private creator fixture rejected line={0} field={1} first=0x{2:X8} second=0x{3:X8} third=0x{4:X8}",
                line >= 1 && line <= 9999 ? line : 0, field, first, second, third));
        }
        static bool Valid(IntPtr handle) { return handle != IntPtr.Zero && handle != Native.InvalidHandle; }
        static void Host() { using (WindowsIdentity thread = WindowsIdentity.GetCurrent(true)) Need(thread == null); }
        static string Folder(string root)
        {
            Need(root != null && root.Length == 3 && root[0] >= 'D' && root[0] <= 'Z' && root[1] == ':' && root[2] == '\\');
            return root + "private-creator";
        }
        static bool NativeRoot(string name)
        {
            const string prefix = @"\Device\HarddiskVolume";
            return name != null && name.StartsWith(prefix, StringComparison.Ordinal) && name.EndsWith("\\", StringComparison.Ordinal) &&
                name.Length > prefix.Length + 1 && name.Length <= prefix.Length + 21 &&
                name.Substring(prefix.Length, name.Length - prefix.Length - 1).All(c => c >= '0' && c <= '9');
        }
        static string Name(IntPtr handle)
        {
            var text = new StringBuilder(512);
            uint length = GetFinalPathNameByHandleW(handle, text, 512, 2);
            Native.Check(length != 0, "query private creator native name"); Need(length < 512 && text.Length == length);
            return text.ToString();
        }
        static IntPtr Open(string path, uint access)
        {
            IntPtr handle = CreateFileW(path, access, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
            Native.Check(Valid(handle), "open fixed private creator directory"); return handle;
        }
        static void Close(IntPtr handle)
        { if (Valid(handle)) Native.Check(Native.CloseHandle(handle), "close private creator fixture handle"); }
        static void Same(ScratchAccess.FileInformation expected, ScratchAccess.FileInformation actual)
        { Need(expected.volume == actual.volume && expected.indexHigh == actual.indexHigh && expected.indexLow == actual.indexLow); }
        static string PolicyText(string user, string package)
        { return "O:" + user + "G:" + user + "D:P(A;;FA;;;" + user + ")(A;;FA;;;" + package + ")S:(ML;OICI;NW;;;LW)"; }
        static void RequirePolicy(RawSecurityDescriptor descriptor, string user, string package)
        {
            Need(descriptor.Owner != null && descriptor.Owner.Value == user && descriptor.Group != null && descriptor.Group.Value == user);
            var flags = descriptor.ControlFlags;
            PolicyNeed((flags & (ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclProtected)) ==
                (ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclProtected), 1, (uint)flags);
            PolicyNeed((flags & (ControlFlags.DiscretionaryAclDefaulted | ControlFlags.DiscretionaryAclAutoInherited)) == 0, 1, (uint)flags);
            RawAcl dacl = descriptor.DiscretionaryAcl, sacl = descriptor.SystemAcl;
            PolicyNeed(dacl != null && dacl.Count == 2 && sacl != null && sacl.Count == 1, 2,
                dacl == null ? UInt32.MaxValue : (uint)dacl.Count, sacl == null ? UInt32.MaxValue : (uint)sacl.Count);
            var principals = new HashSet<string>(StringComparer.Ordinal);
            foreach (GenericAce entry in dacl) {
                var ace = entry as CommonAce;
                PolicyNeed(ace != null && !ace.IsCallback && ace.AceQualifier == AceQualifier.AccessAllowed &&
                    ace.AceFlags == AceFlags.None && ace.AccessMask == 0x1F01FF &&
                    (ace.SecurityIdentifier.Value == user || ace.SecurityIdentifier.Value == package) && principals.Add(ace.SecurityIdentifier.Value),
                    3, (uint)entry.AceType, (uint)entry.AceFlags, ace == null ? 0 : unchecked((uint)ace.AccessMask));
            }
            GenericAce label = sacl[0]; PolicyNeed((int)label.AceType == 17 && label.BinaryLength == 20 &&
                label.AceFlags == (AceFlags.ObjectInherit | AceFlags.ContainerInherit), 4,
                (uint)label.AceType, (uint)label.AceFlags, (uint)label.BinaryLength);
            byte[] bytes = new byte[20]; label.GetBinaryForm(bytes, 0);
            PolicyNeed(BitConverter.ToUInt32(bytes, 4) == 1 && new SecurityIdentifier(bytes, 8).Value == "S-1-16-4096",
                5, BitConverter.ToUInt32(bytes, 4));
        }
        void Policy(IntPtr handle)
        {
            IntPtr descriptor = IntPtr.Zero; Exception primary = null; var failures = new List<Exception>();
            try {
                IntPtr owner, group, dacl, sacl;
                uint error = GetSecurityInfo(handle, 1, 0x17, out owner, out group, out dacl, out sacl, out descriptor);
                if (error != 0) throw new System.ComponentModel.Win32Exception(unchecked((int)error), "query private creator policy");
                Need(descriptor != IntPtr.Zero); uint bytes = GetSecurityDescriptorLength(descriptor); Need(bytes >= 20 && bytes <= 65536);
                var binary = new byte[bytes]; Marshal.Copy(descriptor, binary, 0, binary.Length);
                RequirePolicy(new RawSecurityDescriptor(binary, 0), user, package);
            }
            catch (Exception error) { primary = error; }
            finally { ScratchAccess.Attempt(failures, () => { if (descriptor != IntPtr.Zero) Need(Native.LocalFree(descriptor) == IntPtr.Zero); }); }
            ScratchAccess.Finish(primary, failures);
        }
        static void Absent(string path)
        {
            uint attributes = GetFileAttributesW(path);
            int error = attributes == UInt32.MaxValue ? Marshal.GetLastWin32Error() : 0;
            Need(attributes == UInt32.MaxValue && error == 2);
        }
        void BindRoot()
        { ScratchAccess.RequirePlain(rootPin, true); Same(rootIdentity, ScratchAccess.Identity(rootPin)); Need(Name(rootPin) == rootName); }
        void BindDirectory(IntPtr handle)
        {
            BindRoot(); ScratchAccess.RequirePlain(handle, true); Same(identity, ScratchAccess.Identity(handle));
            Need(identity.volume == rootIdentity.volume && Name(handle) == rootName + "private-creator");
        }
        void RequireEmpty()
        {
            BindDirectory(pin); Policy(pin);
            using (var entries = Directory.EnumerateFileSystemEntries(folder).GetEnumerator()) Need(!entries.MoveNext());
            BindDirectory(pin);
        }
        PrivateCreatorFixture(string run, string scratch, string package)
        {
            Need(run != null && run.Length == 32 && run.All(c => c >= '0' && c <= '9' || c >= 'a' && c <= 'f'));
            Need(package == Sandbox.PackageSid("Scientific.Security." + run));
            this.run = run; this.scratch = scratch; this.package = package; folder = Folder(scratch);
            using (WindowsIdentity host = WindowsIdentity.GetCurrent()) { Need(host.User != null); user = host.User.Value; }
        }
        void Matches(string run, string scratch, string package)
        { Host(); Need(this.run == run && this.scratch == scratch && this.package == package); }
        void Initialize()
        {
            Host(); Absent(folder); rootPin = Open(scratch, 0x80);
            ScratchAccess.RequirePlain(rootPin, true); rootIdentity = ScratchAccess.Identity(rootPin); rootName = Name(rootPin); Need(NativeRoot(rootName));
            IntPtr descriptor = IntPtr.Zero; Exception primary = null; var failures = new List<Exception>();
            try {
                uint bytes;
                Native.Check(Native.ConvertStringSecurityDescriptorToSecurityDescriptorW(PolicyText(user, package), 1, out descriptor, out bytes),
                    "construct fixed private creator directory policy");
                var attributes = new Native.SecurityAttributes { size = (uint)Marshal.SizeOf(typeof(Native.SecurityAttributes)), descriptor = descriptor };
                Native.Check(CreateDirectoryW(folder, ref attributes), "create fixed private creator directory");
                pin = Open(folder, 0x20081); ScratchAccess.RequirePlain(pin, true); identity = ScratchAccess.Identity(pin);
                Need(identity.volume == rootIdentity.volume); RequireEmpty();
            }
            catch (Exception error) { primary = error; }
            finally { ScratchAccess.Attempt(failures, () => { if (descriptor != IntPtr.Zero) Need(Native.LocalFree(descriptor) == IntPtr.Zero); }); }
            ScratchAccess.Finish(primary, failures);
        }
        public static void Prepare(string run, string scratch, string package)
        {
            Host(); Need(current == null); current = new PrivateCreatorFixture(run, scratch, package);
            current.lifecycle.Prepare(current.Initialize);
        }
        public static void RequireAfterSeal(string run, string scratch, string package)
        { Need(current != null); current.Matches(run, scratch, package); current.lifecycle.Seal(current.RequireEmpty); }
        // This is called only for the fixed ordinary KernelProbe role, before resume.
        internal static void RequireUse(Native.ProcessInfo process, string scratch, string package)
        {
            Host(); Need(current != null && current.scratch == scratch && current.package == package);
            current.lifecycle.Use(() => {
                current.RequireEmpty(); IntPtr token = IntPtr.Zero; Exception primary = null; var failures = new List<Exception>();
                try {
                    Native.Check(Native.OpenProcessToken(process.process, 8, out token), "query private creator child identity");
                    Need(RegistryContext.TokenSid(token, 1) == current.user && RegistryContext.TokenSid(token, 31) == current.package);
                }
                catch (Exception error) { primary = error; }
                finally { ScratchAccess.Attempt(failures, () => Close(token)); }
                ScratchAccess.Finish(primary, failures);
            });
        }
        internal static void EndRun(bool clean)
        { if (current != null) current.lifecycle.End(clean); }
        static void RemoveBound(Action check, Action closePin, Func<IntPtr> open, Action<IntPtr> bind,
            Action<IntPtr> dispose, Action<IntPtr> close, Action absent)
        {
            IntPtr deletion = IntPtr.Zero; bool marked = false, closed = false;
            Exception primary = null; var failures = new List<Exception>();
            try { check(); closePin(); deletion = open(); bind(deletion); dispose(deletion); marked = true; }
            catch (Exception error) { primary = error; }
            finally { if (Valid(deletion)) ScratchAccess.Attempt(failures, () => { close(deletion); closed = true; }); }
            if (marked && closed) ScratchAccess.Attempt(failures, absent);
            ScratchAccess.Finish(primary, failures);
        }
        public static void RemoveBeforeAdmission(string run, string scratch, string package)
        {
            Need(current != null); current.Matches(run, scratch, package); var fixture = current;
            fixture.lifecycle.Remove(() => {
                RemoveBound(fixture.RequireEmpty, () => { IntPtr handle = fixture.pin; fixture.pin = IntPtr.Zero; Close(handle); },
                    () => Open(fixture.folder, 0x30081), handle => {
                        fixture.BindDirectory(handle); fixture.Policy(handle);
                        using (var entries = Directory.EnumerateFileSystemEntries(fixture.folder).GetEnumerator()) Need(!entries.MoveNext());
                        fixture.BindDirectory(handle);
                    }, handle => { byte remove = 1; Native.Check(SetFileInformationByHandle(handle, 4, ref remove, 1), "remove bound empty private creator directory"); },
                    Close, () => Absent(fixture.folder));
                IntPtr root = fixture.rootPin; fixture.rootPin = IntPtr.Zero; Close(root);
            });
            Console.Out.WriteLine("WINDOWS_PRIVATE_CREATOR removed=True empty=True identity_bound=True admission=False"); Console.Out.Flush();
        }
        // Failure cleanup never deletes a possibly foreign path. The reaped owned VHD is the recovery boundary.
        public static void ReleasePins()
        {
            Host(); if (current == null) return;
            current.lifecycle.Release(() => {
                var failures = new List<Exception>();
                IntPtr pin = current.pin, root = current.rootPin; current.pin = current.rootPin = IntPtr.Zero;
                ScratchAccess.Attempt(failures, () => Close(pin)); ScratchAccess.Attempt(failures, () => Close(root));
                ScratchAccess.Finish(null, failures);
            });
        }
    }
}
