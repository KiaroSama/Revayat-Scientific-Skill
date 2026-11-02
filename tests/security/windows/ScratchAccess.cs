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
            IntPtr token = IntPtr.Zero, duplicate = IntPtr.Zero, effective = IntPtr.Zero; bool impersonating = false;
            PrivilegeObservation primaryPrivileges = null, duplicatePrivileges = null, effectivePrivileges = null;
            var requests = new List<NativeRequest>(); VolumeObservation volume = null;
            var clock = Stopwatch.StartNew();
            try {
                Deadline(clock);
                using (WindowsIdentity current = WindowsIdentity.GetCurrent(true)) Need(current == null);
                foreach (var item in items) { Deadline(clock); Pin(item); }
                Deadline(clock);
                Need(items[0].identity.volume == items[1].identity.volume);
                volume = Volume(items[0].handle);
                string[] names = NativeNames(scratch, (drive, output) => {
                    uint length = QueryDosDeviceW(drive, output, (uint)output.Length);
                    Native.Check(length != 0, "resolve fixed scratch device"); return length;
                });
                foreach (string role in new [] { "host", "lpac" }) {
                    for (int i = 0; i < names.Length; i++)
                        requests.Add(new NativeRequest { role = role, name = i == 0 ? "dos" : "device", path = names[i] });
                    requests.Add(new NativeRequest { role = role, name = "temp-absolute", target = "temp", path = names[1] + "temp" });
                    requests.Add(new NativeRequest { role = role, name = "temp-relative", target = "temp", path = "temp", root = items[0].handle });
                }
                foreach (var request in requests) if (request.role == "host") {
                    Deadline(clock); request.Open(NtOpenFile, PendingFatal); Need(request.opened);
                    Same(items[request.target == "temp" ? 1 : 0].identity, Identity(Marshal.ReadIntPtr(request.memory)));
                }
                Native.Check(Native.OpenProcessToken(process.process, 0xA, out token), "open fixed scratch source token");
                Native.Check(DuplicateTokenEx(token, 0xC, IntPtr.Zero, 2, 2, out duplicate), "duplicate fixed scratch context");
                var context = new RegistryContext(token, duplicate, package);
                primaryPrivileges = Privileges(token); duplicatePrivileges = Privileges(duplicate);
                primaryPrivileges.Same(duplicatePrivileges);
                using (var identity = new WindowsIdentity(token))
                    foreach (var item in items) { Deadline(clock); Model(item, duplicate, identity.User, new SecurityIdentifier(package)); }
                Deadline(clock);
                Native.Check(ImpersonateLoggedOnUser(duplicate), "enter fixed scratch context"); impersonating = true;
                context.RequireThread();
                Native.Check(OpenThreadToken(GetCurrentThread(), 8, true, out effective), "open fixed scratch effective token");
                effectivePrivileges = Privileges(effective); primaryPrivileges.Same(effectivePrivileges);
                foreach (var item in items) { Deadline(clock); context.RequireThread(); Open(item); }
                foreach (var request in requests) if (request.role == "lpac") {
                    Deadline(clock); context.RequireThread(); request.Open(NtOpenFile, PendingFatal);
                }
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
                Attempt(failures, () => { if (effective != IntPtr.Zero) Native.Check(Native.CloseHandle(effective), "close fixed scratch effective token"); });
                foreach (var request in requests) Attempt(failures, () => request.Release(
                    handle => Same(items[request.target == "temp" ? 1 : 0].identity, Identity(handle)),
                    handle => Native.Check(Native.CloseHandle(handle), "close fixed scratch native handle")));
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
            observations.Add(volume.Frame());
            observations.Add(primaryPrivileges.Frame("primary")); observations.Add(duplicatePrivileges.Frame("duplicate"));
            observations.Add(effectivePrivileges.Frame("effective"));
            foreach (var request in requests) observations.Add(request.Frame());
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
        [StructLayout(LayoutKind.Sequential)] struct UnicodeString
        { internal ushort length, maximum; internal IntPtr buffer; }
        [StructLayout(LayoutKind.Sequential)] struct ObjectAttributes
        { internal uint length; internal IntPtr root, name; internal uint attributes; internal IntPtr descriptor, qos; }
        [StructLayout(LayoutKind.Explicit, Size = 16)] struct IoStatus
        {
            [FieldOffset(0)] internal int status;
            [FieldOffset(8)] internal UIntPtr information;
        }
        delegate int OpenCall(IntPtr handle, uint access, ref ObjectAttributes attributes, IntPtr io, uint share, uint options);
        [DllImport("ntdll.dll")] static extern int NtOpenFile(IntPtr handle, uint access,
            ref ObjectAttributes attributes, IntPtr io, uint share, uint options);
        [DllImport("ntdll.dll")] static extern int NtQueryVolumeInformationFile(IntPtr handle,
            IntPtr io, IntPtr information, uint length, int kind);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint QueryDosDeviceW(string device, [Out] char[] output, uint capacity);
        static bool Valid(IntPtr handle) { return handle != IntPtr.Zero && handle != Native.InvalidHandle; }
        static string[] NativeNames(string scratch, Func<string, char[], uint> query)
        {
            Need(scratch != null && scratch.Length == 3 && scratch[0] >= 'D' && scratch[0] <= 'Z' &&
                scratch[1] == ':' && scratch[2] == '\\');
            var output = new char[512]; uint length = query(scratch.Substring(0, 2), output);
            Need(length >= 3 && length <= output.Length && output[length - 1] == '\0' && output[length - 2] == '\0');
            int end = Array.IndexOf(output, '\0', 0, (int)length); Need(end == length - 2);
            string device = new string(output, 0, end), prefix = @"\Device\HarddiskVolume";
            Need(device.StartsWith(prefix, StringComparison.Ordinal) && device.Length > prefix.Length && device.Length <= prefix.Length + 20);
            for (int i = prefix.Length; i < device.Length; i++) Need(device[i] >= '0' && device[i] <= '9');
            return new [] { @"\??\" + scratch, device + "\\" };
        }
        static void RequireSynchronous(int returned, IoStatus io, Action fatal)
        {
            if (returned == 0x103 || io.status == 0x103) {
                fatal(); throw new InvalidOperationException("fixed scratch pending termination unexpectedly returned");
            }
        }
        static void PendingFatal()
        { Environment.FailFast("Scratch synchronous observation remained pending; outer owner must recover."); }
        static void RequireVolume(int returned, IoStatus io)
        { Need(returned == 0 && io.status == 0 && io.information.ToUInt64() == 8); }
        sealed class VolumeObservation
        {
            internal int status;
            internal bool known;
            internal uint type, characteristics;
            internal string Frame()
            {
                return "WINDOWS_SCRATCH_DEVICE ntstatus=0x" + unchecked((uint)status).ToString("X8") +
                    " known=" + known + " device_type=0x" + type.ToString("X8") +
                    " characteristics=0x" + characteristics.ToString("X8") + " cause_claimed=False";
            }
        }
        static VolumeObservation Volume(IntPtr root)
        {
            IntPtr memory = Marshal.AllocHGlobal(24); bool pending = false;
            try {
                Marshal.Copy(new byte[24], 0, memory, 24); Marshal.WriteInt32(memory, -1);
                int status;
                try { status = NtQueryVolumeInformationFile(root, memory, IntPtr.Add(memory, 16), 8, 4); }
                catch {
                    pending = Marshal.ReadInt32(memory) == 0x103;
                    if (pending) PendingFatal();
                    throw;
                }
                var io = (IoStatus)Marshal.PtrToStructure(memory, typeof(IoStatus));
                pending = status == 0x103 || io.status == 0x103;
                RequireSynchronous(status, io, PendingFatal);
                var result = new VolumeObservation { status = status };
                if (status == 0) {
                    RequireVolume(status, io); result.known = true;
                    result.type = unchecked((uint)Marshal.ReadInt32(memory, 16));
                    result.characteristics = unchecked((uint)Marshal.ReadInt32(memory, 20));
                }
                return result;
            }
            finally { if (!pending) Marshal.FreeHGlobal(memory); }
        }
        sealed class NativeRequest
        {
            internal string path, role, name, target = "root";
            internal IntPtr memory, root;
            internal int returned;
            internal bool opened, pending;
            internal void Open(OpenCall call, Action fatal)
            {
                Need(memory == IntPtr.Zero && path != null && path.Length <= 128);
                byte[] text = new System.Text.UnicodeEncoding(false, false, true).GetBytes(path);
                int size = 40 + text.Length + 2;
                memory = Marshal.AllocHGlobal(size); Marshal.Copy(new byte[size], 0, memory, size);
                Marshal.WriteInt32(memory, 8, -1);
                Marshal.StructureToPtr(new UnicodeString { length = checked((ushort)text.Length),
                    maximum = checked((ushort)(text.Length + 2)), buffer = IntPtr.Add(memory, 40) }, IntPtr.Add(memory, 24), false);
                Marshal.Copy(text, 0, IntPtr.Add(memory, 40), text.Length);
                Need(root == IntPtr.Zero || (Valid(root) && path == "temp"));
                var attributes = new ObjectAttributes { length = 48, root = root, name = IntPtr.Add(memory, 24), attributes = 0x40 };
                try { returned = call(memory, Desired, ref attributes, IntPtr.Add(memory, 8), 7, 0x200021); }
                catch {
                    pending = Marshal.ReadInt32(memory, 8) == 0x103;
                    if (pending) fatal();
                    throw;
                }
                var io = (IoStatus)Marshal.PtrToStructure(IntPtr.Add(memory, 8), typeof(IoStatus));
                pending = returned == 0x103 || io.status == 0x103;
                RequireSynchronous(returned, io, fatal);
                opened = returned == 0;
                if (opened) Need(io.status == 0 && io.information.ToUInt64() == 1 && Valid(Marshal.ReadIntPtr(memory)));
            }
            internal void Release(Action<IntPtr> bind, Action<IntPtr> close)
            {
                if (memory == IntPtr.Zero || pending) return;
                var failures = new List<Exception>(); IntPtr handle = Marshal.ReadIntPtr(memory);
                Attempt(failures, () => { if (Valid(handle)) bind(handle); });
                Attempt(failures, () => { if (Valid(handle)) close(handle); });
                Attempt(failures, () => { Marshal.FreeHGlobal(memory); memory = IntPtr.Zero; });
                Finish(null, failures);
            }
            internal string Frame()
            {
                Need((role == "host" || role == "lpac") &&
                    (name == "dos" || name == "device" || name == "temp-absolute" || name == "temp-relative") &&
                    (target == "root" || target == "temp") && !pending);
                return "WINDOWS_SCRATCH_NATIVE role=" + role + " name=" + name + " desired=0x00100020 share=7 options=0x00200021" +
                    " ntstatus=0x" + unchecked((uint)returned).ToString("X8") + " opened=" + opened +
                    " identity_qualified=True context_verified=True cleanup_qualified=True cause_claimed=False child_equivalence_claimed=False";
            }
        }
        static void NativeObservationFixtures()
        {
            Need(IntPtr.Size == 8 && Marshal.SizeOf(typeof(UnicodeString)) == 16 &&
                Marshal.SizeOf(typeof(ObjectAttributes)) == 48 && Marshal.SizeOf(typeof(IoStatus)) == 16);
            Need(Marshal.OffsetOf(typeof(ObjectAttributes), "name").ToInt32() == 16 &&
                Marshal.OffsetOf(typeof(IoStatus), "information").ToInt32() == 8);
            Func<string, char[], uint> query = (drive, output) => {
                Need(drive == "E:" && output.Length == 512);
                const string mapping = "\\Device\\HarddiskVolume12\0\0";
                mapping.CopyTo(0, output, 0, mapping.Length); return (uint)mapping.Length;
            };
            string[] names = NativeNames(@"E:\", query);
            Need(names.Length == 2 && names[0] == @"\??\E:\" && names[1] == @"\Device\HarddiskVolume12\");
            foreach (string bad in new [] { @"E:", @"E:\temp", @"e:\", @"C:\", @"\\server\share\" }) {
                int calls = 0; bool refused = false;
                try { NativeNames(bad, (_, output) => { calls++; return 0; }); }
                catch (InvalidOperationException) { refused = true; }
                Need(refused && calls == 0);
            }
            foreach (string bad in new [] { "", "\\Device\\HarddiskVolume12\0", "\\Device\\HarddiskVolume12\0old\0\0",
                "\\Device\\HarddiskVolume\0\0", "\\Device\\HarddiskVolume1\\extra\0\0", "\\??\\E:\0\0" }) {
                bool refused = false;
                try { NativeNames(@"E:\", (_, output) => { bad.CopyTo(0, output, 0, bad.Length); return (uint)bad.Length; }); }
                catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            foreach (uint length in new uint[] { 0, 1, 513, UInt32.MaxValue }) {
                bool refused = false;
                try { NativeNames(@"E:\", (_, output) => length); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            foreach (string path in new [] { names[0], names[1], names[1] + "temp", "temp" }) {
                bool relative = path == "temp";
                var request = new NativeRequest { path = path, role = "host", name = relative ? "temp-relative" : "dos",
                    root = relative ? new IntPtr(23) : IntPtr.Zero, target = relative ? "temp" : "root" };
                int calls = 0, closes = 0, binds = 0;
                OpenCall open = (IntPtr slot, uint access, ref ObjectAttributes attributes, IntPtr io, uint share, uint options) => {
                    calls++; Need(access == Desired && share == 7 && options == 0x200021 && attributes.length == 48 &&
                        attributes.root == request.root && attributes.attributes == 0x40 && attributes.descriptor == IntPtr.Zero &&
                        attributes.qos == IntPtr.Zero && Marshal.ReadIntPtr(slot) == IntPtr.Zero && Marshal.ReadInt32(io) == -1);
                    var text = (UnicodeString)Marshal.PtrToStructure(attributes.name, typeof(UnicodeString));
                    Need(text.length == path.Length * 2 && text.maximum == text.length + 2 &&
                        Marshal.PtrToStringUni(text.buffer, text.length / 2) == path && Marshal.ReadInt16(text.buffer, text.length) == 0);
                    Marshal.WriteIntPtr(slot, new IntPtr(17)); Marshal.WriteInt32(io, 0); Marshal.WriteInt64(io, 8, 1); return 0;
                };
                try { request.Open(open, () => { throw new Exception("unexpected pending"); }); Need(request.opened); }
                finally { request.Release(_ => binds++, handle => { Need(handle == new IntPtr(17)); closes++; }); }
                Need(calls == 1 && binds == 1 && closes == 1 && request.memory == IntPtr.Zero);
                string frame = request.Frame();
                Need(frame.Length < 512 && (relative || !frame.Contains(path)) &&
                    frame.Contains("role=host name=" + request.name) && frame.Contains("opened=True"));
            }
            foreach (int status in new [] { 0, unchecked((int)0xC0000022) }) {
                var request = new NativeRequest { role = "lpac", name = "device", returned = status, opened = status == 0 };
                Need(request.Frame().Contains("ntstatus=0x" + unchecked((uint)status).ToString("X8")));
            }
            foreach (int returned in new [] { 0x103, 0, unchecked((int)0xC0000022) }) {
                bool fatal = false, refused = false;
                try { RequireSynchronous(returned, new IoStatus { status = returned == 0 ? 0x103 : 0 }, () => fatal = true); }
                catch (InvalidOperationException) { refused = true; }
                Need(fatal == (returned == 0x103 || returned == 0) && refused == fatal);
            }
            foreach (ulong bytes in new ulong[] { 0, 7, 8, 9, UInt64.MaxValue }) {
                bool refused = false;
                try { RequireVolume(0, new IoStatus { information = new UIntPtr(bytes) }); }
                catch (InvalidOperationException) { refused = true; }
                Need(refused == (bytes != 8));
            }
            var original = new IOException("private-close"); var failures = new List<Exception>(); int attempts = 0;
            var failed = new NativeRequest { memory = Marshal.AllocHGlobal(64) };
            Marshal.WriteIntPtr(failed.memory, new IntPtr(17));
            try { failed.Release(_ => { attempts++; throw original; }, _ => attempts++); }
            catch (AggregateException error) { failures.AddRange(error.InnerExceptions); }
            Need(attempts == 2 && failed.memory == IntPtr.Zero && failures.Count == 1 && Object.ReferenceEquals(failures[0], original));
        }
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenThreadToken(IntPtr thread, uint access, bool asSelf, out IntPtr token);
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
        sealed class PrivilegeObservation
        {
            internal bool present;
            internal uint attributes;
            internal string[] inventory;
            internal void Same(PrivilegeObservation actual)
            {
                Need(inventory.Length == actual.inventory.Length);
                for (int i = 0; i < inventory.Length; i++) Need(inventory[i] == actual.inventory[i]);
            }
            internal string Frame(string role)
            {
                Need(role == "primary" || role == "duplicate" || role == "effective");
                return "WINDOWS_SCRATCH_PRIVILEGE role=" + role + " count=" + inventory.Length +
                    " traversal_present=" + present + " traversal_enabled=" + (present && (attributes & 2) != 0) +
                    " attributes=0x" + attributes.ToString("X8") + " cause_claimed=False";
            }
        }
        static PrivilegeObservation Privileges(byte[] bytes)
        {
            Need(bytes != null && bytes.Length >= 4 && bytes.Length <= 65536);
            uint count = BitConverter.ToUInt32(bytes, 0);
            Need(count <= 128 && bytes.Length >= 4 + count * 12);
            var result = new PrivilegeObservation { inventory = new string[count] };
            var identities = new HashSet<ulong>();
            for (int i = 0; i < count; i++) {
                int offset = 4 + i * 12;
                ulong luid = BitConverter.ToUInt64(bytes, offset);
                uint attributes = BitConverter.ToUInt32(bytes, offset + 8);
                Need(identities.Add(luid));
                result.inventory[i] = luid.ToString("X16") + ":" + attributes.ToString("X8");
                if (luid == 23) { result.present = true; result.attributes = attributes; }
            }
            Array.Sort(result.inventory, StringComparer.Ordinal); return result;
        }
        static PrivilegeObservation Privileges(IntPtr token)
        {
            uint bytes;
            bool initial = Native.GetTokenInformation(token, 3, IntPtr.Zero, 0, out bytes);
            int error = Marshal.GetLastWin32Error();
            Need(!initial && error == 122 && bytes >= 4 && bytes <= 65536);
            IntPtr memory = Marshal.AllocHGlobal((int)bytes);
            try {
                uint capacity = bytes;
                Native.Check(Native.GetTokenInformation(token, 3, memory, capacity, out bytes), "read fixed scratch token privileges");
                Need(bytes >= 4 && bytes <= capacity);
                var binary = new byte[bytes]; Marshal.Copy(memory, binary, 0, binary.Length);
                return Privileges(binary);
            }
            finally { Marshal.FreeHGlobal(memory); }
        }
        static void PrivilegeFixtures()
        {
            Need(Privileges(new byte[4]).Frame("primary").Contains("count=0 traversal_present=False traversal_enabled=False"));
            foreach (uint attributes in new uint[] { 0, 1, 2, 3, 0x80000002 }) {
                var bytes = new byte[16]; BitConverter.GetBytes(1U).CopyTo(bytes, 0);
                BitConverter.GetBytes(23U).CopyTo(bytes, 4); BitConverter.GetBytes(attributes).CopyTo(bytes, 12);
                var value = Privileges(bytes); value.Same(Privileges(bytes));
                string frame = value.Frame("duplicate");
                Need(frame.Contains("count=1 traversal_present=True traversal_enabled=" + ((attributes & 2) != 0)) &&
                    frame.Contains("attributes=0x" + attributes.ToString("X8")) && frame.Length < 256);
                var changed = (byte[])bytes.Clone(); changed[12] ^= 2; bool mismatch = false;
                try { value.Same(Privileges(changed)); } catch (InvalidOperationException) { mismatch = true; } Need(mismatch);
                bytes[8] = 1; var other = Privileges(bytes);
                Need(!other.present); bool refused = false;
                try { value.Same(other); } catch (InvalidOperationException) { refused = true; } Need(refused);
            }
            foreach (byte[] bytes in new [] { new byte[3], new byte[65537],
                new byte[] { 1, 0, 0, 0 }, new byte[] { 129, 0, 0, 0 } }) {
                bool refused = false; try { Privileges(bytes); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            var duplicate = new byte[28]; BitConverter.GetBytes(2U).CopyTo(duplicate, 0);
            BitConverter.GetBytes(23U).CopyTo(duplicate, 4); BitConverter.GetBytes(23U).CopyTo(duplicate, 16);
            bool invalid = false; try { Privileges(duplicate); } catch (InvalidOperationException) { invalid = true; } Need(invalid);
        }
        public static void CheckValidation()
        {
            NativeObservationFixtures(); PrivilegeFixtures();
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
