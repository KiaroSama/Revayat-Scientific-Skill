using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace ScientificSecurity
{
    // Disposable hosted diagnostic only. Read/compare/set is not an atomic compare-and-swap.
    public sealed class RegistryPolicyLease : IDisposable
    {
        const string KeyName = @"\Registry\MACHINE\Software\Microsoft\Windows\CurrentVersion\SideBySide";
        const string ReceiptName = "registry-policy.receipt";
        const string MutexName = @"Local\Scientific.Security.SideBySide.CausalLease";
        static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
        [StructLayout(LayoutKind.Sequential)] struct Name { internal ushort length, maximum; internal IntPtr buffer; }
        [StructLayout(LayoutKind.Sequential)] struct Attributes {
            internal uint length; internal IntPtr root, name; internal uint flags; internal IntPtr descriptor, qos;
        }
        [DllImport("ntdll.dll")] static extern int NtOpenKey(out IntPtr key, uint access, ref Attributes attributes);
        [DllImport("ntdll.dll")] static extern int NtClose(IntPtr key);
        [DllImport("ntdll.dll")] static extern int NtQueryKey(IntPtr key, int kind, IntPtr data, uint capacity, out uint returned);
        [DllImport("ntdll.dll")] static extern int NtQuerySecurityObject(IntPtr key, uint info, IntPtr data, uint capacity, out uint returned);
        [DllImport("ntdll.dll")] static extern int NtSetSecurityObject(IntPtr key, uint info, byte[] descriptor);
        IntPtr key;
        Mutex mutex;
        string receipt;
        byte[] original, expected, receiptBytes;
        bool intent, closed;
        static bool recoveryBlocked;
        private RegistryPolicyLease() { }

        static void Need(bool condition)
        { if (!condition) throw new InvalidOperationException("fixed registry-policy lease contract failed"); }
        static void Status(int status) { Need(status >= 0); }
        static bool Identifier(string value)
        { return value != null && value.Length == 32 && value.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')); }
        static void RequirePlain(FileAttributes attributes) { Need((attributes & FileAttributes.ReparsePoint) == 0); }
        static void RequireAbsent(Func<FileAttributes> attributes)
        {
            try { attributes(); } catch (FileNotFoundException) { return; }
            throw new InvalidOperationException("fixed registry-policy receipt collision");
        }
        static void Plain(string path, bool missing = false)
        {
            Need(Path.IsPathFullyQualified(path));
            var ancestors = new Stack<string>();
            for (string current = Path.GetFullPath(path); !String.IsNullOrEmpty(current); current = Path.GetDirectoryName(current)) {
                Need(ancestors.Count < 64); ancestors.Push(current);
            }
            while (ancestors.Count != 0) {
                string current = ancestors.Pop();
                try { RequirePlain(File.GetAttributes(current)); }
                catch (FileNotFoundException) { if (!missing || current != path) throw; }
                catch (DirectoryNotFoundException) { if (!missing || current != path) throw; }
            }
        }
        static string State(string run, string state, bool missing = false)
        {
            Need(Identifier(run) && Path.IsPathFullyQualified(state));
            state = Path.GetFullPath(state); Plain(state, missing);
            Need(Path.GetFileName(Path.TrimEndingDirectorySeparator(state)) == "security-windows-" + run);
            return Path.Combine(state, ReceiptName);
        }
        static string Package(string run)
        {
            Need(Identifier(run)); IntPtr sid = IntPtr.Zero;
            int result = Native.DeriveAppContainerSidFromAppContainerName("Scientific.Security." + run, out sid);
            if (result != 0) Marshal.ThrowExceptionForHR(result);
            try { Need(sid != IntPtr.Zero); return new SecurityIdentifier(sid).Value; }
            finally { if (sid != IntPtr.Zero) Need(Native.FreeSid(sid) == IntPtr.Zero); }
        }
        static void ProfileBinding(string run, string state, string package)
        {
            string path = Path.Combine(state, "profile.receipt"); Plain(path);
            byte[] bytes;
            using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                Need(file.Length > 0 && file.Length <= 512); bytes = new byte[(int)file.Length];
                int offset = 0;
                while (offset < bytes.Length) { int count = file.Read(bytes, offset, bytes.Length - offset); Need(count > 0); offset += count; }
            }
            string text = Utf8.GetString(bytes).Replace("\r\n", "\n");
            Need(text == "Scientific.Security." + run + "\n" + package + "\nintent\n" ||
                text == "Scientific.Security." + run + "\n" + package + "\ncreated\n");
        }
        static byte[] AceBytes(GenericAce value)
        { byte[] bytes = new byte[value.BinaryLength]; value.GetBinaryForm(bytes, 0); return bytes; }
        static byte[] Binary(GenericAcl value)
        {
            if (value == null) return null;
            byte[] bytes = new byte[value.BinaryLength]; value.GetBinaryForm(bytes, 0); return bytes;
        }
        static byte[] Binary(RawSecurityDescriptor value)
        { byte[] bytes = new byte[value.BinaryLength]; value.GetBinaryForm(bytes, 0); return bytes; }
        static bool Equal(byte[] first, byte[] second)
        { return first == null ? second == null : second != null && first.SequenceEqual(second); }
        static RawSecurityDescriptor Descriptor(byte[] bytes)
        {
            Need(bytes != null && bytes.Length >= 20 && bytes.Length <= 65536);
            var value = new RawSecurityDescriptor(bytes, 0);
            Need((value.ControlFlags & (ControlFlags.SelfRelative | ControlFlags.DiscretionaryAclPresent)) ==
                (ControlFlags.SelfRelative | ControlFlags.DiscretionaryAclPresent));
            Need(value.Owner != null && value.Group != null && value.DiscretionaryAcl != null && value.DiscretionaryAcl.Count < 256);
            if (value.SystemAcl != null) foreach (GenericAce item in value.SystemAcl)
                Need(item.AceType == (AceType)17 && item.AceFlags == AceFlags.None);
            Need(new CommonSecurityDescriptor(false, false, value).IsDiscretionaryAclCanonical);
            foreach (GenericAce item in value.DiscretionaryAcl) {
                var ace = item as CommonAce;
                Need(ace != null && !ace.IsCallback && (ace.AceQualifier == AceQualifier.AccessAllowed || ace.AceQualifier == AceQualifier.AccessDenied));
            }
            return value;
        }
        static bool Same(byte[] first, byte[] second)
        {
            var a = Descriptor(first); var b = Descriptor(second);
            return a.ResourceManagerControl == b.ResourceManagerControl && a.ControlFlags == b.ControlFlags && a.Owner.Equals(b.Owner) && a.Group.Equals(b.Group) &&
                Equal(Binary(a.DiscretionaryAcl), Binary(b.DiscretionaryAcl)) && Equal(Binary(a.SystemAcl), Binary(b.SystemAcl));
        }
        static byte[] WithTrial(byte[] bytes, string package)
        {
            var original = Descriptor(bytes); var value = Descriptor(bytes);
            var sid = new SecurityIdentifier(package); Need(package.StartsWith("S-1-15-2-", StringComparison.Ordinal));
            int position = value.DiscretionaryAcl.Count;
            for (int index = 0; index < value.DiscretionaryAcl.Count; index++) {
                var ace = (CommonAce)value.DiscretionaryAcl[index];
                Need(!ace.SecurityIdentifier.Equals(sid));
                if (position == value.DiscretionaryAcl.Count && (ace.AceFlags & AceFlags.Inherited) != 0) position = index;
            }
            value.DiscretionaryAcl.InsertAce(position, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x20019, sid, false, null));
            byte[] result = Binary(value); Descriptor(result);
            Need(value.Owner.Equals(original.Owner) && value.Group.Equals(original.Group) && value.ControlFlags == original.ControlFlags &&
                value.ResourceManagerControl == original.ResourceManagerControl && Equal(Binary(value.SystemAcl), Binary(original.SystemAcl)) &&
                value.DiscretionaryAcl.Count == original.DiscretionaryAcl.Count + 1);
            for (int index = 0; index < original.DiscretionaryAcl.Count; index++)
                Need(Equal(AceBytes(original.DiscretionaryAcl[index]), AceBytes(value.DiscretionaryAcl[index < position ? index : index + 1])));
            return result;
        }
        static string Hash(string value)
        {
            using (var sha = SHA256.Create()) return String.Concat(sha.ComputeHash(Utf8.GetBytes(value)).Select(b => b.ToString("x2")));
        }
        static string Encode(string run, string package, string nonce, byte[] before, byte[] after)
        {
            Need(Identifier(run) && Identifier(nonce) && Same(WithTrial(before, package), after));
            string body = "registry-policy-v1\n" + run + "\n" + package + "\n" + nonce + "\nsxs-policy\n" +
                Convert.ToBase64String(before) + "\n" + Convert.ToBase64String(after) + "\n";
            string text = body + Hash(body) + "\n"; Need(Utf8.GetByteCount(text) <= 196608); return text;
        }
        static byte[] ReadReceipt(FileStream file)
        {
            Need(file.Length > 0 && file.Length <= 196608); byte[] bytes = new byte[(int)file.Length];
            int offset = 0;
            while (offset < bytes.Length) { int count = file.Read(bytes, offset, bytes.Length - offset); Need(count > 0); offset += count; }
            return bytes;
        }
        static byte[][] Decode(string text, string run, string package)
        {
            Need(text != null && Utf8.GetByteCount(text) <= 196608);
            string[] parts = text.Split('\n');
            Need(parts.Length == 9 && parts[0] == "registry-policy-v1" && parts[1] == run && parts[2] == package &&
                Identifier(run) && Identifier(parts[3]) && parts[4] == "sxs-policy" && parts[8] == "");
            string body = String.Join("\n", parts.Take(7)) + "\n"; Need(parts[7] == Hash(body));
            byte[] before = Convert.FromBase64String(parts[5]), after = Convert.FromBase64String(parts[6]);
            Need(Convert.ToBase64String(before) == parts[5] && Convert.ToBase64String(after) == parts[6] && Same(WithTrial(before, package), after));
            return new [] { before, after };
        }
        static byte[] Read(IntPtr handle)
        {
            IntPtr data = Marshal.AllocHGlobal(65536);
            try {
                uint returned; Status(NtQuerySecurityObject(handle, 0x17, data, 65536, out returned));
                Need(returned >= 20 && returned <= 65536);
                byte[] bytes = new byte[returned]; Marshal.Copy(data, bytes, 0, bytes.Length); Descriptor(bytes); return bytes;
            }
            finally { Marshal.FreeHGlobal(data); }
        }
        delegate void OpenKey(ref IntPtr handle);
        static IntPtr Acquire(OpenKey open, Action finalize, Action<IntPtr> close)
        {
            IntPtr handle = IntPtr.Zero; Exception primary = null;
            try { open(ref handle); } catch (Exception error) { primary = error; }
            try { finalize(); } catch (Exception error) {
                primary = primary == null ? error : new AggregateException("fixed registry acquisition/finalization failed", primary, error);
            }
            if (primary != null) {
                Finish(primary, () => { if (handle != IntPtr.Zero && handle != Native.InvalidHandle) close(handle); });
                throw primary;
            }
            return handle;
        }
        static IntPtr Open()
        {
            Need(IntPtr.Size == 8 && Marshal.SizeOf(typeof(Name)) == 16 && Marshal.SizeOf(typeof(Attributes)) == 48);
            IntPtr text = IntPtr.Zero, name = IntPtr.Zero, data = IntPtr.Zero;
            return Acquire(delegate(ref IntPtr handle) {
                text = Marshal.StringToHGlobalUni(KeyName); name = Marshal.AllocHGlobal(16);
                Marshal.StructureToPtr(new Name { length = 140, maximum = 142, buffer = text }, name, false);
                var attributes = new Attributes { length = 48, name = name, flags = 0x40 };
                Status(NtOpenKey(out handle, 0x60000, ref attributes)); Need(handle != IntPtr.Zero && handle != Native.InvalidHandle);
                data = Marshal.AllocHGlobal(4096); uint returned;
                Status(NtQueryKey(handle, 3, data, 4096, out returned)); Need(returned >= 4 && returned <= 4096);
                int length = Marshal.ReadInt32(data); Need(length == 140 && length <= returned - 4);
                byte[] bytes = new byte[length]; Marshal.Copy(IntPtr.Add(data, 4), bytes, 0, length);
                Need(new UnicodeEncoding(false, false, true).GetString(bytes).Equals(KeyName, StringComparison.OrdinalIgnoreCase));
            }, () => Finish(null,
                () => { if (data != IntPtr.Zero) Marshal.FreeHGlobal(data); },
                () => { if (name != IntPtr.Zero) Marshal.FreeHGlobal(name); },
                () => { if (text != IntPtr.Zero) Marshal.FreeHGlobal(text); }), handle => Status(NtClose(handle)));
        }
        static void Establish(Action install, Func<bool> persisted, Action recover, Action close)
        {
            try { install(); }
            catch (Exception primary) {
                var failures = new List<Exception>();
                if (persisted()) try { recover(); } catch (Exception error) { failures.Add(error); }
                try { close(); } catch (Exception error) { failures.Add(error); }
                if (failures.Count != 0) throw Combined(primary, failures);
                throw;
            }
        }
        static void Install(byte[] before, byte[] after, Action persist, Func<byte[]> read, Action<byte[]> write)
        {
            persist(); Need(Same(read(), before)); write(after); Need(Same(read(), after));
        }
        static void Restore(byte[] before, byte[] after, Func<byte[]> read, Action<byte[]> write, bool cleanupQualified = true)
        {
            byte[] current = read();
            if (Same(current, before)) return;
            Need(cleanupQualified && Same(current, after)); write(before); Need(Same(read(), before));
        }
        void Restore(bool cleanupQualified = true)
        { Restore(original, expected, () => Read(key), bytes => Status(NtSetSecurityObject(key, 4, bytes)), cleanupQualified); }
        static void Finish(Exception primary, params Action[] actions)
        {
            var failures = new List<Exception>();
            foreach (Action action in actions) try { action(); } catch (Exception failure) { failures.Add(failure); }
            if (failures.Count != 0) throw Combined(primary, failures);
        }
        void Close()
        {
            if (closed) return; closed = true;
            IntPtr owned = key; key = IntPtr.Zero;
            Mutex held = mutex; mutex = null;
            Finish(null, () => { if (owned != IntPtr.Zero) Status(NtClose(owned)); }, () => { if (held != null) held.Dispose(); });
        }
        public static void CleanupOwned(Action recovery, Action snaps, Action profile, Action disk, Action remove)
        {
            var failures = new List<Exception>(); bool restored = false;
            try { recovery(); restored = true; } catch (Exception error) { failures.Add(error); }
            try { snaps(); } catch (Exception error) { failures.Add(error); }
            if (restored) try { profile(); } catch (Exception error) { failures.Add(error); }
            try { disk(); } catch (Exception error) { failures.Add(error); }
            if (failures.Count == 0) try { remove(); } catch (Exception error) { failures.Add(error); }
            if (failures.Count != 0) throw Combined(null, failures);
        }
        static AggregateException Combined(Exception primary, List<Exception> failures)
        {
            if (primary != null) failures.Insert(0, primary);
            return new AggregateException("fixed registry-policy operation/recovery failed", failures);
        }
        static RegistryPolicyLease New(string run, string state)
        {
            var lease = new RegistryPolicyLease(); bool created;
            try {
                lease.receipt = State(run, state);
                lease.mutex = new Mutex(false, MutexName, out created); Need(created);
                lease.key = Open(); return lease;
            }
            catch (Exception primary) {
                try { lease.Close(); } catch (Exception cleanup) { throw new AggregateException("fixed registry-policy acquisition failed", primary, cleanup); }
                throw;
            }
        }
        public static RegistryPolicyLease Begin(string run, string state)
        {
            string package = Package(run); ProfileBinding(run, state, package);
            RegistryPolicyLease lease = New(run, state);
            Establish(() => {
                Plain(lease.receipt, true);
                RequireAbsent(() => File.GetAttributes(lease.receipt));
                lease.original = Read(lease.key); lease.expected = WithTrial(lease.original, package);
                byte[] bytes = Utf8.GetBytes(Encode(run, package, Guid.NewGuid().ToString("N"), lease.original, lease.expected));
                Install(lease.original, lease.expected, () => {
                    using (var file = new FileStream(lease.receipt, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None)) {
                        file.Write(bytes, 0, bytes.Length); file.Flush(true); file.Position = 0;
                        Need(Equal(ReadReceipt(file), bytes));
                    }
                    lease.receiptBytes = bytes; lease.intent = true;
                }, () => Read(lease.key), value => Status(NtSetSecurityObject(lease.key, 4, value)));
            }, () => lease.intent, () => lease.Restore(), lease.Close);
            return lease;
        }
        public void DeferRecovery() { recoveryBlocked = true; Close(); }
        public static void Recover(string run, string state, bool outerOwnerReaped = false)
        {
            Need(!recoveryBlocked);
            string path = State(run, state, true);
            try { File.GetAttributes(state); } catch (FileNotFoundException) { return; } catch (DirectoryNotFoundException) { return; }
            Plain(path, true);
            try { File.GetAttributes(path); } catch (FileNotFoundException) { return; }
            string package = Package(run); ProfileBinding(run, state, package);
            RegistryPolicyLease lease = New(run, state);
            try {
                byte[] bytes;
                using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) bytes = ReadReceipt(file);
                byte[][] parsed = Decode(Utf8.GetString(bytes), run, package);
                lease.original = parsed[0]; lease.expected = parsed[1]; lease.receiptBytes = bytes; lease.intent = true;
                lease.DisposeQualified(outerOwnerReaped);
            }
            catch (Exception primary) {
                try { lease.Close(); } catch (Exception error) { throw new AggregateException("fixed registry-policy recovery failed", primary, error); }
                throw;
            }
        }
        static void CompleteLease(bool intent, Action restore, Action close, Action remove)
        {
            var failures = new List<Exception>();
            try { if (intent) restore(); } catch (Exception error) { failures.Add(error); }
            try { close(); } catch (Exception error) { failures.Add(error); }
            if (intent && failures.Count == 0) try { remove(); } catch (Exception error) { failures.Add(error); }
            if (failures.Count != 0) throw Combined(null, failures);
        }
        static void FinishRestore(byte[] before, byte[] after, Func<byte[]> read, Action<byte[]> write, bool cleanupQualified)
        { Restore(before, after, read, write, cleanupQualified); Need(cleanupQualified); }
        public void Dispose() { DisposeQualified(true); }
        void DisposeQualified(bool cleanupQualified)
        {
            if (closed) return;
            CompleteLease(intent, () => FinishRestore(original, expected, () => Read(key),
                bytes => Status(NtSetSecurityObject(key, 4, bytes)), cleanupQualified), Close, () => {
                Plain(receipt);
                using (var file = new FileStream(receipt, FileMode.Open, FileAccess.Read, FileShare.None)) Need(Equal(ReadReceipt(file), receiptBytes));
                File.Delete(receipt);
            });
        }

        static void CheckFailureProtocol(byte[] before, byte[] after, byte[] foreign, string run, string package, string receipt)
        {
            var operation = new InvalidOperationException("fixed operation"); var final = new InvalidOperationException("fixed finalization");
            var closing = new InvalidOperationException("fixed closing"); int closes = 0; Exception caught = null;
            try { Acquire(delegate(ref IntPtr handle) { handle = new IntPtr(1); }, () => { throw final; }, _ => closes++); }
            catch (Exception error) { caught = error; }
            Need(Object.ReferenceEquals(caught, final) && closes == 1);
            caught = null;
            try { Acquire(delegate(ref IntPtr handle) { handle = new IntPtr(1); throw operation; }, () => { throw final; }, _ => { closes++; throw closing; }); }
            catch (Exception error) { caught = error; }
            var all = ((AggregateException)caught).Flatten().InnerExceptions;
            Need(closes == 2 && all.Count == 3 && all.Contains(operation) && all.Contains(final) && all.Contains(closing));
            foreach (bool readbackFails in new [] { false, true }) {
                byte[] current = before; bool intent = false; int writes = 0, reads = 0; closes = 0; caught = null;
                try {
                    Establish(() => Install(before, after, () => intent = true,
                        () => { if (readbackFails && ++reads == 2) throw operation; return current; },
                        value => { current = value; writes++; if (!readbackFails) throw operation; }),
                        () => intent, () => Restore(before, after, () => current, value => { current = value; writes++; }), () => closes++);
                }
                catch (Exception error) { caught = error; }
                Need(Object.ReferenceEquals(caught, operation) && intent && writes == 2 && closes == 1 && Same(current, before));
            }
            int restoreCalls = 0; caught = null;
            try { Establish(() => { throw operation; }, () => true, () => { restoreCalls++; throw final; }, () => { closes++; throw closing; }); }
            catch (Exception error) { caught = error; }
            all = ((AggregateException)caught).Flatten().InnerExceptions;
            Need(restoreCalls == 1 && all.Count == 3 && all.Contains(operation) && all.Contains(final) && all.Contains(closing));
            int setters = 0; caught = null;
            try { Restore(before, after, () => after, _ => setters++, false); } catch (InvalidOperationException error) { caught = error; }
            Need(caught != null && setters == 0);
            Restore(before, after, () => before, _ => setters++, false); Need(setters == 0);
            int retired = 0; caught = null;
            try { CompleteLease(true, () => FinishRestore(before, after, () => before, _ => setters++, false),
                () => { }, () => retired++); } catch (AggregateException error) { caught = error; }
            Need(caught != null && retired == 0 && setters == 0);
            foreach (Action prewrite in new Action[] {
                () => RequireAbsent(() => FileAttributes.Normal), () => RequirePlain(FileAttributes.ReparsePoint),
                () => Decode(receipt.Substring(0, receipt.Length / 2), run, package),
                () => Decode(receipt.Substring(0, receipt.Length - 65) + new string('0', 64) + "\n", run, package)
            }) {
                bool persisted = false; caught = null;
                try { Establish(() => Install(before, after, () => { prewrite(); persisted = true; }, () => before, _ => setters++),
                    () => persisted, () => restoreCalls++, () => closes++); } catch (Exception error) { caught = error; }
                Need(caught != null && !persisted && setters == 0);
            }
            int removals = 0; closes = 0; caught = null;
            try { CompleteLease(true, () => { throw operation; }, () => { closes++; throw closing; }, () => removals++); }
            catch (Exception error) { caught = error; }
            all = ((AggregateException)caught).InnerExceptions;
            Need(closes == 1 && removals == 0 && all.Count == 2 && Object.ReferenceEquals(all[0], operation) && Object.ReferenceEquals(all[1], closing));
            var order = new List<string>(); caught = null;
            try { CleanupOwned(() => { order.Add("recovery"); throw operation; }, () => { order.Add("snaps"); throw final; },
                () => order.Add("profile"), () => { order.Add("disk"); throw closing; }, () => order.Add("remove")); }
            catch (Exception error) { caught = error; }
            all = ((AggregateException)caught).InnerExceptions;
            Need(String.Join(",", order) == "recovery,snaps,disk" && all.Count == 3 &&
                Object.ReferenceEquals(all[0], operation) && Object.ReferenceEquals(all[1], final) && Object.ReferenceEquals(all[2], closing));
            byte[] inherited = Binary(new RawSecurityDescriptor("O:SYG:SYD:(A;;KR;;;SY)(A;ID;KR;;;BU)S:(ML;;NW;;;ME)"));
            var changed = Descriptor(WithTrial(inherited, package));
            Need(((CommonAce)changed.DiscretionaryAcl[1]).SecurityIdentifier.Value == package &&
                (changed.DiscretionaryAcl[2].AceFlags & AceFlags.Inherited) != 0);
        }
        public static void CheckValidation()
        {
            string package = "S-1-15-2-1-2-3-4-5-6-7", run = new string('a', 32), nonce = new string('b', 32);
            byte[] before = Binary(new RawSecurityDescriptor("O:SYG:SYD:P(A;;KR;;;SY)(A;;KR;;;BU)S:(ML;;NW;;;ME)"));
            byte[] after = WithTrial(before, package); var a = Descriptor(after); var b = Descriptor(before);
            Need(a.DiscretionaryAcl.Count == 3 && b.DiscretionaryAcl.Count == 2);
            var added = (CommonAce)a.DiscretionaryAcl[2];
            Need(added.AccessMask == 0x20019 && added.AceFlags == AceFlags.None && added.AceQualifier == AceQualifier.AccessAllowed && added.SecurityIdentifier.Value == package);
            Need(Equal(Binary(b.DiscretionaryAcl), Binary(Descriptor(before).DiscretionaryAcl)) && !Same(before, after));
            string receipt = Encode(run, package, nonce, before, after); var parsed = Decode(receipt, run, package);
            Need(Same(parsed[0], before) && Same(parsed[1], after));
            CheckFailureProtocol(before, after, Binary(new RawSecurityDescriptor("O:SYG:SYD:P(A;;KA;;;SY)S:(ML;;NW;;;ME)")), run, package, receipt);
            foreach (Action invalid in new Action[] {
                () => WithTrial(after, package), () => Decode(receipt, nonce, package),
                () => Decode(receipt.Replace("sxs-policy", "other"), run, package),
                () => Decode(receipt + "extra", run, package), () => Decode(receipt.Substring(0, receipt.Length - 1), run, package),
                () => Descriptor(new byte[19]), () => Descriptor(Binary(new RawSecurityDescriptor("O:SYG:SYD:NO_ACCESS_CONTROL")))
            }) {
                bool refused = false; try { invalid(); } catch (Exception) { refused = true; } Need(refused);
            }
            int writes = 0;
            Restore(before, after, () => before, _ => writes++); Need(writes == 0);
            byte[] current = after;
            Restore(before, after, () => current, value => { writes++; current = value; }); Need(writes == 1 && Same(current, before));
            byte[] foreign = Binary(new RawSecurityDescriptor("O:SYG:SYD:P(A;;KA;;;SY)S:(ML;;NW;;;ME)"));
            bool conflict = false;
            try { Restore(before, after, () => foreign, _ => writes++); } catch (InvalidOperationException) { conflict = true; }
            Need(conflict && writes == 1);
            var order = new List<string>(); current = before;
            Install(before, after, () => order.Add("intent"), () => { order.Add("read"); return current; },
                value => { order.Add("write"); current = value; });
            Need(String.Join(",", order) == "intent,read,write,read" && Same(current, after));
            var primary = new InvalidOperationException("fixed intent failure"); var cleanup = new InvalidOperationException("fixed cleanup failure");
            writes = 0; Exception caught = null;
            try { Install(before, after, () => { throw primary; }, () => before, _ => writes++); } catch (Exception error) { caught = error; }
            Need(Object.ReferenceEquals(caught, primary) && writes == 0);
            caught = null;
            try { Install(before, after, () => { }, () => foreign, _ => writes++); } catch (InvalidOperationException error) { caught = error; }
            Need(caught != null && writes == 0);
            int attempts = 0; AggregateException aggregate = null;
            try { Finish(primary, () => { attempts++; throw cleanup; }, () => attempts++, () => attempts++); }
            catch (AggregateException error) { aggregate = error; }
            Need(attempts == 3 && aggregate != null && aggregate.InnerExceptions.Count == 2 &&
                Object.ReferenceEquals(aggregate.InnerExceptions[0], primary) && Object.ReferenceEquals(aggregate.InnerExceptions[1], cleanup));
        }
    }
}
