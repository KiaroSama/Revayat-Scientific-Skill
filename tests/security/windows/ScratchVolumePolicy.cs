using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ScientificSecurity
{
    // Exact disposable-volume diagnostic/supported leases. Compare/set/readback is not atomic.
    public sealed class ScratchVolumePolicy : IDisposable
    {
        const string ReceiptName = "scratch-volume-policy.receipt";
        static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
        static ScratchVolumePolicy active;
        static int runs;
        static bool uncertain, selected, cleanupQualified;
        static IntPtr selectedJob, selectedProcess;
        [StructLayout(LayoutKind.Sequential)] struct FileIdentity { internal ulong volume, high, low; }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandleEx(IntPtr handle, int kind, out FileIdentity identity, uint bytes);
        [DllImport("ntdll.dll")] static extern int NtQuerySecurityObject(IntPtr handle, uint fields, IntPtr data, uint length, out uint returned);
        [DllImport("ntdll.dll")] static extern int NtSetSecurityObject(IntPtr handle, uint fields, byte[] descriptor);
        string run, state, root, package;
        uint disk, partition;
        FileIdentity imageIdentity;
        IntPtr volume;
        byte[] before, after, receiptBytes;
        bool possible, closed, supported, ready, running, deferred, cleanupProved;
        ScratchVolumePolicy() { }
        static void Need(bool value)
        { if (!value) throw new InvalidOperationException("fixed scratch volume policy is unqualified"); }
        static bool Valid(IntPtr handle) { return handle != IntPtr.Zero && handle != Native.InvalidHandle; }
        static bool Identifier(string text)
        { return text != null && text.Length == 32 && text.All(c => c >= '0' && c <= '9' || c >= 'a' && c <= 'f'); }
        static string State(string run, string state)
        {
            Need(Identifier(run) && Path.IsPathFullyQualified(state)); state = Path.GetFullPath(state); Plain(state);
            Need(Path.GetFileName(Path.TrimEndingDirectorySeparator(state)) == "security-windows-" + run); return state;
        }
        static void Plain(string path)
        {
            Need(Path.IsPathFullyQualified(path)); var parents = new Stack<string>();
            for (string current = Path.GetFullPath(path); !String.IsNullOrEmpty(current); current = Path.GetDirectoryName(current)) {
                Need(parents.Count < 64); parents.Push(current);
            }
            while (parents.Count != 0) Need((File.GetAttributes(parents.Pop()) & FileAttributes.ReparsePoint) == 0);
        }
        static string Package(string run)
        {
            IntPtr sid = IntPtr.Zero; int status = Native.DeriveAppContainerSidFromAppContainerName("Scientific.Security." + run, out sid);
            if (status != 0) Marshal.ThrowExceptionForHR(status);
            try { Need(sid != IntPtr.Zero); return new SecurityIdentifier(sid).Value; }
            finally { if (sid != IntPtr.Zero) Need(Native.FreeSid(sid) == IntPtr.Zero); }
        }
        internal static void EnterRun()
        { Need(runs == 0 && !uncertain && active == null); runs = 1; selected = false; cleanupQualified = false; }
        internal static void EndRun(bool clean)
        {
            Need(runs == 1); runs = 0; cleanupQualified = clean; uncertain |= !clean || active != null;
            selected = false; selectedJob = selectedProcess = IntPtr.Zero;
        }
        internal static void SelectSuspended(IntPtr job, Native.ProcessInfo process)
        {
            Need(runs == 1 && !uncertain && active == null && !selected);
            selectedJob = job; selectedProcess = process.process; selected = true; RequireSuspended();
        }
        internal static bool Supports(string phase, bool observe, int? registry, bool qualified)
        {
            return (phase == "preflight" || phase == "wall" || phase == "regressions") && registry == 0 &&
                (qualified || observe && phase == "preflight");
        }
        internal static void RequireResume(bool required)
        {
            RequireHost(); Need(!required || active != null);
            if (active != null) {
                RequireSuspended(); Need(active.supported && active.ready && active.possible && !active.deferred);
                active.Bind(); Need(Same(Read(active.volume), active.after)); active.running = true;
            }
            selected = false;
        }
        internal void QualifySupported()
        { RequireHost(); RequireSuspended(); Need(active == this && supported && possible && !ready && !running && !deferred); ready = true; }
        internal static void CompleteSupported(bool clean, Action restore, Action defer)
        {
            if (!clean) { Finish(new InvalidOperationException("supported scratch process cleanup remains uncertain"), defer); return; }
            restore();
        }
        internal static void FinishSupported(bool clean)
        {
            var lease = active; if (lease == null) return;
            CompleteSupported(clean, () => { lease.running = false; lease.cleanupProved = true; lease.Dispose(); }, lease.DeferRecovery);
        }
        internal void DeferRecovery()
        { RequireHost(); Need(active == this); deferred = true; uncertain = true; Close(); active = null; }
        static void RequireSuspended()
        {
            Need(selected && runs == 1 && !uncertain && Valid(selectedJob) && Valid(selectedProcess));
            var accounting = Native.QueryJob<Native.Accounting>(selectedJob, 1);
            Need(accounting.activeProcesses == 1 && accounting.totalProcesses == 1 &&
                Native.WaitForSingleObject(selectedProcess, 0) == 0x102);
        }
        static byte[] Binary(GenericAcl value)
        { if (value == null) return null; var bytes = new byte[value.BinaryLength]; value.GetBinaryForm(bytes, 0); return bytes; }
        static byte[] Binary(RawSecurityDescriptor value)
        { var bytes = new byte[value.BinaryLength]; value.GetBinaryForm(bytes, 0); return bytes; }
        static bool Equal(byte[] a, byte[] b)
        { return a == null ? b == null : b != null && a.SequenceEqual(b); }
        static RawSecurityDescriptor Descriptor(byte[] bytes)
        {
            Need(bytes != null && bytes.Length >= 20 && bytes.Length <= 65536);
            var sd = new RawSecurityDescriptor(bytes, 0);
            Need(sd.Owner != null && sd.Group != null && sd.DiscretionaryAcl != null && sd.DiscretionaryAcl.Count < 256 &&
                (sd.ControlFlags & (ControlFlags.SelfRelative | ControlFlags.DiscretionaryAclPresent)) ==
                (ControlFlags.SelfRelative | ControlFlags.DiscretionaryAclPresent));
            Need(new CommonSecurityDescriptor(false, false, sd).IsDiscretionaryAclCanonical);
            foreach (GenericAce item in sd.DiscretionaryAcl) {
                var ace = item as CommonAce;
                Need(ace != null && !ace.IsCallback &&
                    (ace.AceQualifier == AceQualifier.AccessAllowed || ace.AceQualifier == AceQualifier.AccessDenied));
            }
            if (sd.SystemAcl != null) {
                Need(sd.SystemAcl.Count <= 16);
                foreach (GenericAce item in sd.SystemAcl) Need((int)item.AceType == 17 && item.AceFlags == AceFlags.None);
            }
            return sd;
        }
        static bool Same(byte[] a, byte[] b)
        {
            var first = Descriptor(a); var second = Descriptor(b);
            return first.Owner == second.Owner && first.Group == second.Group && first.ControlFlags == second.ControlFlags &&
                first.ResourceManagerControl == second.ResourceManagerControl &&
                Equal(Binary(first.DiscretionaryAcl), Binary(second.DiscretionaryAcl)) && Equal(Binary(first.SystemAcl), Binary(second.SystemAcl));
        }
        static byte[] Trial(byte[] bytes, string package, bool supported = false)
        {
            var original = Descriptor(bytes); var trial = Descriptor(bytes); var sid = new SecurityIdentifier(package);
            Need(package.StartsWith("S-1-15-2-", StringComparison.Ordinal)); int position = trial.DiscretionaryAcl.Count;
            for (int i = 0; i < trial.DiscretionaryAcl.Count; i++) {
                var ace = (CommonAce)trial.DiscretionaryAcl[i]; Need(ace.SecurityIdentifier != sid);
                if (position == trial.DiscretionaryAcl.Count && (ace.AceFlags & AceFlags.Inherited) != 0) position = i;
            }
            trial.DiscretionaryAcl.InsertAce(position, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, supported ? 0x100020 : 0x20, sid, false, null));
            byte[] result = Binary(trial); Descriptor(result);
            Need(trial.Owner == original.Owner && trial.Group == original.Group && trial.ControlFlags == original.ControlFlags &&
                trial.ResourceManagerControl == original.ResourceManagerControl && Equal(Binary(trial.SystemAcl), Binary(original.SystemAcl)));
            for (int i = 0; i < original.DiscretionaryAcl.Count; i++) {
                var old = original.DiscretionaryAcl[i]; var changed = trial.DiscretionaryAcl[i < position ? i : i + 1];
                var oldBytes = new byte[old.BinaryLength]; var changedBytes = new byte[changed.BinaryLength];
                old.GetBinaryForm(oldBytes, 0); changed.GetBinaryForm(changedBytes, 0); Need(Equal(oldBytes, changedBytes));
            }
            return result;
        }
        static byte[] Read(IntPtr handle)
        {
            IntPtr data = Marshal.AllocHGlobal(65536); bool pending = false;
            try {
                uint returned; int status = NtQuerySecurityObject(handle, 0x17, data, 65536, out returned);
                pending = status == 0x103;
                if (pending) Environment.FailFast("Scratch policy query remained pending; outer owner must recover.");
                Need(status == 0 && returned >= 20 && returned <= 65536);
                var bytes = new byte[returned]; Marshal.Copy(data, bytes, 0, bytes.Length); Descriptor(bytes); return bytes;
            }
            finally { if (!pending) Marshal.FreeHGlobal(data); }
        }
        static void Write(IntPtr handle, byte[] bytes)
        { Need(NtSetSecurityObject(handle, 4, bytes) == 0); }
        static FileIdentity Image(string state)
        {
            string path = Path.Combine(state, "scratch.vhdx"); Plain(path);
            IntPtr handle = CreateFileW(path, 0x80, 3, IntPtr.Zero, 3, 0x200000, IntPtr.Zero);
            Native.Check(Valid(handle), "open scratch policy image identity"); Exception primary = null; FileIdentity result = default(FileIdentity);
            try { Native.Check(GetFileInformationByHandleEx(handle, 18, out result, 24), "read scratch policy image identity"); }
            catch (Exception error) { primary = error; }
            Finish(primary, () => Native.Check(Native.CloseHandle(handle), "close scratch policy image identity")); return result;
        }
        static void SameIdentity(FileIdentity a, FileIdentity b)
        { Need(a.volume == b.volume && a.high == b.high && a.low == b.low); }
        void Bind()
        {
            SameIdentity(imageIdentity, Image(state));
            IntPtr data = Marshal.AllocHGlobal(12);
            try {
                uint returned; Native.Check(Native.DeviceIoControl(volume, 0x2D1080, IntPtr.Zero, 0, data, 12, out returned, IntPtr.Zero),
                    "bind owned scratch policy volume");
                Need(returned == 12 && Marshal.ReadInt32(data) == 7 && unchecked((uint)Marshal.ReadInt32(data, 4)) == disk &&
                    unchecked((uint)Marshal.ReadInt32(data, 8)) == partition && partition > 0);
            }
            finally { Marshal.FreeHGlobal(data); }
        }
        void Open()
        {
            Need(root != null && root.Length == 3 && root[0] >= 'D' && root[0] <= 'Z' && root[1] == ':' && root[2] == '\\');
            volume = CreateFileW(@"\\.\" + root.Substring(0, 2), 0x60000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
            Native.Check(Valid(volume), "open exact scratch volume DACL lease"); Bind();
        }
        static string Hash(string text)
        { using (var hash = SHA256.Create()) return String.Concat(hash.ComputeHash(Utf8.GetBytes(text)).Select(b => b.ToString("x2"))); }
        string Encode()
        {
            string body = "scratch-volume-v3\n" + run + "\n" + package + "\n" + (supported ? "supported" : "diagnostic") + "\n" + root + "\n" + disk + "\n" + partition + "\n" +
                imageIdentity.volume.ToString("X16") + ":" + imageIdentity.high.ToString("X16") + ":" + imageIdentity.low.ToString("X16") + "\n" +
                Convert.ToBase64String(before) + "\n" + Convert.ToBase64String(after) + "\n";
            return body + Hash(body) + "\n";
        }
        void Decode(byte[] bytes, string expectedPackage)
        {
            Need(bytes != null && bytes.Length > 0 && bytes.Length <= 196608); string text = Utf8.GetString(bytes); string[] values = text.Split('\n');
            Need(values.Length == 12 && values[0] == "scratch-volume-v3" && values[1] == run && values[2] == expectedPackage &&
                (values[3] == "diagnostic" || values[3] == "supported") &&
                values[11] == "" && values[10] == Hash(String.Join("\n", values.Take(10)) + "\n"));
            supported = values[0] == "scratch-volume-v3" && values[3] == "supported";
            package = values[2]; root = values[4];
            Need(values[5].Length > 0 && values[5].Length <= 10 && values[5].All(c => c >= '0' && c <= '9') &&
                values[6].Length > 0 && values[6].Length <= 10 && values[6].All(c => c >= '0' && c <= '9'));
            disk = UInt32.Parse(values[5], System.Globalization.CultureInfo.InvariantCulture);
            partition = UInt32.Parse(values[6], System.Globalization.CultureInfo.InvariantCulture);
            string[] identity = values[7].Split(':');
            Need(identity.Length == 3 && identity.All(v => v.Length == 16 && v.All(c => c >= '0' && c <= '9' || c >= 'A' && c <= 'F')));
            imageIdentity = new FileIdentity { volume = Convert.ToUInt64(identity[0], 16), high = Convert.ToUInt64(identity[1], 16), low = Convert.ToUInt64(identity[2], 16) };
            before = Convert.FromBase64String(values[8]); after = Convert.FromBase64String(values[9]);
            Need(Same(Trial(before, package, supported), after)); receiptBytes = bytes;
        }
        static byte[] ReadReceipt(FileStream file)
        {
            Need(file.Length > 0 && file.Length <= 196608); var bytes = new byte[(int)file.Length]; int offset = 0;
            while (offset < bytes.Length) { int count = file.Read(bytes, offset, bytes.Length - offset); Need(count > 0); offset += count; }
            return bytes;
        }
        void Persist()
        {
            receiptBytes = Utf8.GetBytes(Encode()); Need(receiptBytes.Length <= 196608);
            using (WindowsIdentity host = WindowsIdentity.GetCurrent()) {
                IntPtr descriptor = IntPtr.Zero; uint length;
                Native.Check(Native.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    "D:P(D;;0x000C0000;;;OW)(D;;FA;;;" + package + ")(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + host.User.Value + ")",
                    1, out descriptor, out length), "create private scratch recovery descriptor");
                try {
                    var attributes = new Native.SecurityAttributes { size = (uint)Marshal.SizeOf(typeof(Native.SecurityAttributes)), descriptor = descriptor };
                    IntPtr handle = Native.CreateFileW(Path.Combine(state, ReceiptName), 0xC0000000, 1, ref attributes, 1, 0x200080, IntPtr.Zero);
                    Native.Check(Valid(handle), "create private scratch policy receipt");
                    using (var file = new FileStream(new SafeFileHandle(handle, true), FileAccess.ReadWrite)) {
                        file.Write(receiptBytes, 0, receiptBytes.Length); file.Flush(true); file.Position = 0; Need(Equal(ReadReceipt(file), receiptBytes));
                    }
                }
                finally { if (descriptor != IntPtr.Zero) Need(Native.LocalFree(descriptor) == IntPtr.Zero); }
            }
        }
        internal static ScratchVolumePolicy Begin(string run, string state, string root, uint disk, uint partition, string package, bool supported = false)
        {
            RequireSuspended(); Need(active == null && package == Package(run));
            var lease = new ScratchVolumePolicy { run = run, state = State(run, state), root = root, disk = disk, partition = partition, package = package, supported = supported };
            try {
                lease.imageIdentity = Image(lease.state); lease.Open(); lease.before = Read(lease.volume); lease.after = Trial(lease.before, package, supported);
                active = lease; return lease;
            }
            catch (Exception error) { Finish(error, lease.Close); throw; }
        }
        static void RequireHost()
        { using (WindowsIdentity thread = WindowsIdentity.GetCurrent(true)) Need(thread == null); }
        internal void Install()
        {
            RequireHost(); RequireSuspended(); Need(active == this && !possible); Bind(); Persist(); Need(Same(Read(volume), before));
            possible = true; Write(volume, after); Need(Same(Read(volume), after));
        }
        static void Restore(byte[] before, byte[] after, Func<byte[]> read, Action<byte[]> write)
        {
            byte[] actual = read(); if (Same(actual, before)) return;
            Need(Same(actual, after)); write(before); Need(Same(read(), before));
        }
        static bool CanRestore(bool supported, bool running, bool deferred, bool clean)
        { return !deferred && (!supported || !running && clean); }
        internal void Restore()
        { RequireHost(); Need(CanRestore(supported, running, deferred, cleanupProved)); if (possible) { Bind(); Restore(before, after, () => Read(volume), bytes => Write(volume, bytes)); } }
        static List<int[]> Differential(Func<int[]> probe, Action qualify, Action install, Action restore)
        {
            var results = new List<int[]>(); Exception primary = null; var failures = new List<Exception>();
            try {
                qualify(); results.Add(probe());
                Need(results[0].Length >= 2 && results[0].Take(2).All(value => value == unchecked((int)0xC0000022)));
                qualify(); install(); results.Add(probe()); qualify();
                Need(results[1].Length == results[0].Length && results[1].Take(2).All(value => value == 0 || value == unchecked((int)0xC0000022)));
            }
            catch (Exception error) { primary = error; }
            finally { Attempt(failures, restore); }
            if (failures.Count == 0 && primary == null) {
                try { qualify(); results.Add(probe()); Need(results[2].SequenceEqual(results[0])); }
                catch (Exception error) { primary = error; }
            }
            Finish(primary, failures.ToArray()); return results;
        }
        internal List<string> Compare(Func<int[]> probe, Action deadline, Func<string, int[], List<string>> extra = null)
        {
            Need(!supported); List<int[]> results = null; Exception primary = null;
            try { results = Differential(probe, () => { deadline(); RequireSuspended(); }, Install, Restore); }
            catch (Exception error) { primary = error; }
            Finish(primary, Dispose);
            var frames = new List<string>(); string[] phases = { "baseline", "modified", "restored" };
            for (int i = 0; i < results.Count; i++) for (int j = 0; j < 2; j++)
                frames.Add("WINDOWS_SCRATCH_POLICY phase=" + phases[i] + " object=" + (j == 0 ? "root" : "temp") +
                    " ntstatus=0x" + unchecked((uint)results[i][j]).ToString("X8") +
                    " descriptor_restored=True handles_closed=True cause_claimed=False admission=False");
            if (extra != null) for (int i = 0; i < results.Count; i++) frames.AddRange(extra(phases[i], results[i]));
            return frames;
        }
        void Close()
        {
            if (closed) return; closed = true; IntPtr handle = volume; volume = IntPtr.Zero;
            if (Valid(handle)) Native.Check(Native.CloseHandle(handle), "close scratch volume DACL lease");
        }
        public void Dispose()
        {
            if (closed) return; bool restored = false; var failures = new List<Exception>();
            Attempt(failures, () => { Restore(); restored = true; }); Attempt(failures, Close);
            if (restored && failures.Count == 0 && receiptBytes != null) Attempt(failures, () => {
                string path = Path.Combine(state, ReceiptName); Plain(path);
                using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None)) Need(Equal(ReadReceipt(file), receiptBytes));
                File.Delete(path);
            });
            if (failures.Count == 0) { if (active == this) active = null; }
            else uncertain = true;
            Finish(null, failures.ToArray());
        }
        public static bool HasReceipt(string run, string state)
        {
            string path = Path.Combine(State(run, state), ReceiptName);
            try { Plain(path); return true; } catch (FileNotFoundException) { return false; }
        }
        static bool RecoveryAvailable(bool outerReaped, bool clean, int activeRuns, bool chosen)
        { return outerReaped || clean && activeRuns == 0 && !chosen; }
        public static void Recover(string run, string state, uint actualDisk, bool outerOwnerReaped)
        {
            RequireHost(); Need(RecoveryAvailable(outerOwnerReaped, cleanupQualified, runs, selected)); state = State(run, state);
            string path = Path.Combine(state, ReceiptName); Plain(path);
            var lease = new ScratchVolumePolicy { run = run, state = state, possible = true, cleanupProved = true };
            try {
                using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) lease.Decode(ReadReceipt(file), Package(run));
                Need(lease.disk == actualDisk); lease.Open(); lease.Dispose();
            }
            catch (Exception error) { Finish(error, lease.Close); throw; }
        }
        static void Attempt(List<Exception> failures, Action action)
        { try { action(); } catch (Exception error) { failures.Add(error); } }
        static void Finish(Exception primary, params Action[] actions)
        {
            var failures = new List<Exception>(); foreach (Action action in actions) Attempt(failures, action);
            Finish(primary, failures.ToArray());
        }
        static void Finish(Exception primary, Exception[] failures)
        {
            if (failures.Length == 0) { if (primary != null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw(); return; }
            var all = new List<Exception>(); if (primary != null) all.Add(primary); all.AddRange(failures);
            throw new AggregateException("scratch volume policy operation/recovery failed", all);
        }
        public static void CheckValidation()
        {
            foreach (string phase in new [] { "preflight", "wall", "regressions", "registry-authority", "module-id2", "python-loader-trace" })
                foreach (bool observe in new [] { false, true }) foreach (bool qualified in new [] { false, true })
                    foreach (int? registry in new int?[] { null, 0, unchecked((int)0xC0000022) })
                        Need(Supports(phase, observe, registry, qualified) ==
                            ((phase == "preflight" || phase == "wall" || phase == "regressions") && registry == 0 &&
                            (qualified || observe && phase == "preflight")));
            foreach (bool supported in new [] { false, true }) foreach (bool running in new [] { false, true })
                foreach (bool deferred in new [] { false, true }) foreach (bool clean in new [] { false, true })
                    Need(CanRestore(supported, running, deferred, clean) == (!deferred && (!supported || !running && clean)));
            for (int mode = 0; mode < 4; mode++) {
                var order = new List<string>(); var failure = new IOException("fixed restoration"); bool caught = false;
                try { CompleteSupported(mode != 1 && mode != 3, () => { order.Add("restore"); if (mode == 2) throw failure; },
                    () => { order.Add("defer"); if (mode == 3) throw failure; }); }
                catch (Exception error) { caught = true; Need(mode == 1 || mode == 3 || Object.ReferenceEquals(error, failure)); }
                Need(caught == (mode != 0) && String.Join(",", order) == (mode == 1 || mode == 3 ? "defer" : "restore"));
                if (mode == 3) {
                    bool retained = false;
                    try { CompleteSupported(false, () => { }, () => { throw failure; }); }
                    catch (AggregateException error) { retained = error.InnerExceptions.Count == 2 &&
                        error.InnerExceptions[0].Message == "supported scratch process cleanup remains uncertain" &&
                        Object.ReferenceEquals(error.InnerExceptions[1], failure); }
                    Need(retained);
                }
            }
            const string sid = "S-1-15-2-1-2-3-4-5-6-7";
            byte[] original = Binary(new RawSecurityDescriptor("O:SYG:SYD:P(A;;GA;;;SY)(A;;GR;;;BU)S:(ML;;NW;;;ME)"));
            byte[] trial = Trial(original, sid); var expected = Descriptor(trial); var added = (CommonAce)expected.DiscretionaryAcl[2];
            Need(added.AccessMask == 0x20 && (added.AccessMask & 0x100000) == 0 &&
                added.AceFlags == AceFlags.None && added.SecurityIdentifier.Value == sid && !Same(original, trial));
            bool refused = false; try { Trial(trial, sid); } catch (InvalidOperationException) { refused = true; } Need(refused);
            byte[] actual = trial; int writes = 0;
            Restore(original, trial, () => actual, bytes => { writes++; actual = bytes; }); Need(writes == 1 && Same(actual, original));
            Restore(original, trial, () => original, _ => writes++); Need(writes == 1);
            refused = false; try { Restore(original, trial, () => Binary(new RawSecurityDescriptor("O:SYG:SYD:P(A;;GR;;;SY)")), _ => writes++); }
            catch (InvalidOperationException) { refused = true; } Need(refused && writes == 1);
            var operation = new IOException("private-operation"); var cleanup = new IOException("private-cleanup"); int attempts = 0;
            try { Finish(operation, () => { attempts++; throw cleanup; }, () => attempts++); }
            catch (AggregateException error) { Need(error.InnerExceptions.Count == 2 && Object.ReferenceEquals(error.InnerExceptions[0], operation)); }
            Need(attempts == 2);
            for (int mode = 0; mode < 6; mode++) {
                int phase = 0, installs = 0, restores = 0; bool caught = false;
                try {
                    var values = Differential(() => {
                        int step = phase++;
                        if (mode == 1 && step == 1) throw operation;
                        if (mode == 2 && step == 2) return new [] { 0, 0 };
                        if (mode == 3 && step == 0) return new [] { 0, 0 };
                        if (mode == 4 && step == 1) return new [] { 1, 1 };
                        return step == 1 ? new [] { 0, 0 } : new [] { unchecked((int)0xC0000022), unchecked((int)0xC0000022) };
                    }, () => { }, () => { installs++; if (mode == 5) throw operation; }, () => restores++);
                    Need(values.Count == 3 && mode == 0);
                }
                catch (Exception) { caught = true; }
                Need(caught == (mode != 0) && restores == 1 && installs == (mode == 3 ? 0 : 1));
            }
            foreach (bool outer in new [] { false, true })
                foreach (bool clean in new [] { false, true })
                    foreach (int count in new [] { 0, 1 })
                        foreach (bool chosen in new [] { false, true })
                            Need(RecoveryAvailable(outer, clean, count, chosen) ==
                                (outer || clean && count == 0 && !chosen));
            Need(!RecoveryAvailable(false, false, 0, false));
            var encoded = new ScratchVolumePolicy {
                run = new string('a', 32), package = sid, root = @"E:\", disk = 2, partition = 1,
                imageIdentity = new FileIdentity { volume = 1, high = 2, low = 3 }, before = original, after = trial
            };
            foreach (bool supported in new [] { false, true }) {
                encoded.supported = supported; encoded.after = Trial(original, sid, supported);
                var modeAce = (CommonAce)Descriptor(encoded.after).DiscretionaryAcl[2];
                Need(modeAce.AccessMask == (supported ? 0x100020 : 0x20) && modeAce.AceFlags == AceFlags.None &&
                    modeAce.SecurityIdentifier.Value == sid);
                string receipt = encoded.Encode(); string[] fields = receipt.Split('\n');
                Need(fields.Length == 12 && fields[10] == Hash(String.Join("\n", fields.Take(10)) + "\n") &&
                    !receipt.Contains("private"));
                var decoded = new ScratchVolumePolicy { run = encoded.run };
                decoded.Decode(Utf8.GetBytes(receipt), sid);
                Need(Same(decoded.before, original) && Same(decoded.after, encoded.after) &&
                    decoded.supported == supported && decoded.disk == 2 && decoded.partition == 1);
                for (int mode = 0; mode < 4; mode++) {
                    var invalidFields = (string[])fields.Clone();
                    if (mode == 0) invalidFields[0] = "scratch-volume-v2";
                    if (mode == 1) invalidFields[0] = "scratch-volume-v1";
                    if (mode == 2) invalidFields[3] = supported ? "diagnostic" : "supported";
                    if (mode == 3) invalidFields[9] = Convert.ToBase64String(Trial(original, sid, !supported));
                    invalidFields[10] = Hash(String.Join("\n", invalidFields.Take(10)) + "\n");
                    refused = false;
                    try { new ScratchVolumePolicy { run = encoded.run }.Decode(Utf8.GetBytes(String.Join("\n", invalidFields)), sid); }
                    catch (InvalidOperationException) { refused = true; }
                    Need(refused);
                }
                foreach (string invalid in new [] { receipt + "extra", receipt.Replace("scratch-volume-v3", "foreign"),
                    receipt.Substring(0, receipt.Length - 2), receipt.Replace(fields[10], new string('0', 64)) }) {
                    refused = false;
                    try { decoded.Decode(Utf8.GetBytes(invalid), sid); } catch (InvalidOperationException) { refused = true; }
                    Need(refused);
                }
            }
        }
    }
}
