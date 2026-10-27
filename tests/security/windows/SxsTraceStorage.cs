using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;

namespace ScientificSecurity
{
    // One fixed synchronous creation; the protected policy is never repaired after creation.
    internal static class SxsTraceStorage
    {
        [StructLayout(LayoutKind.Sequential)] struct UnicodeString { internal ushort length, maximum; internal IntPtr buffer; }
        [StructLayout(LayoutKind.Sequential)] struct ObjectAttributes {
            internal uint length; internal IntPtr root, name; internal uint attributes; internal IntPtr descriptor, qos;
        }
        [StructLayout(LayoutKind.Explicit, Size = 16)] struct IoStatus {
            [FieldOffset(0)] internal int status;
            [FieldOffset(0)] internal IntPtr pointer;
            [FieldOffset(8)] internal UIntPtr information;
        }
        delegate int CreateCall(IntPtr handle, uint access, ref ObjectAttributes attributes, IntPtr io,
            IntPtr allocation, uint flags, uint sharing, uint disposition, uint options, IntPtr ea, uint eaLength);
        [DllImport("ntdll.dll")] static extern int NtCreateFile(IntPtr handle, uint access, ref ObjectAttributes attributes,
            IntPtr io, IntPtr allocation, uint flags, uint sharing, uint disposition, uint options, IntPtr ea, uint eaLength);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint QueryDosDeviceW(string device, [Out] char[] target, uint capacity);
        static readonly UnicodeEncoding Unicode = new UnicodeEncoding(false, false, true);
        static void Need(bool value) { SxsTraceSession.Need(value); }
        static string NativePath(string folder, Func<string, char[], uint> query)
        {
            Need(folder != null && folder.Length == 45 && folder[1] == ':' && folder[2] == '\\' &&
                folder[0] >= 'D' && folder[0] <= 'Z' && folder.Substring(3, 10) == "sxs-trace-" &&
                folder.Substring(13).All(c => c >= '0' && c <= '9' || c >= 'a' && c <= 'f'));
            var buffer = new char[512]; uint length = query(folder.Substring(0, 2), buffer);
            Need(length >= 3 && length <= buffer.Length && buffer[length - 1] == '\0' && buffer[length - 2] == '\0');
            int end = Array.IndexOf(buffer, '\0', 0, (int)length); Need(end == length - 2);
            string device = new string(buffer, 0, end), prefix = @"\Device\HarddiskVolume";
            Need(device.StartsWith(prefix, StringComparison.Ordinal) && device.Length > prefix.Length &&
                device.Length <= prefix.Length + 20 && device.Substring(prefix.Length).All(c => c >= '0' && c <= '9'));
            string path = device + "\\" + folder.Substring(3); Need(Unicode.GetByteCount(path) <= 512); return path;
        }
        static bool Valid(IntPtr handle) { return handle != IntPtr.Zero && handle != Native.InvalidHandle; }
        static void RequireResult(int returned, IoStatus completed, IntPtr handle)
        {
            if (returned != 0) throw new SxsTraceSession.PrivateFailure(
                new InvalidOperationException("fixed SxS native creation failed"),
                "storage-create ntstatus-" + unchecked((uint)returned).ToString("X8"));
            Need(completed.status == 0 && completed.information.ToUInt64() == 2 && Valid(handle));
        }
        static void Complete(int returned, Func<IoStatus> read, Func<IntPtr> handle, Action fatal, Action<Exception> finalize)
        {
            bool pending = returned == 0x103; Exception primary = null;
            try {
                IoStatus completed = default(IoStatus);
                if (!pending) { completed = read(); pending = completed.status == 0x103; }
                // Pending output storage can still be written. Only the independent outer process owner may recover it.
                if (pending) { fatal(); throw new InvalidOperationException("fixed SxS pending termination unexpectedly returned"); }
                RequireResult(returned, completed, handle());
            }
            catch (Exception error) { primary = error; throw; }
            finally { if (!pending) finalize(primary); }
        }
        static void Release(Exception primary, IntPtr handle, Action<IntPtr> close, params Action[] releases)
        {
            var failures = new List<Exception>();
            StartupActivationAccess.Attempt(failures, () => { if (Valid(handle)) close(handle); });
            foreach (Action release in releases) StartupActivationAccess.Attempt(failures, release);
            StartupActivationAccess.Finish(primary, failures);
        }
        internal static void Create(string folder, DirectorySecurity policy)
        {
            Need(IntPtr.Size == 8);
            CreateFixed(folder, policy.GetSecurityDescriptorBinaryForm(), (device, target) => {
                uint result = QueryDosDeviceW(device, target, (uint)target.Length);
                Native.Check(result != 0, "resolve fixed SxS volume device"); return result;
            }, NtCreateFile, handle => Native.Check(Native.CloseHandle(handle), "close fixed SxS creation handle"),
                () => Environment.FailFast("SxS synchronous creation remained pending; outer owner must recover."));
        }
        static void CreateFixed(string folder, byte[] descriptor, Func<string, char[], uint> query, CreateCall create,
            Action<IntPtr> close, Action fatal)
        {
            IntPtr memory = IntPtr.Zero; bool handed = false, attempted = false; Exception primary = null;
            try {
                Need(descriptor != null && descriptor.Length > 0 && descriptor.Length <= 65536);
                string path = NativePath(folder, query); byte[] name = Unicode.GetBytes(path);
                int descriptorOffset = (40 + name.Length + 2 + 7) & ~7, size = descriptorOffset + descriptor.Length;
                memory = Marshal.AllocHGlobal(size); Marshal.Copy(new byte[size], 0, memory, size);
                Marshal.WriteInt32(memory, 8, -1);
                Marshal.StructureToPtr(new UnicodeString { length = checked((ushort)name.Length),
                    maximum = checked((ushort)(name.Length + 2)), buffer = IntPtr.Add(memory, 40) }, IntPtr.Add(memory, 24), false);
                Marshal.Copy(name, 0, IntPtr.Add(memory, 40), name.Length);
                Marshal.Copy(descriptor, 0, IntPtr.Add(memory, descriptorOffset), descriptor.Length);
                var attributes = new ObjectAttributes { length = 48, name = IntPtr.Add(memory, 24),
                    attributes = 0x1040, descriptor = IntPtr.Add(memory, descriptorOffset) };
                attempted = true;
                int returned = create(memory, 0x120080, ref attributes, IntPtr.Add(memory, 8), IntPtr.Zero, 0x80, 0, 2, 0x21, IntPtr.Zero, 0);
                handed = true;
                Complete(returned, () => (IoStatus)Marshal.PtrToStructure(IntPtr.Add(memory, 8), typeof(IoStatus)),
                    () => Marshal.ReadIntPtr(memory), fatal,
                    error => Release(error, Marshal.ReadIntPtr(memory), close, () => Marshal.FreeHGlobal(memory),
                        () => Array.Clear(descriptor, 0, descriptor.Length)));
            }
            catch (Exception error) {
                primary = error;
                if (attempted && !handed && Marshal.ReadInt32(memory, 8) == 0x103) {
                    handed = true; fatal();
                    throw new InvalidOperationException("fixed SxS pending termination unexpectedly returned");
                }
                throw;
            }
            finally { if (!handed) Release(primary, attempted ? Marshal.ReadIntPtr(memory) : IntPtr.Zero, close,
                () => { if (memory != IntPtr.Zero) Marshal.FreeHGlobal(memory); },
                () => { if (descriptor != null) Array.Clear(descriptor, 0, descriptor.Length); }); }
        }
        static void Layout(Type type, int size, string[] fields, int[] offsets)
        {
            Need(Marshal.SizeOf(type) == size);
            for (int i = 0; i < fields.Length; i++) Need(Marshal.OffsetOf(type, fields[i]).ToInt32() == offsets[i]);
        }
        internal static void CheckValidation()
        {
            Need(IntPtr.Size == 8);
            Layout(typeof(UnicodeString), 16, new [] { "length", "maximum", "buffer" }, new [] { 0, 2, 8 });
            Layout(typeof(ObjectAttributes), 48, new [] { "length", "root", "name", "attributes", "descriptor", "qos" }, new [] { 0, 8, 16, 24, 32, 40 });
            Layout(typeof(IoStatus), 16, new [] { "status", "pointer", "information" }, new [] { 0, 0, 8 });
            const string folder = @"D:\sxs-trace-0123456789abcdef0123456789abcdef";
            Func<string, char[], uint> query = (drive, output) => {
                Need(drive == "D:" && output.Length == 512);
                string value = "\\Device\\HarddiskVolume12\0\0"; value.CopyTo(0, output, 0, value.Length); return (uint)value.Length;
            };
            Need(NativePath(folder, query) == @"\Device\HarddiskVolume12\sxs-trace-0123456789abcdef0123456789abcdef");
            foreach (string mapping in new [] { "", "\\Device\\HarddiskVolume12\0", "\\Device\\HarddiskVolume12\0prior\0\0",
                "\\Device\\HarddiskVolume\0\0", "\\Device\\HarddiskVolume1\\bad\0\0", "\\??\\D:\0\0", "\\device\\HarddiskVolume1\0\0",
                "\\Device\\HarddiskVolume123456789012345678901\0\0" }) {
                bool refused = false;
                try { NativePath(folder, (_, output) => { mapping.CopyTo(0, output, 0, mapping.Length); return (uint)mapping.Length; }); }
                catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            foreach (uint length in new uint[] { 0, 1, 513, UInt32.MaxValue }) {
                bool refused = false;
                try { NativePath(folder, (_, output) => length); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            foreach (string bad in new [] { folder.ToLowerInvariant(), folder + "\\extra", folder.Replace("sxs-trace", "other-dir"), folder.Replace('f', 'G') }) {
                int calls = 0; bool refused = false;
                try { NativePath(bad, (_, output) => { calls++; return 0; }); } catch (InvalidOperationException) { refused = true; }
                Need(refused && calls == 0);
            }
            RequireResult(0, new IoStatus { status = 0, information = new UIntPtr(2) }, new IntPtr(17));
            foreach (int status in new [] { 0x103, 0, unchecked((int)0xC0000035), unchecked((int)0x80000005) }) {
                bool fatal = false, finalized = false; int reads = 0; Exception caught = null;
                try { Complete(status, () => { reads++; return new IoStatus { status = status == 0 ? 0x103 : 0, information = new UIntPtr(2) }; },
                    () => new IntPtr(17), () => fatal = true, _ => finalized = true); } catch (Exception error) { caught = error; }
                Need(caught != null && fatal == (status == 0x103 || status == 0) && finalized == !fatal && reads == (status == 0x103 ? 0 : 1));
            }
            foreach (var result in new [] { Tuple.Create(0, 0, IntPtr.Zero, 2UL), Tuple.Create(0, 0, Native.InvalidHandle, 2UL),
                Tuple.Create(0, -1, new IntPtr(17), 2UL), Tuple.Create(0, 0, new IntPtr(17), 1UL) }) {
                bool refused = false;
                try { RequireResult(result.Item1, new IoStatus { status = result.Item2, information = new UIntPtr(result.Item4) }, result.Item3); }
                catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            byte[] descriptor = { 1, 2, 3, 4 }; int created = 0, closed = 0;
            CreateCall call = (IntPtr handle, uint access, ref ObjectAttributes attributes, IntPtr io, IntPtr allocation,
                uint flags, uint share, uint disposition, uint options, IntPtr ea, uint eaLength) => {
                created++; Need(access == 0x120080 && attributes.length == 48 && attributes.root == IntPtr.Zero &&
                    attributes.attributes == 0x1040 && attributes.qos == IntPtr.Zero && allocation == IntPtr.Zero && flags == 0x80 &&
                    share == 0 && disposition == 2 && options == 0x21 && ea == IntPtr.Zero && eaLength == 0);
                Need(Marshal.ReadIntPtr(handle) == IntPtr.Zero && Marshal.ReadInt32(io) == -1 && Marshal.ReadIntPtr(io, 8) == IntPtr.Zero);
                var text = (UnicodeString)Marshal.PtrToStructure(attributes.name, typeof(UnicodeString));
                Need(text.length == 134 && text.maximum == 136 && Marshal.ReadInt16(text.buffer, text.length) == 0 &&
                    Marshal.PtrToStringUni(text.buffer, text.length / 2) == @"\Device\HarddiskVolume12\sxs-trace-0123456789abcdef0123456789abcdef");
                byte[] actual = new byte[4]; Marshal.Copy(attributes.descriptor, actual, 0, 4); Need(actual.SequenceEqual(descriptor));
                Marshal.WriteIntPtr(handle, new IntPtr(17)); Marshal.WriteInt64(io, unchecked((long)0xF123456700000000));
                Marshal.WriteInt64(io, 8, 2); return 0;
            };
            CreateFixed(folder, descriptor, query, call, handle => { Need(handle == new IntPtr(17)); closed++; }, () => { throw new Exception("unexpected pending"); });
            Need(created == 1 && closed == 1);
            var original = new InvalidOperationException("private-operation-sentinel"); var cleanup = new InvalidOperationException("private-close-sentinel");
            string order = ""; AggregateException aggregate = null;
            try { Release(original, new IntPtr(17), _ => { order += "c"; throw cleanup; },
                () => { order += "a"; throw cleanup; }, () => order += "b"); }
            catch (AggregateException error) { aggregate = error; }
            Need(order == "cab" && aggregate != null && aggregate.InnerExceptions.Count == 3 &&
                Object.ReferenceEquals(aggregate.InnerExceptions[0], original) && Object.ReferenceEquals(aggregate.InnerExceptions[1], cleanup));
        }
    }
}
