using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace ScientificSecurity
{
    internal static class RegistryAuthoritySurface
    {
        const string KeyName = @"\Registry\MACHINE\Software\Microsoft\Windows\CurrentVersion\SideBySide";
        [StructLayout(LayoutKind.Sequential)] struct Name { internal ushort length, maximum; internal IntPtr buffer; }
        [StructLayout(LayoutKind.Sequential)] struct Attributes { internal uint length; internal IntPtr root, name; internal uint flags; internal IntPtr descriptor, qos; }
        [DllImport("ntdll.dll")] static extern int NtOpenKeyEx(out IntPtr key, uint access, ref Attributes attributes, uint options);
        [DllImport("ntdll.dll")] static extern int NtClose(IntPtr key);
        [DllImport("ntdll.dll")] static extern int NtQueryKey(IntPtr key, int kind, byte[] data, uint capacity, out uint returned);
        [DllImport("ntdll.dll")] static extern int NtQueryObject(IntPtr key, int kind, byte[] data, uint capacity, out uint returned);
        [DllImport("ntdll.dll")] static extern int NtQuerySecurityObject(IntPtr key, uint info, byte[] data, uint capacity, out uint returned);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegEnumKeyExW(IntPtr key, uint index, StringBuilder name, ref uint length, IntPtr reserved, IntPtr klass, IntPtr klassLength, IntPtr time);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegEnumValueW(IntPtr key, uint index, StringBuilder name, ref uint length, IntPtr reserved, out uint type, byte[] data, ref uint bytes);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegQueryInfoKeyW(IntPtr key, IntPtr klass, IntPtr klassLength, IntPtr reserved,
            out uint subkeys, IntPtr maxSubkey, IntPtr maxClass, out uint values, IntPtr maxName, IntPtr maxValue, IntPtr security, out long modified);
        static void Need(bool value) { RegistryAuthorityComparison.Need(value); }
        static void Deadline(Stopwatch clock) { if (clock.Elapsed.TotalSeconds > 10) throw new TimeoutException("fixed registry surface exceeded 10 seconds"); }
        static void Finish(Exception primary, params Action[] actions)
        {
            var errors = new List<Exception>();
            foreach (var action in actions) try { action(); } catch (Exception failure) { errors.Add(failure); }
            if (errors.Count != 0) { if (primary != null) errors.Insert(0, primary); throw new AggregateException("registry surface operation/cleanup failed", errors); }
        }
        sealed class PrivateFailure : Exception
        {
            internal readonly Exception Original;
            internal PrivateFailure(Exception original, string category) : base("fixed registry surface failed phase=inventory category=" + category + " raw_error_withheld=True")
            { Original = original; }
        }
        static Exception Sanitize(Exception failure)
        {
            var group = failure as AggregateException;
            if (group != null) return new AggregateException("fixed registry surface operation/cleanup failed",
                group.InnerExceptions.Select(Sanitize));
            if (failure is PrivateFailure) return failure;
            string category = failure is DecoderFallbackException ? "decode" : failure is EncoderFallbackException ? "encode" :
                failure is TimeoutException ? "timeout" : failure is InvalidOperationException ? "control" : "other";
            return new PrivateFailure(failure, category);
        }
        static T Private<T>(Func<T> operation)
        { try { return operation(); } catch (Exception failure) { throw Sanitize(failure); } }
        static IntPtr Open()
        {
            Need(IntPtr.Size == 8 && Marshal.SizeOf(typeof(Name)) == 16 && Marshal.SizeOf(typeof(Attributes)) == 48);
            IntPtr text = IntPtr.Zero, name = IntPtr.Zero, key = IntPtr.Zero; Exception failure = null;
            try {
                text = Marshal.StringToHGlobalUni(KeyName); name = Marshal.AllocHGlobal(16);
                Marshal.StructureToPtr(new Name { length = 140, maximum = 142, buffer = text }, name, false);
                var attributes = new Attributes { length = 48, name = name, flags = 0x1040 };
                Need(NtOpenKeyEx(out key, 0x20019, ref attributes, 0) == 0 && Valid(key));
                byte[] basic = new byte[56], identity = new byte[4096]; uint returned;
                Need(NtQueryObject(key, 0, basic, 56, out returned) == 0 && returned == 56 && BitConverter.ToUInt32(basic, 0) == 0 && BitConverter.ToUInt32(basic, 4) == 0x20019);
                Need(NtQueryKey(key, 3, identity, 4096, out returned) == 0 && returned >= 144 && returned <= 4096 && BitConverter.ToUInt32(identity, 0) == 140);
                Need(new UnicodeEncoding(false, false, true).GetString(identity, 4, 140).Equals(KeyName, StringComparison.OrdinalIgnoreCase));
            }
            catch (Exception error) { failure = error; }
            try { Finish(failure,
                () => { if (name != IntPtr.Zero) Marshal.FreeHGlobal(name); },
                () => { if (text != IntPtr.Zero) Marshal.FreeHGlobal(text); }); }
            catch (Exception error) { failure = error; }
            if (failure != null) {
                Finish(failure, () => { if (Valid(key)) Need(NtClose(key) == 0); });
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
            }
            return key;
        }
        static bool Valid(IntPtr key) { return key.ToInt64() > 0 && !(key.ToInt64() >= 0x80000000 && key.ToInt64() <= 0x800000FF); }
        static void Value(uint type, byte[] data, uint bytes)
        {
            Need(bytes <= 4096 && new uint[] { 0, 1, 2, 3, 4, 5, 7, 11 }.Contains(type));
            if (type == 4 || type == 5) Need(bytes == 4);
            if (type == 11) Need(bytes == 8);
            if (type == 1 || type == 2 || type == 7) {
                Need(bytes >= (type == 7 ? 4 : 2) && bytes % 2 == 0);
                string text = new UnicodeEncoding(false, false, true).GetString(data, 0, (int)bytes);
                Need(text.EndsWith(type == 7 ? "\0\0" : "\0", StringComparison.Ordinal));
            }
        }
        internal sealed class Snapshot
        {
            internal byte[] digest;
            internal int values, subkeys;
            internal uint types;
            internal void RequireEqual(Snapshot other)
            { Need(other != null && values == other.values && subkeys == other.subkeys && types == other.types && digest.SequenceEqual(other.digest)); }
        }
        internal static Snapshot Read() { return Private(ReadCore); }
        static Snapshot ReadCore()
        {
            var clock = Stopwatch.StartNew(); IntPtr key = Open(); Exception primary = null;
            var fields = new List<string>();
            try {
                uint expectedKeys, expectedValues; long modified;
                Need(RegQueryInfoKeyW(key, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out expectedKeys, IntPtr.Zero, IntPtr.Zero,
                    out expectedValues, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out modified) == 0 && expectedKeys <= 256 && expectedValues <= 32);
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase); var result = new Snapshot(); int total = 0;
                for (uint index = 0; index <= 32; index++) {
                    Deadline(clock); var name = new StringBuilder(512); uint length = 512, bytes = 4096, type;
                    byte[] data = new byte[4096];
                    try {
                        int status = RegEnumValueW(key, index, name, ref length, IntPtr.Zero, out type, data, ref bytes);
                        if (status == 259) { Need(index == expectedValues); break; }
                        Need(status == 0 && index < 32 && length < 512 && length == name.Length && names.Add(name.ToString())); Value(type, data, bytes);
                        total = checked(total + (int)bytes); Need(total <= 32768);
                        fields.Add("v:" + Convert.ToBase64String(new UnicodeEncoding(false, false, true).GetBytes(name.ToString())) + ":" + type + ":" + Convert.ToBase64String(data, 0, (int)bytes));
                        result.values++; result.types |= 1U << (int)type;
                    } finally { Array.Clear(data, 0, data.Length); }
                }
                names.Clear();
                for (uint index = 0; index <= 256; index++) {
                    Deadline(clock); var name = new StringBuilder(512); uint length = 512;
                    int status = RegEnumKeyExW(key, index, name, ref length, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                    if (status == 259) { Need(index == expectedKeys); break; }
                    Need(status == 0 && index < 256 && length > 0 && length < 512 && length == name.Length && names.Add(name.ToString()));
                    fields.Add("k:" + Convert.ToBase64String(new UnicodeEncoding(false, false, true).GetBytes(name.ToString()))); result.subkeys++;
                }
                uint finalKeys, finalValues; long finalModified;
                Need(RegQueryInfoKeyW(key, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out finalKeys, IntPtr.Zero, IntPtr.Zero,
                    out finalValues, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out finalModified) == 0 && finalKeys == expectedKeys && finalValues == expectedValues && finalModified == modified);
                byte[] descriptor = new byte[65536]; uint returned;
                try {
                    Need(NtQuerySecurityObject(key, 0x17, descriptor, 65536, out returned) == 0 && returned >= 20 && returned <= 65536);
                    fields.Add("sd:" + Convert.ToBase64String(descriptor, 0, (int)returned)); fields.Sort(StringComparer.Ordinal);
                    byte[] bytes = Encoding.UTF8.GetBytes(String.Join("\n", fields));
                    try { using (var hash = SHA256.Create()) result.digest = hash.ComputeHash(bytes); }
                    finally { Array.Clear(bytes, 0, bytes.Length); }
                } finally { Array.Clear(descriptor, 0, descriptor.Length); }
                Deadline(clock); return result;
            }
            catch (Exception failure) { primary = failure; throw; }
            finally { fields.Clear(); Finish(primary, () => Need(NtClose(key) == 0)); }
        }
        internal static void CheckPrivacyValidation()
        {
            foreach (bool name in new [] { false, true }) {
                Exception raw = null, caught = null;
                var close = new InvalidOperationException("private-close-sentinel");
                try {
                    Private<int>(() => {
                        try {
                            if (name) new UnicodeEncoding(false, false, true).GetBytes("private-name-sentinel\uD800");
                            else Value(1, new byte[] { 0x37, 0xD8, 0, 0 }, 4);
                            throw new InvalidOperationException("malformed fixture was accepted");
                        }
                        catch (Exception failure) { raw = failure; throw; }
                        finally { Finish(raw, () => { throw close; }); }
                    });
                } catch (Exception failure) { caught = failure; }
                var group = caught as AggregateException;
                Need(group != null && group.InnerExceptions.Count == 2);
                var first = group.InnerExceptions[0] as PrivateFailure; var last = group.InnerExceptions[1] as PrivateFailure;
                Need(first != null && last != null && Object.ReferenceEquals(first.Original, raw) && Object.ReferenceEquals(last.Original, close));
                Need(first.InnerException == null && last.InnerException == null && first.Message.Contains(name ? "category=encode" : "category=decode"));
                string report = caught.ToString();
                Need(!report.Contains("sentinel") && !report.Contains("[D8]") && !report.Contains("[37]") && !report.Contains("\\u"));
            }
        }
        internal static void CheckValidation()
        {
            CheckPrivacyValidation();
            foreach (uint type in new uint[] { 0, 3, 4, 5, 11 }) Value(type, new byte[8], type == 11 ? 8U : 4U);
            Value(1, new byte[] { 65, 0, 0, 0 }, 4);
            foreach (var item in new [] { Tuple.Create(6U, 4U), Tuple.Create(4U, 8U), Tuple.Create(11U, 4U), Tuple.Create(1U, 1U), Tuple.Create(7U, 2U) }) {
                bool refused = false; try { Value(item.Item1, new byte[8], item.Item2); } catch (InvalidOperationException) { refused = true; } Need(refused);
            }
            var original = new Snapshot { digest = new byte[] { 1, 2 }, values = 1, subkeys = 2, types = 8 };
            original.RequireEqual(new Snapshot { digest = new byte[] { 1, 2 }, values = 1, subkeys = 2, types = 8 });
            for (int mode = 0; mode < 4; mode++) {
                bool refused = false;
                try { original.RequireEqual(new Snapshot { digest = mode == 0 ? new byte[] { 2, 1 } : original.digest, values = mode == 1 ? 2 : 1, subkeys = mode == 2 ? 3 : 2, types = mode == 3 ? 9U : 8U }); }
                catch (InvalidOperationException) { refused = true; } Need(refused);
            }
        }
    }
}
