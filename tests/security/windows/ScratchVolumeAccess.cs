using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace ScientificSecurity
{
    // Handle-only evidence; no data/control operations or production admission.
    public static class ScratchVolumeAccess
    {
        internal static readonly uint[] Masks = { 0, 0x20, 0x100000, 0x100020, 1, 2, 0x20000, 0x40000, 0x80000 };
        [DllImport("ntdll.dll")] static extern int NtQueryObject(IntPtr handle, int kind, IntPtr memory, uint capacity, out uint returned);
        static void Need(bool value)
        { if (!value) throw new InvalidOperationException("fixed scratch volume handle evidence is unqualified"); }
        static string Bare(string root)
        {
            const string prefix = @"\Device\HarddiskVolume";
            Need(root != null && root.StartsWith(prefix, StringComparison.Ordinal) && root.EndsWith("\\", StringComparison.Ordinal));
            string suffix = root.Substring(prefix.Length, root.Length - prefix.Length - 1);
            Need(suffix.Length > 0 && suffix.Length <= 20);
            foreach (char c in suffix) Need(c >= '0' && c <= '9');
            return root.Substring(0, root.Length - 1);
        }
        internal static ScratchAccess.NativeRequest[] Requests(string root)
        {
            string path = Bare(root); var requests = new ScratchAccess.NativeRequest[Masks.Length];
            for (int i = 0; i < Masks.Length; i++) {
                uint mask = Masks[i];
                requests[i] = new ScratchAccess.NativeRequest { path = path, role = "lpac", name = "volume",
                    target = "volume", requested = mask, options = 0x200000 };
            }
            return requests;
        }
        static uint Granted(IntPtr memory, uint returned)
        {
            Need(returned == 56 && Marshal.ReadInt32(memory) == 0);
            return unchecked((uint)Marshal.ReadInt32(memory, 4));
        }
        static string Name(IntPtr memory, uint returned)
        {
            Need(returned >= 16 && returned <= 1024);
            uint length = unchecked((ushort)Marshal.ReadInt16(memory));
            uint maximum = unchecked((ushort)Marshal.ReadInt16(memory, 2));
            IntPtr text = Marshal.ReadIntPtr(memory, 8);
            ulong start = unchecked((ulong)memory.ToInt64()), pointer = unchecked((ulong)text.ToInt64());
            Need(length > 0 && length <= 256 && length % 2 == 0 && maximum >= length && maximum % 2 == 0 &&
                pointer >= start + 16 && pointer - start <= returned && maximum <= returned - (pointer - start));
            return Marshal.PtrToStringUni(text, (int)length / 2);
        }
        static T Query<T>(IntPtr handle, int kind, Func<IntPtr, uint, T> parse)
        {
            IntPtr memory = Marshal.AllocHGlobal(1024); bool pending = false;
            try {
                uint returned; int status = NtQueryObject(handle, kind, memory, 1024, out returned);
                pending = status == 0x103;
                if (pending) Environment.FailFast("Scratch volume metadata remained pending; outer owner must recover.");
                Need(status == 0 && returned <= 1024); return parse(memory, returned);
            }
            finally { if (!pending) Marshal.FreeHGlobal(memory); }
        }
        internal static void Open(ScratchAccess.NativeRequest[] requests, Action qualify)
        { foreach (var request in requests) { qualify(); request.Open(); } }
        static void Close(IntPtr handle)
        { Native.Check(Native.CloseHandle(handle), "close scratch volume probe handle"); }
        internal static int[] Qualify(ScratchAccess.NativeRequest[] requests, string root, bool host, Action deadline)
        {
            return Qualify(requests, root, host, (handle, desired) => {
                deadline(); uint granted = Query(handle, 0, Granted);
                deadline(); Need(granted == desired && Query(handle, 1, Name) == Bare(root)); deadline(); return granted;
            }, Close);
        }
        static int[] Qualify(ScratchAccess.NativeRequest[] requests, string root, bool host,
            Func<IntPtr, uint, uint> inspect, Action<IntPtr> close)
        {
            Need(requests.Length == Masks.Length); string path = Bare(root);
            var result = new int[Masks.Length * 2]; Exception primary = null; var failures = new List<Exception>();
            try {
                for (int i = 0; i < requests.Length; i++) {
                    var request = requests[i]; Need(request.path == path && request.requested == Masks[i] && !request.pending &&
                        request.memory != IntPtr.Zero && request.opened == (request.returned == 0));
                    Need(request.returned == 0 || !host && request.returned == unchecked((int)0xC0000022));
                    result[i] = request.returned;
                    if (request.opened) {
                        uint granted = inspect(Marshal.ReadIntPtr(request.memory), request.requested);
                        Need(granted == request.requested); result[Masks.Length + i] = unchecked((int)granted);
                    }
                }
            }
            catch (Exception error) { primary = error; }
            finally { Release(requests, failures, close); }
            ScratchAccess.Finish(primary, failures); return result;
        }
        internal static void Release(ScratchAccess.NativeRequest[] requests, List<Exception> failures)
        { Release(requests, failures, Close); }
        static void Release(ScratchAccess.NativeRequest[] requests, List<Exception> failures, Action<IntPtr> close)
        {
            foreach (var request in requests) ScratchAccess.Attempt(failures, () => request.Release(_ => { }, close));
        }
        internal static void Host(string root, Action deadline)
        {
            var requests = Requests(root); Exception primary = null; var failures = new List<Exception>();
            try { Open(requests, deadline); Qualify(requests, root, true, deadline); }
            catch (Exception error) { primary = error; }
            finally { Release(requests, failures); }
            ScratchAccess.Finish(primary, failures);
        }
        internal static int[] Combine(int root, int temp, int[] volume)
        {
            Need(volume != null && volume.Length == Masks.Length * 2);
            var result = new int[2 + volume.Length]; result[0] = root; result[1] = temp;
            Array.Copy(volume, 0, result, 2, volume.Length); return result;
        }
        internal static List<string> Frames(string phase, int[] result)
        {
            Need(result.Length == 2 + Masks.Length * 2); var frames = new List<string>();
            for (int i = 0; i < Masks.Length; i++) frames.Add(Frame(phase, i, result[2 + i], result[2 + Masks.Length + i]));
            return frames;
        }
        internal static string Frame(string phase, int index, int status, int granted)
        {
            Need((phase == "baseline" || phase == "modified" || phase == "restored") && index >= 0 && index < Masks.Length &&
                (status == 0 || status == unchecked((int)0xC0000022)) && (status == 0 ? unchecked((uint)granted) == Masks[index] : granted == 0));
            return "WINDOWS_SCRATCH_VOLUME phase=" + phase + " desired=0x" + Masks[index].ToString("X8") +
                " ntstatus=0x" + unchecked((uint)status).ToString("X8") + " granted=0x" + unchecked((uint)granted).ToString("X8") +
                " metadata_qualified=True descriptor_restored=True handles_closed=True authority_qualified=False admission=False";
        }
        public static void CheckValidation()
        {
            const string root = "\\Device\\HarddiskVolume12\\";
            var requests = Requests(root); Need(requests.Length == 9);
            for (int i = 0; i < requests.Length; i++) {
                var request = requests[i]; Need(request.path == root.TrimEnd('\\') && request.requested == Masks[i] && request.options == 0x200000);
                int calls = 0;
                try {
                    request.Open((IntPtr slot, uint access, ref ScratchAccess.ObjectAttributes attributes, IntPtr io, uint share, uint options) => {
                        calls++; Need(access == Masks[i] && share == 7 && options == 0x200000 && attributes.root == IntPtr.Zero);
                        Marshal.WriteInt32(io, unchecked((int)0xC0000022)); return unchecked((int)0xC0000022);
                    }, () => { throw new InvalidOperationException("unexpected pending fixture"); });
                    Need(calls == 1 && !request.opened);
                }
                finally { request.Release(_ => { throw new InvalidOperationException("unexpected bind fixture"); }, _ => { throw new InvalidOperationException("unexpected close fixture"); }); }
                string frame = Frame("modified", i, unchecked((int)0xC0000022), 0);
                Need(frame.Length < 384 && !frame.Contains("Harddisk") && frame.Contains("authority_qualified=False"));
            }
            for (int mode = 0; mode < 4; mode++) {
                var probes = Requests(root); int closes = 0; Exception caught = null;
                var operation = new InvalidOperationException("fixed metadata fixture");
                var cleanup = new InvalidOperationException("fixed close fixture");
                foreach (var probe in probes) {
                    probe.memory = Marshal.AllocHGlobal(8); Marshal.WriteIntPtr(probe.memory, new IntPtr(17));
                    probe.returned = 0; probe.opened = true;
                }
                try {
                    int[] result = Qualify(probes, root, true, (handle, desired) => {
                        Need(handle == new IntPtr(17));
                        if (mode == 1 || mode == 3) throw operation;
                        return desired;
                    }, _ => { closes++; if (mode == 2 || mode == 3) throw cleanup; });
                    Need(mode == 0 && Frames("modified", Combine(0, 0, result)).Count == 9);
                }
                catch (Exception error) { caught = error; }
                Need(closes == 9 && (mode == 0 ? caught == null : caught != null));
                foreach (var probe in probes) Need(probe.memory == IntPtr.Zero);
                if (mode == 1) Need(Object.ReferenceEquals(caught, operation));
                if (mode == 3) Need(caught is AggregateException &&
                    Object.ReferenceEquals(((AggregateException)caught).InnerExceptions[0], operation));
            }
            IntPtr memory = Marshal.AllocHGlobal(1024);
            try {
                Marshal.Copy(new byte[1024], 0, memory, 1024); Marshal.WriteInt32(memory, 4, 0x100020);
                Need(Granted(memory, 56) == 0x100020);
                string name = root.TrimEnd('\\'); byte[] bytes = System.Text.Encoding.Unicode.GetBytes(name);
                Marshal.Copy(bytes, 0, IntPtr.Add(memory, 16), bytes.Length);
                Marshal.WriteInt16(memory, (short)bytes.Length); Marshal.WriteInt16(memory, 2, (short)bytes.Length);
                Marshal.WriteIntPtr(memory, 8, IntPtr.Add(memory, 16)); Need(Name(memory, (uint)(16 + bytes.Length)) == name);
                foreach (Action invalid in new Action[] { () => Granted(memory, 55), () => Name(memory, 15),
                    () => { Marshal.WriteIntPtr(memory, 8, IntPtr.Add(memory, 1023)); Name(memory, 1024); },
                    () => Requests(root + "temp"), () => Frame("other", 0, 0, 0), () => Frame("baseline", 1, 0, 0) }) {
                    bool refused = false; try { invalid(); } catch (InvalidOperationException) { refused = true; } Need(refused);
                }
            }
            finally { Marshal.FreeHGlobal(memory); }
        }
    }
}
