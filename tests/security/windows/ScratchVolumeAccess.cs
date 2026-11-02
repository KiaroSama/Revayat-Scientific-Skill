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
        sealed class Evidence
        {
            internal readonly ScratchAccess.NativeRequest request;
            internal readonly bool host;
            // 1=request, 2=status, 3/4=basic query/shape, 5=grant, 6/7=name query/shape, 8=name equality.
            internal int stage = 1, queryKind = -1, queryStatus, nameEqual = -1;
            internal uint returned, attributes, granted;
            internal bool queried, basicKnown;
            internal string census;
            internal Evidence(ScratchAccess.NativeRequest request, bool host) { this.request = request; this.host = host; }
            internal string Message()
            {
                return "fixed scratch volume handle evidence is unqualified stage=" + stage + " host=" + host +
                    " desired=0x" + request.requested.ToString("X8") +
                    " ntstatus=0x" + unchecked((uint)request.returned).ToString("X8") +
                    " io_status=0x" + unchecked((uint)request.ioStatus).ToString("X8") +
                    " information=0x" + request.information.ToString("X16") +
                    " query_kind=" + queryKind + " queried=" + queried +
                    " query_status=0x" + unchecked((uint)queryStatus).ToString("X8") + " returned=" + returned +
                    " basic_known=" + basicKnown + " attributes=0x" + attributes.ToString("X8") +
                    " granted=0x" + granted.ToString("X8") + " name_equal=" + nameEqual +
                    (census == null ? "" : " open_statuses=" + census);
            }
        }
        static void Need(bool value, Evidence evidence = null)
        { if (!value) throw new InvalidOperationException(evidence == null ? "fixed scratch volume handle evidence is unqualified" : evidence.Message()); }
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
        static uint Granted(IntPtr memory, uint returned, Evidence evidence = null)
        {
            Need(returned == 56, evidence);
            uint attributes = unchecked((uint)Marshal.ReadInt32(memory));
            uint granted = unchecked((uint)Marshal.ReadInt32(memory, 4));
            if (evidence != null) { evidence.basicKnown = true; evidence.attributes = attributes; evidence.granted = granted; }
            Need(attributes == 0, evidence); return granted;
        }
        static string Name(IntPtr memory, uint returned, Evidence evidence = null)
        {
            Need(returned >= 16 && returned <= 1024, evidence);
            uint length = unchecked((ushort)Marshal.ReadInt16(memory));
            uint maximum = unchecked((ushort)Marshal.ReadInt16(memory, 2));
            IntPtr text = Marshal.ReadIntPtr(memory, 8);
            ulong start = unchecked((ulong)memory.ToInt64()), pointer = unchecked((ulong)text.ToInt64());
            Need(length > 0 && length <= 256 && length % 2 == 0 && maximum >= length && maximum % 2 == 0 &&
                pointer >= start + 16 && pointer - start <= returned && maximum <= returned - (pointer - start), evidence);
            return Marshal.PtrToStringUni(text, (int)length / 2);
        }
        delegate int QueryCall(IntPtr handle, int kind, IntPtr memory, uint capacity, out uint returned);
        static T Query<T>(IntPtr handle, int kind, Func<IntPtr, uint, T> parse, Evidence evidence, QueryCall call)
        {
            IntPtr memory = Marshal.AllocHGlobal(1024); bool pending = false;
            try {
                evidence.stage = kind == 0 ? 3 : 6; evidence.queryKind = kind; evidence.queried = false;
                uint returned; int status = call(handle, kind, memory, 1024, out returned);
                pending = status == 0x103;
                if (pending) Environment.FailFast("Scratch volume metadata remained pending; outer owner must recover.");
                evidence.queried = true; evidence.queryStatus = status; evidence.returned = returned;
                Need(status == 0 && returned <= 1024, evidence);
                evidence.stage = kind == 0 ? 4 : 7; return parse(memory, returned);
            }
            finally { if (!pending) Marshal.FreeHGlobal(memory); }
        }
        static bool StatusAllowed(uint mask, bool host, int status)
        {
            // Native zero access is unsupported; its measured denial earns no authority credit.
            return mask == 0 ? status == unchecked((int)0xC0000022) :
                status == 0 || !host && status == unchecked((int)0xC0000022);
        }
        static string Census(ScratchAccess.NativeRequest[] requests)
        {
            var values = new string[requests.Length];
            for (int i = 0; i < requests.Length; i++) {
                var request = requests[i];
                values[i] = request.memory != IntPtr.Zero && !request.pending &&
                    request.opened == (request.returned == 0) &&
                    (request.returned == 0 || request.returned == unchecked((int)0xC0000022)) ?
                    unchecked((uint)request.returned).ToString("X8") : "unknown";
            }
            return String.Join(",", values);
        }
        internal static void Open(ScratchAccess.NativeRequest[] requests, Action qualify)
        { foreach (var request in requests) { qualify(); request.Open(); } }
        static void Close(IntPtr handle)
        { Native.Check(Native.CloseHandle(handle), "close scratch volume probe handle"); }
        static uint Inspect(IntPtr handle, uint desired, string root, Action deadline, Evidence evidence, QueryCall call)
        {
            deadline(); uint granted = Query(handle, 0, (memory, length) => Granted(memory, length, evidence), evidence, call);
            deadline(); evidence.stage = 5; Need(granted == desired, evidence);
            string name = Query(handle, 1, (memory, length) => Name(memory, length, evidence), evidence, call);
            evidence.stage = 8; evidence.nameEqual = name == Bare(root) ? 1 : 0;
            Need(evidence.nameEqual == 1, evidence); deadline(); return granted;
        }
        internal static int[] Qualify(ScratchAccess.NativeRequest[] requests, string root, bool host, Action deadline)
        {
            return Qualify(requests, root, host, (handle, desired, evidence) =>
                Inspect(handle, desired, root, deadline, evidence, NtQueryObject), Close);
        }
        static int[] Qualify(ScratchAccess.NativeRequest[] requests, string root, bool host,
            Func<IntPtr, uint, Evidence, uint> inspect, Action<IntPtr> close)
        {
            Need(requests.Length == Masks.Length); string path = Bare(root);
            var result = new int[Masks.Length * 5]; Exception primary = null; var failures = new List<Exception>();
            try {
                for (int i = 0; i < requests.Length; i++) {
                    var request = requests[i]; var evidence = new Evidence(request, host) { census = Census(requests) };
                    Need(request.path == path && request.requested == Masks[i] && !request.pending &&
                        request.memory != IntPtr.Zero && request.opened == (request.returned == 0), evidence);
                    evidence.stage = 2;
                    Need(StatusAllowed(request.requested, host, request.returned), evidence);
                    result[i] = request.returned;
                    result[Masks.Length * 2 + i] = request.ioStatus;
                    result[Masks.Length * 3 + i] = unchecked((int)request.information);
                    result[Masks.Length * 4 + i] = unchecked((int)(request.information >> 32));
                    if (request.opened) {
                        uint granted = inspect(Marshal.ReadIntPtr(request.memory), request.requested, evidence);
                        evidence.stage = 5; evidence.granted = granted;
                        Need(granted == request.requested, evidence); result[Masks.Length + i] = unchecked((int)granted);
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
            Need(volume != null && volume.Length == Masks.Length * 5);
            var result = new int[2 + volume.Length]; result[0] = root; result[1] = temp;
            Array.Copy(volume, 0, result, 2, volume.Length); return result;
        }
        internal static List<string> Frames(string phase, int[] result)
        {
            Need(result.Length == 2 + Masks.Length * 5); var frames = new List<string>();
            for (int i = 0; i < Masks.Length; i++) {
                ulong information = unchecked((uint)result[2 + Masks.Length * 3 + i]) |
                    ((ulong)unchecked((uint)result[2 + Masks.Length * 4 + i]) << 32);
                frames.Add(Frame(phase, i, result[2 + i], result[2 + Masks.Length + i]) +
                    " io_status=0x" + unchecked((uint)result[2 + Masks.Length * 2 + i]).ToString("X8") +
                    " information=0x" + information.ToString("X16"));
            }
            return frames;
        }
        internal static string Frame(string phase, int index, int status, int granted)
        {
            Need((phase == "baseline" || phase == "modified" || phase == "restored") && index >= 0 && index < Masks.Length &&
                StatusAllowed(Masks[index], false, status) && (status == 0 ? unchecked((uint)granted) == Masks[index] : granted == 0));
            return "WINDOWS_SCRATCH_VOLUME phase=" + phase + " desired=0x" + Masks[index].ToString("X8") +
                " ntstatus=0x" + unchecked((uint)status).ToString("X8") + " granted=0x" + unchecked((uint)granted).ToString("X8") +
                " native_request_supported=" + (Masks[index] != 0) + " metadata_qualified=" + (Masks[index] != 0) +
                " descriptor_restored=True handles_closed=True authority_qualified=False admission=False";
        }
        public static void CheckValidation()
        {
            const string root = "\\Device\\HarddiskVolume12\\";
            foreach (uint mask in Masks) foreach (bool host in new [] { false, true })
                foreach (int status in new [] { 0, unchecked((int)0xC0000022), unchecked((int)0xC000000D), 0x103 }) {
                    bool expected = mask == 0 ? status == unchecked((int)0xC0000022) :
                        status == 0 || !host && status == unchecked((int)0xC0000022);
                    Need(StatusAllowed(mask, host, status) == expected);
                }
            Need(Frame("baseline", 0, unchecked((int)0xC0000022), 0).Contains(
                "native_request_supported=False metadata_qualified=False"));
            foreach (bool host in new [] { false, true }) {
                var probes = Requests(root); int closes = 0, inspections = 0; Exception caught = null;
                foreach (var probe in probes) {
                    probe.memory = Marshal.AllocHGlobal(8); Marshal.WriteIntPtr(probe.memory, new IntPtr(17)); probe.opened = true;
                }
                try { Qualify(probes, root, host, (handle, desired, context) => { inspections++; return desired; }, _ => closes++); }
                catch (InvalidOperationException error) { caught = error; }
                Need(caught != null && caught.Message.Contains("stage=2") && inspections == 0 && closes == 9);
                foreach (var probe in probes) Need(probe.memory == IntPtr.Zero);
                Need(Census(probes) == String.Join(",", new string[] {
                    "unknown", "unknown", "unknown", "unknown", "unknown", "unknown", "unknown", "unknown", "unknown" }));
            }
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
            foreach (bool device in new [] { false, true })
                foreach (ulong information in new ulong[] { 0, 1, 2, UInt64.MaxValue }) {
                    var probe = new ScratchAccess.NativeRequest { path = device ? root.TrimEnd('\\') : root,
                        target = device ? "volume" : "root", options = device ? 0x200000U : 0x200021U };
                    bool refused = false; int closes = 0;
                    try {
                        probe.Open((IntPtr slot, uint access, ref ScratchAccess.ObjectAttributes attributes, IntPtr io, uint share, uint options) => {
                            Marshal.WriteIntPtr(slot, new IntPtr(17)); Marshal.WriteInt32(io, 0);
                            Marshal.WriteInt64(io, 8, unchecked((long)information)); return 0;
                        }, () => { throw new InvalidOperationException("unexpected pending fixture"); });
                    }
                    catch (InvalidOperationException) { refused = true; }
                    finally { probe.Release(_ => { }, _ => closes++); }
                    Need(refused == (!device && information != 1) && closes == 1);
                }
            foreach (IntPtr invalid in new [] { IntPtr.Zero, Native.InvalidHandle }) {
                var probe = Requests(root)[0]; bool refused = false; int closes = 0;
                try {
                    probe.Open((IntPtr slot, uint access, ref ScratchAccess.ObjectAttributes attributes, IntPtr io, uint share, uint options) => {
                        Marshal.WriteIntPtr(slot, invalid); Marshal.WriteInt32(io, 0); return 0;
                    }, () => { throw new InvalidOperationException("unexpected pending fixture"); });
                }
                catch (InvalidOperationException) { refused = true; }
                finally { probe.Release(_ => { }, _ => closes++); }
                Need(refused && closes == 0 && probe.memory == IntPtr.Zero);
            }
            foreach (bool pendingReturn in new [] { false, true }) {
                var probe = Requests(root)[0]; bool refused = false; int fatalCalls = 0;
                try {
                    probe.Open((IntPtr slot, uint access, ref ScratchAccess.ObjectAttributes attributes, IntPtr io, uint share, uint options) => {
                        Marshal.WriteInt32(io, pendingReturn ? 0 : 0x103); return pendingReturn ? 0x103 : 0;
                    }, () => fatalCalls++);
                }
                catch (InvalidOperationException) { refused = true; }
                finally {
                    Need(refused && fatalCalls == 1 && probe.pending && probe.memory != IntPtr.Zero);
                    // The injected call has no live I/O; production pending buffers remain retained.
                    probe.pending = false; probe.Release(_ => { }, _ => { throw new InvalidOperationException("unexpected handle fixture"); });
                }
                Need(probe.memory == IntPtr.Zero);
            }
            for (int mode = 0; mode < 4; mode++) {
                var probes = Requests(root); int closes = 0; Exception caught = null;
                var operation = new InvalidOperationException("fixed metadata fixture");
                var cleanup = new InvalidOperationException("fixed close fixture");
                foreach (var probe in probes) {
                    probe.memory = Marshal.AllocHGlobal(8); Marshal.WriteIntPtr(probe.memory, new IntPtr(17));
                    probe.returned = 0; probe.opened = true; probe.ioStatus = -1; probe.information = UInt64.MaxValue;
                }
                probes[0].returned = unchecked((int)0xC0000022); probes[0].opened = false;
                Marshal.WriteIntPtr(probes[0].memory, IntPtr.Zero);
                try {
                    int[] result = Qualify(probes, root, true, (handle, desired, context) => {
                        Need(handle == new IntPtr(17));
                        if (mode == 1 || mode == 3) throw operation;
                        return desired;
                    }, _ => { closes++; if (mode == 2 || mode == 3) throw cleanup; });
                    var frames = Frames("modified", Combine(0, 0, result));
                    Need(mode == 0 && frames.Count == 9 && frames[0].Contains("information=0xFFFFFFFFFFFFFFFF") &&
                        frames[0].Contains("io_status=0xFFFFFFFF"));
                }
                catch (Exception error) { caught = error; }
                Need(closes == 8 && (mode == 0 ? caught == null : caught != null));
                foreach (var probe in probes) Need(probe.memory == IntPtr.Zero);
                if (mode == 1) Need(Object.ReferenceEquals(caught, operation));
                if (mode == 3) Need(caught is AggregateException &&
                    Object.ReferenceEquals(((AggregateException)caught).InnerExceptions[0], operation));
            }
            for (int mode = 0; mode < 11; mode++) {
                var probes = Requests(root); int closes = 0, queries = 0; Exception caught = null;
                var cleanup = new InvalidOperationException("fixed close fixture");
                foreach (var probe in probes) {
                    probe.memory = Marshal.AllocHGlobal(8); Marshal.WriteIntPtr(probe.memory, new IntPtr(17));
                    probe.opened = true; probe.information = UInt64.MaxValue;
                }
                probes[0].returned = unchecked((int)0xC0000022); probes[0].opened = false;
                Marshal.WriteIntPtr(probes[0].memory, IntPtr.Zero);
                if (mode == 8) { probes[1].returned = unchecked((int)0xC0000022); probes[1].opened = false;
                    Marshal.WriteIntPtr(probes[1].memory, IntPtr.Zero); }
                if (mode == 9) probes[1].requested = UInt32.MaxValue;
                Need(Census(probes).StartsWith("C0000022,"));
                if (mode == 0) {
                    probes[1].opened = false;
                    Need(Census(probes).StartsWith("C0000022,unknown,"));
                    probes[1].opened = true; probes[1].pending = true;
                    Need(Census(probes).StartsWith("C0000022,unknown,"));
                    probes[1].pending = false;
                }
                QueryCall query = (IntPtr handle, int kind, IntPtr buffer, uint capacity, out uint length) => {
                    queries++; Need(handle == new IntPtr(17) && capacity == 1024);
                    Marshal.Copy(new byte[1024], 0, buffer, 1024); length = kind == 0 ? 56U : 16U;
                    if (kind == 0) {
                        if (mode == 1 || mode == 10) return unchecked((int)0xC0000022);
                        if (mode == 2) length = 55;
                        Marshal.WriteInt32(buffer, mode == 3 ? 2 : 0);
                        Marshal.WriteInt32(buffer, 4, unchecked((int)(mode == 4 ? UInt32.MaxValue : probes[1 + queries / 2].requested)));
                    }
                    else {
                        if (mode == 5) return unchecked((int)0xC0000022);
                        string name = mode == 7 ? "private fixture name" : root.TrimEnd('\\');
                        byte[] bytes = System.Text.Encoding.Unicode.GetBytes(name);
                        Marshal.Copy(bytes, 0, IntPtr.Add(buffer, 16), bytes.Length);
                        Marshal.WriteInt16(buffer, (short)bytes.Length); Marshal.WriteInt16(buffer, 2, (short)bytes.Length);
                        Marshal.WriteIntPtr(buffer, 8, IntPtr.Add(buffer, 16)); length = mode == 6 ? 15U : (uint)(16 + bytes.Length);
                    }
                    return 0;
                };
                try {
                    Qualify(probes, root, true, (handle, desired, context) =>
                        Inspect(handle, desired, root, () => { }, context, query), _ => { closes++; if (mode == 10) throw cleanup; });
                }
                catch (Exception error) { caught = error; }
                Need(closes == (mode == 8 ? 7 : 8));
                foreach (var probe in probes) Need(probe.memory == IntPtr.Zero);
                if (mode == 0) Need(caught == null && queries == 16);
                else {
                    int stage = new [] { 0, 3, 4, 4, 5, 6, 7, 8, 2, 1, 3 }[mode];
                    Exception operation = caught;
                    if (mode == 10) {
                        var aggregate = caught as AggregateException;
                        Need(aggregate != null && aggregate.InnerExceptions.Count == 9);
                        operation = aggregate.InnerExceptions[0];
                        for (int i = 1; i < aggregate.InnerExceptions.Count; i++) {
                            var released = aggregate.InnerExceptions[i] as AggregateException;
                            Need(released != null && released.InnerExceptions.Count == 1 &&
                                Object.ReferenceEquals(released.InnerExceptions[0], cleanup));
                        }
                    }
                    Need(operation is InvalidOperationException && operation.Message.Contains("stage=" + stage) &&
                        operation.Message.Contains("information=0xFFFFFFFFFFFFFFFF") && operation.Message.Length < 640 &&
                        !operation.Message.Contains(root) && !operation.Message.Contains("private fixture name") &&
                        operation.Message.Contains("open_statuses=C0000022,"));
                    Need(queries == (mode == 8 || mode == 9 ? 0 : mode < 5 || mode == 10 ? 1 : 2));
                }
            }
            var evidence = new Evidence(Requests(root)[0], true) { stage = 4, queryKind = 0,
                queried = true, queryStatus = -1, returned = 56, basicKnown = true,
                attributes = UInt32.MaxValue, granted = 0x100020 };
            evidence.request.ioStatus = -1; evidence.request.information = UInt64.MaxValue;
            string refusal = null;
            try { Need(false, evidence); } catch (InvalidOperationException error) { refusal = error.Message; }
            Need(refusal != null && refusal.Length < 640 && refusal.Contains("stage=4") &&
                refusal.Contains("information=0xFFFFFFFFFFFFFFFF") && refusal.Contains("attributes=0xFFFFFFFF") &&
                refusal.Contains("query_status=0xFFFFFFFF") && refusal.Contains("name_equal=-1") &&
                !refusal.Contains("Harddisk") && !refusal.Contains("\\\\Device") && !refusal.Contains("17"));
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
