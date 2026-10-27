using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace ScientificSecurity
{
    // Owns the standard tool's session, not an ETW provider or event reader.
    public static class SxsTraceSession
    {
        internal const string SessionName = "WinSxs Trace Session";
        const int Capacity = 4216, Header = 120, Slots = 256;
        const uint Missing = 4201;
        static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        static extern uint ControlTraceW(ulong handle, string name, IntPtr properties, uint operation);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        static extern uint QueryAllTracesW(IntPtr[] properties, uint count, out uint returned);
        internal sealed class Snapshot
        {
            internal ulong handle;
            internal Guid guid;
            internal string name, path;
            internal uint mode, lost, logLost, realLost, bufferSize, maximumBuffers;
        }
        internal sealed class PrivateFailure : Exception
        {
            internal readonly Exception Original;
            internal PrivateFailure(Exception original, string stage) : base("fixed SxS trace failed stage=" + stage + " raw_error_withheld=True")
            { Original = original; }
        }
        internal static Exception Safe(Exception error, string stage)
        { return error is PrivateFailure ? error : new PrivateFailure(error, stage); }
        internal static void Need(bool value)
        { if (!value) throw new InvalidOperationException("fixed SxS trace contract is inconclusive"); }
        internal enum Stage { Initial, Intent, StartTool, PostTool, Bind, PostBind, BindSave }
        internal static void At(Stage stage, Action operation)
        {
            string label;
            switch (stage) {
                case Stage.Initial: label = "initial"; break;
                case Stage.Intent: label = "intent"; break;
                case Stage.StartTool: label = "start-tool"; break;
                case Stage.PostTool: label = "post-tool"; break;
                case Stage.Bind: label = "bind"; break;
                case Stage.PostBind: label = "post-bind"; break;
                case Stage.BindSave: label = "bind-save"; break;
                default: throw new InvalidOperationException("unsupported fixed SxS start stage");
            }
            try { operation(); } catch (Exception error) { throw Safe(error, label); }
        }
        enum Predicate { Length, Header, Offsets, TextOffset, Terminator, Selection, Present, Handle, Guid, Name, Path, Mode }
        static void Check(bool value, Predicate predicate)
        {
            if (!value) throw new PrivateFailure(new InvalidOperationException("fixed SxS session predicate rejected"),
                "session-predicate check=" + predicate.ToString().ToLowerInvariant());
        }
        internal static IDisposable Exclusive()
        {
            bool created; var mutex = new Mutex(false, @"Local\Scientific.Security.SxsTrace", out created);
            if (!created) { mutex.Dispose(); throw new InvalidOperationException("fixed SxS trace owner collision"); }
            return mutex;
        }
        internal static string State(string run, string state)
        {
            Need(run != null && run.Length == 32 && run.All(c => c >= '0' && c <= '9' || c >= 'a' && c <= 'f'));
            Need(Path.IsPathFullyQualified(state)); state = Path.GetFullPath(state);
            Need(Path.GetFileName(state) == "security-windows-" + run); Plain(state, true); return state;
        }
        internal static void Plain(string path, bool missing = false)
        {
            Need(Path.IsPathFullyQualified(path));
            var stack = new Stack<string>();
            for (string p = Path.GetFullPath(path); !String.IsNullOrEmpty(p); p = Path.GetDirectoryName(p)) {
                Need(stack.Count < 64); stack.Push(p);
            }
            while (stack.Count != 0) {
                string p = stack.Pop();
                try { Need((File.GetAttributes(p) & FileAttributes.ReparsePoint) == 0); }
                catch (FileNotFoundException) { Need(missing && p == path); }
                catch (DirectoryNotFoundException) { Need(missing && p == path); }
            }
        }
        internal static bool Exists(string path)
        {
            try { Need((File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0); return true; }
            catch (FileNotFoundException) { return false; }
            catch (DirectoryNotFoundException) { return false; }
        }
        internal static string Folder(string run, string volume)
        {
            Need(volume != null && volume.Length == 3 && volume[1] == ':' && volume[2] == '\\' &&
                Char.ToUpperInvariant(volume[0]) >= 'D' && Char.ToUpperInvariant(volume[0]) <= 'Z');
            return Path.Combine(volume, "sxs-trace-" + run);
        }
        internal static void Save(string path, string text)
        {
            Plain(path, true); Need(!Exists(path)); byte[] data = Utf8.GetBytes(text); Need(data.Length <= 2048);
            using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                file.Write(data, 0, data.Length); file.Flush(true);
            }
        }
        static string Read(string path)
        {
            Plain(path);
            using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                Need(file.Length > 0 && file.Length <= 2048); byte[] bytes = new byte[(int)file.Length];
                int offset = 0;
                while (offset < bytes.Length) { int n = file.Read(bytes, offset, bytes.Length - offset); Need(n > 0); offset += n; }
                return Utf8.GetString(bytes);
            }
        }
        static IntPtr Allocate()
        {
            Need(IntPtr.Size == 8); IntPtr p = Marshal.AllocHGlobal(Capacity);
            try {
                Marshal.Copy(new byte[Capacity], 0, p, Capacity);
                Marshal.WriteInt32(p, Capacity); Marshal.WriteInt32(p, 112, Header + 2048); Marshal.WriteInt32(p, 116, Header);
                return p;
            }
            catch { Marshal.FreeHGlobal(p); throw; }
        }
        static string Text(byte[] bytes, int offset)
        {
            Check(offset == Header || offset == Header + 2048, Predicate.TextOffset);
            int end = offset;
            while (end - offset < 2048 && (bytes[end] != 0 || bytes[end + 1] != 0)) end += 2;
            Check(end - offset < 2048, Predicate.Terminator);
            try { return new UnicodeEncoding(false, false, true).GetString(bytes, offset, end - offset); }
            catch (DecoderFallbackException error) { throw Safe(error, "session-text-encoding"); }
        }
        internal static Snapshot Decode(byte[] bytes)
        {
            Check(bytes != null && bytes.Length == Capacity, Predicate.Length);
            Check(BitConverter.ToInt32(bytes, 0) == Capacity, Predicate.Header);
            int path = BitConverter.ToInt32(bytes, 112), name = BitConverter.ToInt32(bytes, 116);
            Check(name == Header && path == Header + 2048, Predicate.Offsets);
            return new Snapshot { handle = BitConverter.ToUInt64(bytes, 8), guid = new Guid(bytes.Skip(24).Take(16).ToArray()),
                name = Text(bytes, name), path = Text(bytes, path), mode = BitConverter.ToUInt32(bytes, 64),
                bufferSize = BitConverter.ToUInt32(bytes, 48), maximumBuffers = BitConverter.ToUInt32(bytes, 56),
                lost = BitConverter.ToUInt32(bytes, 88), logLost = BitConverter.ToUInt32(bytes, 96), realLost = BitConverter.ToUInt32(bytes, 100) };
        }
        static Snapshot Result(IntPtr p)
        { byte[] bytes = new byte[Capacity]; Marshal.Copy(p, bytes, 0, Capacity); return Decode(bytes); }
        static Snapshot Query()
        {
            IntPtr p = Allocate();
            try {
                uint status = ControlTraceW(0, SessionName, p, 0);
                if (status == Missing) return null;
                if (status != 0) throw new PrivateFailure(new InvalidOperationException("fixed SxS session query failed"),
                    "session-query win32=" + status.ToString("X8"));
                return Result(p);
            }
            finally { Marshal.FreeHGlobal(p); }
        }
        static Snapshot[] All()
        {
            var pointers = new IntPtr[Slots];
            try {
                for (int i = 0; i < Slots; i++) pointers[i] = Allocate();
                uint count; uint status = QueryAllTracesW(pointers, Slots, out count); RequireEnumeration(status, count);
                var result = new Snapshot[count];
                for (int i = 0; i < count; i++) result[i] = Result(pointers[i]);
                return result;
            }
            finally { foreach (IntPtr p in pointers) if (p != IntPtr.Zero) Marshal.FreeHGlobal(p); }
        }
        internal static void RequireEnumeration(uint status, uint count)
        {
            if (status != 0 || count > Slots)
                throw new PrivateFailure(new InvalidOperationException("fixed SxS session enumeration failed"),
                    "session-enumeration win32=" + status.ToString("X8") + " count=" + count);
        }
        static bool PathEqual(string a, string b)
        { return String.Equals(a, b, StringComparison.OrdinalIgnoreCase); }
        internal static Snapshot Select(Snapshot[] sessions, string path)
        {
            Check(sessions != null && sessions.Length <= Slots, Predicate.Selection);
            var matches = sessions.Where(s => s.name == SessionName || PathEqual(s.path, path)).ToArray();
            if (matches.Length > 1) throw new PrivateFailure(new InvalidOperationException("fixed SxS session match collision"),
                "session-selection matches=" + matches.Length);
            if (matches.Length == 0) return null;
            Snapshot found = matches[0];
            Check(found.name == SessionName, Predicate.Name); Check(PathEqual(found.path, path), Predicate.Path);
            Check(found.handle != 0, Predicate.Handle); Check(found.guid != Guid.Empty, Predicate.Guid);
            return found;
        }
        internal static void RequireCapture(Snapshot s)
        {
            Check(s != null, Predicate.Present);
            if (s.mode != 1 || s.bufferSize == 0 || s.maximumBuffers == 0 ||
                (ulong)s.bufferSize * s.maximumBuffers > 16384 || s.lost != 0 || s.logLost != 0 || s.realLost != 0)
                throw new PrivateFailure(new InvalidOperationException("fixed SxS capture policy rejected"),
                    "session-capture mode=" + s.mode.ToString("X8") + " buffer_kib=" + s.bufferSize +
                    " maximum_buffers=" + s.maximumBuffers + " events_lost=" + s.lost +
                    " log_lost=" + s.logLost + " realtime_lost=" + s.realLost);
        }
        internal static void RequireSame(Snapshot expected, Snapshot actual)
        {
            Check(expected != null && actual != null, Predicate.Present);
            Check(expected.handle == actual.handle, Predicate.Handle); Check(expected.guid == actual.guid, Predicate.Guid);
            Check(expected.name == actual.name, Predicate.Name); Check(PathEqual(expected.path, actual.path), Predicate.Path);
            Check(expected.mode == actual.mode, Predicate.Mode);
        }
        internal static void Intent(string run, string state, string volume)
        {
            State(run, state); string path = Path.Combine(Folder(run, volume), "capture.etl");
            Need(Select(All(), path) == null && Query() == null);
            Save(Path.Combine(state, "sxs-trace.intent"), IntentText(run, volume));
        }
        internal static void Bind(string run, string state, string volume)
        {
            string path = Path.Combine(Folder(run, volume), "capture.etl"); Snapshot found = Select(All(), path);
            RequireSame(found, Query()); RequireCapture(found);
            At(Stage.BindSave, () => Save(Path.Combine(state, "sxs-trace.bound"), BoundText(run, found)));
        }
        internal static string IntentText(string run, string volume)
        { Folder(run, volume); return "sxs-intent-v1\n" + run + "\n" + volume + "\n"; }
        internal static string IntentVolume(string text, string run)
        {
            Need(text != null && Utf8.GetByteCount(text) <= 2048);
            string[] fields = text.Split('\n');
            Need(fields.Length == 4 && fields[0] == "sxs-intent-v1" && fields[1] == run && fields[3] == "");
            Folder(run, fields[2]); return fields[2];
        }
        internal static string BoundText(string run, Snapshot found)
        {
            Need(found != null && found.handle != 0 && found.guid != Guid.Empty);
            return "sxs-bound-v1\n" + run + "\n" + found.handle.ToString("X16") + "\n" + found.guid.ToString("D") + "\n" + found.mode.ToString("X8") + "\n";
        }
        internal static Snapshot DecodeBound(string text, string run, string logfile)
        {
            Need(text != null && Utf8.GetByteCount(text) <= 2048);
            string[] fields = text.Split('\n'); ulong handle; Guid guid = Guid.Empty; uint mode = 0;
            Need(fields.Length == 6 && fields[0] == "sxs-bound-v1" && fields[1] == run && fields[5] == "");
            Need(UInt64.TryParse(fields[2], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out handle) &&
                handle != 0 && fields[2] == handle.ToString("X16") && Guid.TryParseExact(fields[3], "D", out guid) && guid != Guid.Empty &&
                UInt32.TryParse(fields[4], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out mode) && fields[4] == mode.ToString("X8"));
            return new Snapshot { handle = handle, guid = guid, mode = mode, name = SessionName, path = logfile };
        }
        internal static void Stop(string run, string state, bool starterReaped, bool capture)
        {
            State(run, state);
            string intent = Path.Combine(state, "sxs-trace.intent");
            if (!Exists(state) || !Exists(intent)) return;
            Need(starterReaped);
            string logfile = Path.Combine(Folder(run, IntentVolume(Read(intent), run)), "capture.etl"), bound = Path.Combine(state, "sxs-trace.bound");
            Snapshot expected = Exists(bound) ? DecodeBound(Read(bound), run, logfile) : null;
            StopOwned(logfile, starterReaped, capture, expected, All, Query, found => {
                IntPtr p = Allocate();
                try { Need(ControlTraceW(found.handle, null, p, 1) == 0); return Result(p); }
                finally { Marshal.FreeHGlobal(p); }
            });
        }
        internal static void StopOwned(string logfile, bool starterReaped, bool capture, Snapshot expected,
            Func<Snapshot[]> all, Func<Snapshot> query, Func<Snapshot, Snapshot> stop)
        {
            Need(starterReaped);
            Snapshot found = Select(all(), logfile), queried = query();
            if (found == null) { Need(queried == null && !capture); return; }
            RequireSame(found, queried);
            if (expected != null) RequireSame(expected, found);
            // Unbound recovery is conditional on preabsence/private logfile and exclusive trusted host writers.
            Snapshot stopped = stop(found);
            Need(query() == null && Select(all(), logfile) == null);
            if (capture) RequireCapture(stopped);
        }
        public static void Recover(string run, string state, bool starterReaped)
        {
            try { using (Exclusive()) Stop(run, state, starterReaped, false); }
            catch (Exception error) { throw Safe(error, "recovery"); }
        }
        static void Refuse(Action action)
        {
            bool rejected = false;
            try { action(); } catch (Exception failure) {
                var safe = failure as PrivateFailure;
                Exception original = safe == null ? failure : safe.Original;
                Need(original is InvalidOperationException || original is DecoderFallbackException); rejected = true;
            }
            Need(rejected);
        }
        static byte[] Fixture(Snapshot value)
        {
            var bytes = new byte[Capacity];
            Action<int, byte[]> put = (offset, field) => Array.Copy(field, 0, bytes, offset, field.Length);
            put(0, BitConverter.GetBytes(Capacity)); put(8, BitConverter.GetBytes(value.handle)); put(24, value.guid.ToByteArray());
            put(48, BitConverter.GetBytes(value.bufferSize)); put(56, BitConverter.GetBytes(value.maximumBuffers));
            put(64, BitConverter.GetBytes(value.mode)); put(88, BitConverter.GetBytes(value.lost));
            put(96, BitConverter.GetBytes(value.logLost)); put(100, BitConverter.GetBytes(value.realLost));
            put(112, BitConverter.GetBytes(Header + 2048)); put(116, BitConverter.GetBytes(Header));
            put(Header, Encoding.Unicode.GetBytes(value.name)); put(Header + 2048, Encoding.Unicode.GetBytes(value.path));
            return bytes;
        }
        static void CheckRecovery(Snapshot value)
        {
            for (int mode = 0; mode < 12; mode++) {
                bool live = mode != 3 && mode != 4; int stops = 0; Exception caught = null;
                Snapshot foreign = Decode(Fixture(value)); foreign.guid = Guid.NewGuid();
                try {
                    StopOwned(value.path, mode != 2, mode == 4 || mode == 7,
                        mode == 1 ? foreign : mode == 5 ? null : value,
                        () => mode == 6 ? new [] { value, value } : live ? new [] { value } : new Snapshot[0],
                        () => live ? mode == 9 ? foreign : value : mode == 10 ? foreign : null,
                        _ => { stops++; if (mode == 8) throw new IOException("fixed stop failure"); live = mode == 11;
                            Snapshot result = Decode(Fixture(value)); if (mode == 7) result.lost = 1; return result; });
                }
                catch (Exception error) { caught = error; }
                bool succeeds = mode == 0 || mode == 3 || mode == 5;
                Need((caught == null) == succeeds && stops == (mode == 0 || mode == 5 || mode == 7 || mode == 8 || mode == 10 || mode == 11 ? 1 : 0));
            }
            string run = new string('a', 32);
            Need(IntentVolume(IntentText(run, "F:\\"), run) == "F:\\");
            RequireSame(value, DecodeBound(BoundText(run, value), run, value.path));
            foreach (string text in new [] { "", BoundText(run, value) + "x", BoundText(run, value).Replace(run, new string('b', 32)),
                BoundText(run, value).Replace("0000000000000007", "0000000000000000"), BoundText(run, value).Replace(value.guid.ToString("D"), "bad-guid") })
                Refuse(() => DecodeBound(text, run, value.path));
            foreach (string text in new [] { "", IntentText(run, "F:\\") + "x", IntentText(run, "F:\\").Replace(run, "bad"), IntentText(run, "F:\\").Replace("F:\\", "C:\\") })
                Refuse(() => IntentVolume(text, run));
        }
        static void CheckReporting()
        {
            var raw = new IOException("C:\\private-session-sentinel\\capture.etl");
            string[] stages = { "initial", "intent", "start-tool", "post-tool", "bind", "post-bind", "bind-save" };
            for (int index = 0; index < stages.Length; index++) {
                Exception caught = null;
                try { At((Stage)index, () => { throw raw; }); } catch (Exception error) { caught = error; }
                var safe = caught as PrivateFailure;
                Need(safe != null && Object.ReferenceEquals(safe.Original, raw) && safe.InnerException == null &&
                    safe.Message == "fixed SxS trace failed stage=" + stages[index] + " raw_error_withheld=True" &&
                    !safe.ToString().Contains("sentinel"));
                Exception retained = null;
                try { At((Stage)index, () => { throw safe; }); } catch (Exception error) { retained = error; }
                Need(Object.ReferenceEquals(retained, safe));
            }
            foreach (int invalid in new [] { -1, 7, Int32.MaxValue }) {
                int calls = 0; Refuse(() => At((Stage)invalid, () => calls++)); Need(calls == 0);
            }
            for (int index = 0; index < 12; index++) {
                Predicate predicate = (Predicate)index; Exception caught = null;
                Check(true, predicate);
                try { Check(false, predicate); } catch (Exception error) { caught = error; }
                Need(caught is PrivateFailure && caught.InnerException == null && caught.Message.Length < 160);
            }
        }
        public static void CheckValidation()
        {
            CheckReporting();
            var rejectedCapture = new Snapshot { mode = 0, bufferSize = 64, maximumBuffers = 16 };
            Exception projection = null;
            try { RequireCapture(rejectedCapture); } catch (Exception error) { projection = error; }
            Need(projection is PrivateFailure && projection.Message ==
                "fixed SxS trace failed stage=session-capture mode=00000000 buffer_kib=64 maximum_buffers=16 events_lost=0 log_lost=0 realtime_lost=0 raw_error_withheld=True");
            var a = new Snapshot { handle = 7, guid = new Guid("12345678-1234-1234-1234-123456789abc"), name = SessionName,
                path = "F:\\sxs-trace-fixed\\capture.etl", mode = 1, bufferSize = 64, maximumBuffers = 16 };
            RequireSame(a, Select(new [] { a }, a.path)); RequireCapture(a); Need(Select(new Snapshot[0], a.path) == null);
            RequireSame(a, Decode(Fixture(a))); CheckRecovery(a);
            Action[] firstPredicates = { () => Decode(null), () => Decode(new byte[Capacity]),
                () => Select(null, a.path), () => RequireSame(null, a), () => RequireSame(a, new Snapshot()),
                () => RequireCapture(null) };
            string[] labels = { "length", "header", "selection", "present", "handle", "present" };
            for (int index = 0; index < firstPredicates.Length; index++) {
                Exception caught = null;
                try { firstPredicates[index](); } catch (Exception error) { caught = error; }
                Need(caught is PrivateFailure && caught.InnerException == null && caught.Message ==
                    "fixed SxS trace failed stage=session-predicate check=" + labels[index] + " raw_error_withheld=True");
            }
            foreach (int offset in new [] { 0, 112, 116 }) {
                byte[] bytes = Fixture(a); Array.Copy(BitConverter.GetBytes(1), 0, bytes, offset, 4); Refuse(() => Decode(bytes));
            }
            foreach (int offset in new [] { Header, Header + 2048 }) {
                byte[] bytes = Fixture(a);
                for (int i = offset; i < offset + 2048; i += 2) { bytes[i] = 65; bytes[i + 1] = 0; }
                Refuse(() => Decode(bytes));
                bytes = Fixture(a); bytes[offset] = 0; bytes[offset + 1] = 216; bytes[offset + 2] = bytes[offset + 3] = 0;
                Refuse(() => Decode(bytes));
            }
            foreach (int field in new [] { 48, 56, 64, 88, 96, 100 }) {
                Snapshot bad = Decode(Fixture(a));
                byte[] bytes = Fixture(bad); Array.Copy(BitConverter.GetBytes(field == 48 || field == 56 || field == 64 ? 0U : 1U), 0, bytes, field, 4);
                Refuse(() => RequireCapture(Decode(bytes)));
            }
            Snapshot huge = Decode(Fixture(a)); huge.bufferSize = UInt32.MaxValue; huge.maximumBuffers = UInt32.MaxValue;
            Refuse(() => RequireCapture(huge));
            Snapshot foreignName = Decode(Fixture(a)); foreignName.name = "foreign-session";
            Refuse(() => Select(new [] { foreignName }, a.path));
            Refuse(() => Select(new Snapshot[Slots + 1], a.path));
            RequireEnumeration(0, Slots);
            Refuse(() => RequireEnumeration(234, 1)); Refuse(() => RequireEnumeration(5, 0)); Refuse(() => RequireEnumeration(0, Slots + 1));
            foreach (Action invalid in new Action[] {
                () => Select(new [] { a, a }, a.path), () => Select(new [] { a }, "F:\\other.etl"),
                () => RequireSame(a, new Snapshot()), () => RequireCapture(new Snapshot()),
                () => Decode(new byte[Capacity]), () => Decode(new byte[Capacity + 1])
            }) Refuse(invalid);
        }
    }
}
