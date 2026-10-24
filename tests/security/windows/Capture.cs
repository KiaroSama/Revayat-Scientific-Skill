using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ScientificSecurity
{
    // Only anonymous pipe write ends cross the boundary; no child paths are promoted.
    internal sealed class Capture : IDisposable
    {
        internal IntPtr Writer { get { return writer; } }
        IntPtr reader, writer;
        readonly MemoryStream captured = new MemoryStream();
        readonly Task drain;
        readonly object gate = new object();
        Exception failure;
        readonly bool strictClose;
        bool closeFailed;
        internal Capture(bool strictClose = false)
        {
            this.strictClose = strictClose;
            var attributes = new Native.SecurityAttributes {
                size = (uint)Marshal.SizeOf(typeof(Native.SecurityAttributes)), inherit = 1 };
            IntPtr write;
            Native.Check(Native.CreatePipe(out reader, out write, ref attributes, 4096), "create anonymous capture pipe");
            writer = write;
            try
            {
                Native.Check(Native.SetHandleInformation(reader, 1, 0), "remove parent pipe-reader inheritance");
                drain = Task.Run((Action)Drain);
            }
            catch (Exception primary) {
                try { Dispose(); }
                catch (Exception cleanup) { throw new AggregateException("capture initialization/cleanup failed", primary, cleanup); }
                throw;
            }
        }
        void Drain()
        {
            try
            {
                byte[] buffer = new byte[4096];
                while (true)
                {
                    uint read;
                    if (!Native.ReadFile(reader, buffer, (uint)buffer.Length, out read, IntPtr.Zero)) {
                        int error = Marshal.GetLastWin32Error();
                        if (error == 109) break;
                        throw new System.ComponentModel.Win32Exception(error, "drain owned capture pipe");
                    }
                    if (read == 0) break;
                    lock (gate) {
                        if (captured.Length + read > 1048576) throw new InvalidOperationException("worker capture exceeded 1 MiB");
                        captured.Write(buffer, 0, checked((int)read));
                    }
                }
            }
            catch (Exception error) { lock (gate) failure = error; }
        }
        internal long Length()
        {
            lock (gate) {
                if (failure != null) throw new InvalidOperationException("owned pipe capture failed", failure);
                return captured.Length;
            }
        }
        static void CloseStrict(ref IntPtr handle, ref bool uncertain, Func<IntPtr, bool> close)
        {
            IntPtr owned = handle;
            if (owned == IntPtr.Zero) return;
            handle = IntPtr.Zero; // Never retry an uncertain numeric handle.
            bool closed = false;
            try { closed = close(owned); }
            finally { if (!closed) uncertain = true; }
            if (!closed) throw new InvalidOperationException("fixed activation capture close remains uncertain");
        }
        static void RequireClosed(bool uncertain)
        { if (uncertain) throw new InvalidOperationException("fixed activation capture close remains uncertain"); }
        internal void CloseWriter()
        {
            if (strictClose) CloseStrict(ref writer, ref closeFailed, Native.CloseHandle);
            else if (writer != IntPtr.Zero) { Native.CloseHandle(writer); writer = IntPtr.Zero; }
        }
        internal bool HasWallTreeMarker()
        {
            lock (gate) {
                if (failure != null) throw new InvalidOperationException("owned pipe capture failed", failure);
                foreach (string line in Encoding.UTF8.GetString(captured.ToArray()).Split('\n')) {
                    if (line.TrimEnd('\r') == "trusted wall-tree negative control started") return true;
                }
                return false;
            }
        }
        internal string Read()
        {
            if (!drain.Wait(TimeSpan.FromSeconds(5))) throw new TimeoutException("pipe did not close after owned job reaping");
            lock (gate) {
                if (failure != null) throw new InvalidOperationException("owned pipe capture failed", failure);
                return new UTF8Encoding(false, true).GetString(captured.ToArray());
            }
        }
        static void FinishStrict(params Action[] actions)
        {
            var failures = new List<Exception>();
            foreach (Action action in actions) try { action(); } catch (Exception error) { failures.Add(error); }
            if (failures.Count != 0) throw new AggregateException("fixed activation capture cleanup failed", failures);
        }
        internal static Exception CheckStrictCleanup()
        {
            Exception actualFailure = null;
            foreach (int mode in new [] { 0, 1, 2, 3 }) {
                IntPtr writer = new IntPtr(11), reader = new IntPtr(12); bool uncertain = false;
                var order = new List<string>(); var attempted = new List<IntPtr>(); Exception caught = null;
                Func<IntPtr, bool> close = handle => {
                    attempted.Add(handle); order.Add(handle == new IntPtr(11) ? "writer" : "reader");
                    return !(handle == new IntPtr(11) ? mode == 1 || mode == 3 : mode == 2 || mode == 3);
                };
                try { FinishStrict(
                    () => CloseStrict(ref writer, ref uncertain, close),
                    () => order.Add("cancel"),
                    () => CloseStrict(ref reader, ref uncertain, close),
                    () => order.Add("join"), () => order.Add("buffer"), () => RequireClosed(uncertain)); }
                catch (Exception failure) { caught = failure; }
                // A second cleanup must neither retry either numeric handle nor forget prior uncertainty.
                Exception repeated = null;
                try { FinishStrict(() => CloseStrict(ref writer, ref uncertain, close),
                    () => CloseStrict(ref reader, ref uncertain, close), () => RequireClosed(uncertain)); }
                catch (Exception failure) { repeated = failure; }
                if (writer != IntPtr.Zero || reader != IntPtr.Zero || attempted.Count != 2 ||
                    attempted[0] != new IntPtr(11) || attempted[1] != new IntPtr(12) ||
                    String.Join(",", order) != "writer,cancel,reader,join,buffer" || uncertain != (mode != 0) ||
                    (mode == 0 ? caught != null || repeated != null : caught == null || repeated == null))
                    throw new InvalidOperationException("capture strict-close ownership or sticky failure differs");
                if (mode == 3) actualFailure = caught;
            }
            return actualFailure;
        }
        public void Dispose()
        {
            if (strictClose) {
                FinishStrict(
                    CloseWriter,
                    () => { if (reader != IntPtr.Zero) Native.CancelIoEx(reader, IntPtr.Zero); },
                    () => CloseStrict(ref reader, ref closeFailed, Native.CloseHandle),
                    () => { if (drain != null && !drain.Wait(TimeSpan.FromSeconds(5))) throw new TimeoutException("fixed activation pipe reader did not stop"); },
                    captured.Dispose,
                    () => RequireClosed(closeFailed));
                return;
            }
            CloseWriter();
            if (reader != IntPtr.Zero) {
                Native.CancelIoEx(reader, IntPtr.Zero);
                Native.CloseHandle(reader); reader = IntPtr.Zero;
            }
            if (drain != null && !drain.Wait(TimeSpan.FromSeconds(5)))
                throw new TimeoutException("owned pipe reader did not stop");
            captured.Dispose();
        }
    }
}
