using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace ScientificSecurity
{
    public static partial class StartupActivationAccess
    {
        sealed class TraceCheckLease : IDisposable
        {
            readonly Action close;
            internal TraceCheckLease(Action close) { this.close = close; }
            public void Dispose() { close(); }
        }
        public static void CheckTraceControlValidation()
        {
            const string run = "0123456789abcdef0123456789abcdef";
            byte[] bytes = TraceControlBytes(run);
            string text = new UTF8Encoding(false, true).GetString(bytes);
            SxsTraceSession.Need(text == "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<assembly manifestVersion=\"1.0\"><assemblyIdentity type=\"win32\" version=\"1.0.0.0\" " +
                "name=\"Scientific.Security.TraceControl." + run + "\"/></assembly>\n" && bytes.Length <= 512);
            foreach (string invalid in new [] { "", run + "0", run.ToUpperInvariant(), "private-path-sentinel" }) {
                bool refused = false; try { TraceControlBytes(invalid); } catch (InvalidOperationException) { refused = true; }
                SxsTraceSession.Need(refused);
            }
            var context = TraceControlContext(@"F:\owned space\collector.manifest");
            SxsTraceSession.Need(Marshal.SizeOf(typeof(ActCtx)) == 56 && context.size == 56 && context.flags == 0 &&
                context.source == @"F:\owned space\collector.manifest" && context.resource == IntPtr.Zero &&
                context.architecture == 0 && context.language == 0 && context.assemblyDirectory == null &&
                context.application == null && context.module == IntPtr.Zero);
            foreach (IntPtr handle in new [] { IntPtr.Zero, Native.InvalidHandle, new IntPtr(7) })
                foreach (uint error in new uint[] { 0, 5, 14001, UInt32.MaxValue }) {
                    int releases = 0, closes = 0, reads = 0, emits = 0; Exception caught = null;
                    try {
                        ExecuteTraceControl(() => new TraceCheckLease(() => closes++),
                            (out uint code) => { code = error; return handle; },
                            value => { SxsTraceSession.Need(value == handle); releases++; },
                            _ => reads++, () => { }, () => emits++);
                    } catch (Exception failure) { caught = failure; }
                    bool expected = handle == Native.InvalidHandle && error == 14001;
                    SxsTraceSession.Need((caught == null) == expected && emits == (expected ? 1 : 0) &&
                        releases == (handle != IntPtr.Zero && handle != Native.InvalidHandle ? 1 : 0) && closes == 1 && reads == 2);
                }
            for (int mode = 0; mode <= 8; mode++) {
                var order = new List<string>(); var first = new IOException("private-control-first");
                var later = new IOException("private-control-later"); Exception caught = null; int reads = 0;
                try {
                    ExecuteTraceControl(() => {
                        order.Add("open"); if (mode == 1) throw first;
                        return new TraceCheckLease(() => { order.Add("close"); if (mode == 5 || mode == 7) throw later; });
                    }, (out uint code) => {
                        order.Add("call"); code = 14001; if (mode == 3 || mode == 7) throw first;
                        return mode == 8 ? new IntPtr(7) : Native.InvalidHandle;
                    }, _ => { order.Add("release"); if (mode == 8) throw later; },
                    _ => { order.Add("read"); if (++reads == 1 && mode == 2) throw first;
                        if (reads == 2 && (mode == 4 || mode == 7)) throw later; },
                    () => { if (mode == 6 && order.Contains("close")) throw first; },
                    () => order.Add("emit"));
                } catch (Exception failure) { caught = failure; }
                SxsTraceSession.Need((caught == null) == (mode == 0) && order.Contains("emit") == (mode == 0) &&
                    order.Contains("close") == (mode != 1) && order.Contains("release") == (mode == 8));
                if (mode == 7) {
                    var group = caught as AggregateException;
                    SxsTraceSession.Need(group != null && group.InnerExceptions.Count == 3 &&
                        Object.ReferenceEquals(group.InnerExceptions[0], first) &&
                        Object.ReferenceEquals(group.InnerExceptions[1], later) && Object.ReferenceEquals(group.InnerExceptions[2], later));
                }
                if (caught != null) SxsTraceSession.Need(!SxsTraceSession.Safe(caught, "collector-control").ToString().Contains("private-"));
            }
            CheckTraceWriterValidation(bytes); CheckTraceLifecycleValidation(); SxsTraceSuccess.CheckValidation();
        }
        sealed class TraceWriteStream : MemoryStream
        {
            internal string order = "";
            internal int failure, closes;
            internal byte[] expected;
            internal readonly Exception first = new IOException("private-control-write");
            internal readonly Exception last = new IOException("private-control-close");
            public override void Write(byte[] bytes, int offset, int count)
            {
                order += "w";
                SxsTraceSession.Need(Object.ReferenceEquals(bytes, expected) && offset == 0 && count == expected.Length);
                if ((failure & 1) != 0) throw first;
                base.Write(bytes, offset, count);
            }
            internal void FlushFixed() { order += "f"; if ((failure & 2) != 0) throw first; }
            protected override void Dispose(bool disposing)
            {
                order += "d"; closes++; base.Dispose(disposing);
                if ((failure & 4) != 0) throw last;
            }
        }
        static void CheckTraceWriterValidation(byte[] bytes)
        {
            for (int mode = 0; mode < 8; mode++) {
                var stream = new TraceWriteStream { failure = mode, expected = bytes };
                int opens = 0, qualified = 0, calls = 0, emits = 0, heldCloses = 0; Exception caught = null;
                try {
                    ExecuteTraceControl(() => {
                        SxsTraceCapture.WriteFixed(() => { opens++; return stream; },
                            value => ((TraceWriteStream)value).FlushFixed(), bytes);
                        qualified++; return new TraceCheckLease(() => heldCloses++);
                    }, (out uint error) => { calls++; error = 14001; return Native.InvalidHandle; },
                    _ => { throw new InvalidOperationException("unexpected release"); },
                    _ => { }, () => { }, () => emits++);
                } catch (Exception error) { caught = error; }
                bool success = mode == 0;
                SxsTraceSession.Need((caught == null) == success && opens == 1 && stream.closes == 1 &&
                    stream.order == ((mode & 1) != 0 ? "wd" : "wfd") && qualified == (success ? 1 : 0) &&
                    calls == (success ? 1 : 0) && emits == (success ? 1 : 0) && heldCloses == (success ? 1 : 0));
                if (success) continue;
                var outer = caught as AggregateException;
                SxsTraceSession.Need(outer != null && outer.InnerExceptions.Count == 1);
                Exception writer = outer.InnerExceptions[0];
                if ((mode & 4) != 0) {
                    var failures = writer as AggregateException;
                    bool operationFailed = (mode & 3) != 0;
                    SxsTraceSession.Need(failures != null && failures.InnerExceptions.Count == (operationFailed ? 2 : 1) &&
                        Object.ReferenceEquals(failures.InnerExceptions[0], operationFailed ? stream.first : stream.last) &&
                        Object.ReferenceEquals(failures.InnerExceptions[failures.InnerExceptions.Count - 1], stream.last));
                }
                else SxsTraceSession.Need(Object.ReferenceEquals(writer, stream.first));
                SxsTraceSession.Need(!SxsTraceSession.Safe(caught, "collector-control").ToString().Contains("private-"));
            }
        }
        static void CheckTraceLifecycleValidation()
        {
            var operation = new IOException("private-consumer"); var control = new IOException("private-control");
            var stop = new IOException("private-stop"); var parse = new IOException("private-parse");
            for (int mode = 0; mode < 7; mode++) {
                string order = ""; Exception caught = null;
                try {
                    SxsTraceCapture.Execute(() => { order += "o"; if (mode == 1 || mode == 5) throw operation; },
                        () => { order += "c"; if (mode == 2) throw control; },
                        () => { order += "s"; if (mode == 3 || mode == 5) throw stop; },
                        success => { order += success ? "p" : "f"; if (mode == 4 || mode == 6) throw parse; });
                } catch (Exception failure) { caught = failure; }
                SxsTraceSession.Need(order == (mode == 1 ? "osf" : mode == 2 || mode == 3 ? "ocs" : mode == 5 ? "os" : "ocsp"));
                SxsTraceSession.Need((caught == null) == (mode == 0));
                if (mode == 1) SxsTraceSession.Need(Object.ReferenceEquals(caught, operation));
                if (mode == 5) SxsTraceSession.Need(caught is AggregateException &&
                    Object.ReferenceEquals(((AggregateException)caught).InnerExceptions[0], operation));
                if (caught != null) SxsTraceSession.Need(!RegistryLoaderEvidence.Sanitize(caught).ToString().Contains("private-"));
            }
        }
    }
}
