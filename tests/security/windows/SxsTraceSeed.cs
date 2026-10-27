using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace ScientificSecurity
{
    // Empty fixed-artifact preparation is never completed trace evidence.
    internal static class SxsTraceSeed
    {
        static void Need(bool value) { SxsTraceSession.Need(value); }
        static void Empty(Stream stream) { Need(stream != null && stream.Length == 0); }
        static void Dispose(Stream stream, Exception primary)
        {
            var failures = new List<Exception>();
            StartupActivationAccess.Attempt(failures, () => { if (stream != null) stream.Dispose(); });
            StartupActivationAccess.Finish(primary, failures);
        }
        internal static void Read(Action policy, Func<Stream> open)
        {
            policy(); Stream stream = null; Exception primary = null;
            try { stream = open(); Empty(stream); }
            catch (Exception error) { primary = error; throw; }
            finally { Dispose(stream, primary); }
        }
        internal static void Create(Func<Stream> create, Action<Stream> flush)
        {
            Stream stream = null; Exception primary = null;
            try { stream = create(); Empty(stream); flush(stream); }
            catch (Exception error) { primary = error; throw; }
            finally { Dispose(stream, primary); }
        }
        internal static void PrepareText(Func<double> remaining, Action absent, Action create, Action readback)
        {
            Need(remaining() > 0); absent(); create(); readback(); Need(remaining() > 0);
        }
        sealed class SeedStream : MemoryStream
        {
            internal string order = "";
            internal int failure;
            internal readonly Exception error = new IOException("private-seed-sentinel");
            internal void FlushFixed() { order += "f"; if ((failure & 2) != 0) throw error; }
            protected override void Dispose(bool disposing)
            { order += "d"; base.Dispose(disposing); if ((failure & 4) != 0) throw error; }
        }
        internal static void CheckValidation()
        {
            for (int mode = 0; mode < 6; mode++) {
                var stream = new SeedStream { failure = mode == 2 ? 2 : mode == 3 ? 4 : mode == 4 ? 6 : 0 };
                if (mode == 5) stream.SetLength(1);
                Exception caught = null; int acquired = 0;
                try { Create(() => { acquired++; if (mode == 1) throw stream.error; return stream; },
                    value => ((SeedStream)value).FlushFixed()); }
                catch (Exception error) { caught = error; }
                Need(acquired == 1 && stream.order == (mode == 1 ? "" : mode == 5 ? "d" : "fd"));
                if (mode == 0) Need(caught == null);
                else if (mode == 3 || mode == 4) {
                    var group = caught as AggregateException;
                    Need(group != null && group.InnerExceptions.Count == (mode == 3 ? 1 : 2) &&
                        group.InnerExceptions.All(error => Object.ReferenceEquals(error, stream.error)));
                }
                else if (mode == 5) Need(caught is InvalidOperationException);
                else Need(Object.ReferenceEquals(caught, stream.error));
                if (mode == 1) stream.Dispose();
            }
            for (int mode = 0; mode < 3; mode++) {
                string order = ""; var stream = new SeedStream(); Exception caught = null;
                if (mode == 2) stream.SetLength(1);
                try { Read(() => { order += "p"; if (mode == 1) throw stream.error; },
                    () => { order += "r"; return stream; }); } catch (Exception error) { caught = error; }
                Need(order == (mode == 1 ? "p" : "pr") && stream.order == (mode == 1 ? "" : "d"));
                Need((caught == null) == (mode == 0));
                if (mode == 1) { Need(Object.ReferenceEquals(caught, stream.error)); stream.Dispose(); }
            }
            var closing = new SeedStream { failure = 4 };
            var first = new IOException("private-seed-first"); Exception combined = null;
            try { Create(() => closing, _ => { throw first; }); } catch (Exception error) { combined = error; }
            var ordered = combined as AggregateException;
            Need(ordered != null && ordered.InnerExceptions.Count == 2 && Object.ReferenceEquals(ordered.InnerExceptions[0], first) &&
                Object.ReferenceEquals(ordered.InnerExceptions[1], closing.error) && closing.order == "d");
            closing = new SeedStream { failure = 4 }; closing.SetLength(1); combined = null;
            try { Read(() => { }, () => closing); } catch (Exception error) { combined = error; }
            ordered = combined as AggregateException;
            Need(ordered != null && ordered.InnerExceptions.Count == 2 && ordered.InnerExceptions[0] is InvalidOperationException &&
                Object.ReferenceEquals(ordered.InnerExceptions[1], closing.error) && closing.order == "d");
            for (int mode = 0; mode < 6; mode++) {
                string order = ""; int clocks = 0; Exception caught = null;
                Action<int> step = phase => { order += phase; if (mode == phase + 1) throw first; };
                try { PrepareText(() => { clocks++; return mode == 4 || mode == 5 && clocks == 2 ? 0 : 1; },
                    () => step(0), () => step(1), () => step(2)); order += "p"; }
                catch (Exception error) { caught = error; }
                Need(order == (mode == 0 ? "012p" : mode == 1 ? "0" : mode == 2 ? "01" : mode == 4 ? "" : "012"));
                Need((caught == null) == (mode == 0));
                if (mode >= 1 && mode <= 3) Need(Object.ReferenceEquals(caught, first));
            }
        }
    }
}
