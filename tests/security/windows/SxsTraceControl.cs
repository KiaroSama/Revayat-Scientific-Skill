using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace ScientificSecurity
{
    public static partial class StartupActivationAccess
    {
        delegate IntPtr TraceCreate(out uint error);
        internal static byte[] TraceControlBytes(string run)
        {
            SxsTraceSession.Need(run != null && run.Length == 32 && run.All(c => c >= '0' && c <= '9' || c >= 'a' && c <= 'f'));
            // The missing required assembly namespace is intentional negative-control input.
            return new UTF8Encoding(false, true).GetBytes("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<assembly manifestVersion=\"1.0\"><assemblyIdentity type=\"win32\" version=\"1.0.0.0\" " +
                "name=\"Scientific.Security.TraceControl." + run + "\"/></assembly>\n");
        }
        static ActCtx TraceControlContext(string path)
        { return new ActCtx { size = 56, source = path }; }
        static void ExecuteTraceControl(Func<IDisposable> acquire, TraceCreate create, Action<IntPtr> release,
            Action<IDisposable> readback, Action deadline, Action emit)
        {
            IDisposable held = null; IntPtr handle = Native.InvalidHandle; Exception primary = null;
            var failures = new List<Exception>();
            try {
                deadline(); held = acquire(); SxsTraceSession.Need(held != null); readback(held); deadline();
                uint error; handle = create(out error);
                SxsTraceSession.Need(handle == Native.InvalidHandle && error == 14001); deadline();
            }
            catch (Exception error) { primary = error; }
            finally {
                if (handle != IntPtr.Zero && handle != Native.InvalidHandle) Attempt(failures, () => release(handle));
                // Readback and close remain independent even after native, deadline or release failure.
                Attempt(failures, deadline);
                if (held != null) {
                    Attempt(failures, () => readback(held));
                    Attempt(failures, held.Dispose);
                }
                Attempt(failures, deadline);
            }
            if (primary != null) failures.Insert(0, primary);
            if (failures.Count != 0) throw new AggregateException("fixed SxS collector control failed", failures);
            emit(); deadline();
        }
        internal static void ObserveTraceControl(string run, string path, Action<byte[]> create, Action qualify)
        {
            byte[] bytes = null;
            try {
                var clock = Stopwatch.StartNew(); RequirePreparationHost(); SxsTraceCapture.RequireCollector(path);
                SxsTraceSession.Need(IntPtr.Size == 8 && Marshal.SizeOf(typeof(ActCtx)) == 56);
                bytes = TraceControlBytes(run); Deadline(clock);
                ExecuteTraceControl(() => {
                    create(bytes); RequirePreparationHost(); qualify(); Deadline(clock);
                    return ModuleActivationFixture.Open(path);
                }, (out uint error) => {
                    RequirePreparationHost(); ActCtx context = TraceControlContext(path);
                    IntPtr handle = CreateActCtxW(ref context);
                    error = handle == Native.InvalidHandle ? unchecked((uint)Marshal.GetLastWin32Error()) : 0;
                    return handle;
                }, ReleaseActCtx, held => {
                    RequirePreparationHost(); qualify(); ModuleActivationFixture.Same((FileStream)held, bytes);
                }, () => Deadline(clock), () => {
                    Console.Out.WriteLine("WINDOWS_SXS_CONTROL context=host expected_failure=True win32_error=14001 " +
                        "collector_recording_verified=False child_visibility_claimed=False cause_claimed=False");
                    Console.Out.Flush();
                });
            }
            catch (Exception error) { throw SxsTraceSession.Safe(error, "collector-control"); }
            finally { if (bytes != null) Array.Clear(bytes, 0, bytes.Length); }
        }
    }
}
