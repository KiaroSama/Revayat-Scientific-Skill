using System;
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
        internal IntPtr Writer { get; private set; }
        IntPtr reader;
        readonly MemoryStream captured = new MemoryStream();
        readonly Task drain;
        readonly object gate = new object();
        Exception failure;
        internal Capture()
        {
            var attributes = new Native.SecurityAttributes {
                size = (uint)Marshal.SizeOf(typeof(Native.SecurityAttributes)), inherit = 1 };
            IntPtr write;
            Native.Check(Native.CreatePipe(out reader, out write, ref attributes, 4096), "create anonymous capture pipe");
            Writer = write;
            try
            {
                Native.Check(Native.SetHandleInformation(reader, 1, 0), "remove parent pipe-reader inheritance");
                drain = Task.Run((Action)Drain);
            }
            catch { Dispose(); throw; }
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
        internal void CloseWriter()
        {
            if (Writer != IntPtr.Zero) { Native.CloseHandle(Writer); Writer = IntPtr.Zero; }
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
        public void Dispose()
        {
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
