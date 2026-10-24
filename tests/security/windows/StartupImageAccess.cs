using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;

namespace ScientificSecurity
{
    // Partial access-boundary differential only. No section view, loader or target execution.
    public static class StartupImageAccess
    {
        [StructLayout(LayoutKind.Sequential)] struct UnicodeString { internal ushort length, maximum; internal IntPtr buffer; }
        [StructLayout(LayoutKind.Sequential)] struct ObjectAttributes {
            internal uint length; internal IntPtr root, name; internal uint attributes; internal IntPtr descriptor, qos;
        }
        [DllImport("ntdll.dll")] static extern int NtCreateSection(out IntPtr section, uint access,
            IntPtr attributes, IntPtr maximum, uint protection, uint flags, IntPtr file);
        [DllImport("ntdll.dll")] static extern int NtOpenSection(out IntPtr section, uint access, ref ObjectAttributes attributes);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool DuplicateTokenEx(
            IntPtr token, uint access, IntPtr attributes, int level, int kind, out IntPtr duplicate);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool ImpersonateLoggedOnUser(IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool RevertToSelf();
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CreateFileW(string path, uint access, uint share, IntPtr attributes, uint disposition, uint flags, IntPtr template);
        static readonly string[] RuntimeFiles = { "python.exe", "python311.dll", "vcruntime140.dll" };
        static readonly string[] SystemFiles = { "ntdll.dll", "kernel32.dll", "kernelbase.dll", "ucrtbase.dll",
            "advapi32.dll", "version.dll", "ws2_32.dll", "bcrypt.dll" };
        static readonly string[] RuntimeLabels = { "python-exe", "python311", "vcruntime140" };

        internal static void Observe(Native.ProcessInfo child, string python, string package)
        {
            CheckValidation();
            using (WindowsIdentity current = WindowsIdentity.GetCurrent(true))
                if (current != null) throw new InvalidOperationException("image differential host context is already impersonating");
            string runtime = Path.GetDirectoryName(python), system = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var paths = new List<Tuple<string, string>>(); var lines = new List<string>();
            var held = new List<FileStream>();
            IntPtr token = IntPtr.Zero, duplicate = IntPtr.Zero; bool impersonating = false;
            var clock = Stopwatch.StartNew();
            try {
                for (int index = 0; index < RuntimeFiles.Length; index++) {
                    string path = Path.Combine(runtime, RuntimeFiles[index]); NativeFixture.Plain(path);
                    var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read); held.Add(stream);
                    byte[] bytes = ReadHeld(stream);
                    try {
                        int apiSets = KernelImage.QualifyPythonImports(bytes, RuntimeLabels[index]);
                        using (var hash = SHA256.Create()) {
                            string digest = BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
                            lines.Add("WINDOWS_STARTUP_IMAGE_IMPORT label=" + RuntimeLabels[index] + " sha256=" + digest +
                                " physical_direct_profile=True api_set_contracts=" + apiSets + " complete_resolution=False");
                        }
                    }
                    finally { Array.Clear(bytes, 0, bytes.Length); }
                    paths.Add(Tuple.Create(RuntimeLabels[index], path));
                }
                foreach (string name in SystemFiles) {
                    string path = Path.Combine(system, name); NativeFixture.Plain(path);
                    paths.Add(Tuple.Create(name, path));
                }
                ObserveMatrix("host", paths, lines, clock);
                Native.Check(Native.OpenProcessToken(child.process, 0xA, out token), "open exact image diagnostic primary token");
                Native.Check(DuplicateTokenEx(token, 0xC, IntPtr.Zero, 2, 2, out duplicate), "duplicate exact image diagnostic token");
                var context = new RegistryContext(token, duplicate, package);
                Native.Check(ImpersonateLoggedOnUser(duplicate), "enter exact image diagnostic LPAC context");
                impersonating = true; context.RequireThread();
                ObserveMatrix("lpac", paths, lines, clock);
                context.RequireThread();
            }
            finally {
                try {
                    try {
                        if (impersonating && !RevertToSelf())
                            Environment.FailFast("Image diagnostic identity restoration failed; outer owner must reap and clean up.");
                    }
                    finally {
                        try { if (duplicate != IntPtr.Zero) Native.Check(Native.CloseHandle(duplicate), "close image diagnostic duplicate token"); }
                        finally {
                            try { if (token != IntPtr.Zero) Native.Check(Native.CloseHandle(token), "close image diagnostic primary token"); }
                            finally {
                                var failures = new List<Exception>();
                                foreach (var stream in held) try { stream.Dispose(); } catch (Exception failure) { failures.Add(failure); }
                                if (failures.Count != 0) throw new AggregateException("held import image cleanup failed", failures);
                            }
                        }
                    }
                }
                finally {
                    foreach (string line in lines) Console.Out.WriteLine(line);
                    Console.Out.Flush();
                }
            }
        }
        static byte[] ReadHeld(FileStream stream)
        {
            if (stream.Length < 256 || stream.Length > 16777216) throw new InvalidOperationException("prepared import image exceeds bound");
            var bytes = new byte[(int)stream.Length]; int offset = 0;
            while (offset < bytes.Length) {
                int read = stream.Read(bytes, offset, Math.Min(65536, bytes.Length - offset));
                if (read == 0) throw new InvalidOperationException("prepared import image is truncated");
                offset += read;
            }
            if (stream.ReadByte() != -1) throw new InvalidOperationException("prepared import image grew");
            return bytes;
        }
        static void Deadline(Stopwatch clock)
        { if (clock.Elapsed.TotalSeconds > 10) throw new TimeoutException("fixed image access differential exceeded 10 seconds"); }
        static void ObserveMatrix(string context, List<Tuple<string, string>> paths, List<string> lines, Stopwatch clock)
        {
            foreach (var item in paths) {
                Deadline(clock);
                IntPtr file = CreateFileW(item.Item2, 0xA0000000, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
                int error = file == Native.InvalidHandle ? Marshal.GetLastWin32Error() : 0;
                bool opened = file != Native.InvalidHandle; IntPtr section = IntPtr.Zero; int? status = null;
                try {
                    if (opened) { status = NtCreateSection(out section, 0xC, IntPtr.Zero, IntPtr.Zero, 2, 0x1000000, file); RequireResult(status.Value, section); }
                    lines.Add("WINDOWS_STARTUP_IMAGE_ACCESS context=" + context + " label=" + item.Item1 +
                        " file_opened=" + opened + " native_error=" + error + " section_attempted=" + status.HasValue +
                        " section_status=" + Status(status) + " view_mapped=False cause_claimed=False");
                    if (context == "host" && (!opened || status.Value < 0))
                        throw new InvalidOperationException("host image-section positive control failed label=" + item.Item1);
                }
                finally {
                    try { if (section != IntPtr.Zero) Native.Check(Native.CloseHandle(section), "close fixed image section"); }
                    finally { if (opened) Native.Check(Native.CloseHandle(file), "close fixed image file"); }
                }
            }
            foreach (string name in SystemFiles) {
                Deadline(clock); IntPtr text = IntPtr.Zero, unicode = IntPtr.Zero, section = IntPtr.Zero;
                try {
                    string path = @"\KnownDlls\" + name;
                    text = Marshal.StringToHGlobalUni(path);
                    unicode = Native.Structure(new UnicodeString { length = checked((ushort)(path.Length * 2)),
                        maximum = checked((ushort)((path.Length + 1) * 2)), buffer = text });
                    var attributes = new ObjectAttributes { length = (uint)Marshal.SizeOf(typeof(ObjectAttributes)), name = unicode, attributes = 0x40 };
                    int status = NtOpenSection(out section, 0xC, ref attributes); RequireResult(status, section);
                    lines.Add("WINDOWS_STARTUP_KNOWN_SECTION context=" + context + " label=" + name + " status=" +
                        Status(status) + " view_mapped=False loader_resolution_claimed=False");
                }
                finally {
                    try { if (section != IntPtr.Zero) Native.Check(Native.CloseHandle(section), "close fixed KnownDLL section"); }
                    finally { if (unicode != IntPtr.Zero) Marshal.FreeHGlobal(unicode); if (text != IntPtr.Zero) Marshal.FreeHGlobal(text); }
                }
            }
            Deadline(clock);
        }
        static void RequireResult(int status, IntPtr handle)
        { if (handle == Native.InvalidHandle || (status >= 0) != (handle != IntPtr.Zero)) throw new InvalidOperationException("native section status/handle are inconsistent"); }
        static string Status(int? status)
        { return status.HasValue ? "0x" + unchecked((uint)status.Value).ToString("X8") : "not-attempted"; }
        public static void CheckValidation()
        {
            if (IntPtr.Size != 8 || Marshal.SizeOf(typeof(UnicodeString)) != 16 || Marshal.SizeOf(typeof(ObjectAttributes)) != 48 ||
                RuntimeFiles.Length != 3 || SystemFiles.Length != 8 || Status(unchecked((int)0xC0000022)) != "0xC0000022" || Status(null) != "not-attempted")
                throw new InvalidOperationException("fixed image differential ABI/format validation failed");
            RequireResult(0, new IntPtr(1)); RequireResult(unchecked((int)0xC0000022), IntPtr.Zero);
            foreach (var input in new [] { Tuple.Create(0, IntPtr.Zero), Tuple.Create(unchecked((int)0xC0000022), new IntPtr(1)) }) {
                bool rejected = false;
                try { RequireResult(input.Item1, input.Item2); } catch (InvalidOperationException) { rejected = true; }
                if (!rejected) throw new InvalidOperationException("inconsistent section status/handle was accepted");
            }
        }
    }
}
