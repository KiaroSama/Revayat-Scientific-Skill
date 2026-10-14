using System;
using System.Globalization;
using System.IO;

namespace ScientificSecurity
{
    // Fixed same-run file inspection only. The inspected DLL is never loaded or executed here.
    public static class StaticKernelInspection
    {
        static string expectedIdentity;
        public static void RunFixed(string state)
        {
            if (expectedIdentity != null) throw new InvalidOperationException("static KernelBase inspection is already bound for this run");
            string phase = "input-path";
            try {
                NativeFixture.Plain(state);
                string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "kernelbase.dll");
                NativeFixture.Plain(path);
                phase = "held-open";
                using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                    phase = "held-read"; byte[] bytes = ReadHeld(stream);
                    phase = "image"; var image = KernelImage.FromStatic(bytes);
                    phase = "identity"; string identity = image.KernelBaseIdentity();
                    phase = "slice"; var slice = image.EntrySlice();
                    phase = "tool-discovery"; var tools = NativeFixture.CompilerTools(state);
                    string dumpbin = Path.Combine(Path.GetDirectoryName(tools.Item1), "dumpbin.exe"); NativeFixture.Plain(dumpbin);
                    string range = "/RANGE:0x" + slice.Start.ToString("X", CultureInfo.InvariantCulture) + ",0x" +
                        (slice.Start + slice.Length - 1).ToString("X", CultureInfo.InvariantCulture);
                    phase = "tool"; string text = TrustedSetup.Run(dumpbin, new [] { "/NOLOGO", "/NOPDB", "/DISASM:BYTES", range, path }, state);
                    phase = "post-path"; NativeFixture.Plain(path);
                    phase = "posthash"; RequireSame(identity, KernelImage.FromStatic(ReadHeld(stream)).KernelBaseIdentity());
                    phase = "qualifier"; var view = image.QualifyStatic(text);
                    phase = "observation-profile"; image.RequireObservationStatic(view);
                    expectedIdentity = identity; // Bind only after successful post-tool same-held-file and fixed-profile checks.
                    phase = "evidence-output";
                    Console.Out.WriteLine("WINDOWS_STATIC_KERNEL phase=entry-slice module=kernelbase.dll records=" + view.Records +
                        " unsupported_lines=" + view.Unsupported + " evidence=" + (view.Unsupported == 0 ? "qualified-records" : "partial") +
                        " slice_bytes=" + slice.Length + " complete_slice_claimed=False cause_claimed=False abi_claimed=False");
                    Console.Out.Write(view.Text); Console.Out.Flush();
                    phase = "held-close";
                }
            }
            catch (Exception) when (ReportFailurePhase(phase)) { throw; }
            catch (IOException) { throw new InvalidOperationException("static KernelBase held-file inspection I/O failed; details withheld"); }
            catch (UnauthorizedAccessException) { throw new InvalidOperationException("static KernelBase held-file inspection access failed; details withheld"); }
        }
        static bool ReportFailurePhase(string phase)
        {
            Console.Error.WriteLine("WINDOWS_STATIC_KERNEL failure_phase=" + phase); Console.Error.Flush();
            return false; // Observe the fixed stage without catching, replacing or exposing the original exception.
        }
        static byte[] ReadHeld(FileStream stream)
        {
            if (stream.Length < 256 || stream.Length > 16 * 1024 * 1024)
                throw new InvalidOperationException("static KernelBase file exceeds fixed image bound");
            stream.Position = 0; byte[] bytes = new byte[(int)stream.Length]; int offset = 0;
            while (offset < bytes.Length) {
                int read = stream.Read(bytes, offset, Math.Min(65536, bytes.Length - offset));
                if (read == 0) throw new InvalidOperationException("static held KernelBase file read was truncated");
                offset += read;
            }
            if (stream.ReadByte() != -1 || stream.Length != bytes.Length)
                throw new InvalidOperationException("static held KernelBase file length changed");
            return bytes;
        }
        static void RequireSame(string expected, string actual)
        {
            if (String.IsNullOrEmpty(expected) || !String.Equals(expected, actual, StringComparison.Ordinal))
                throw new InvalidOperationException("static KernelBase same-run file identity is unavailable or changed");
        }
        internal static uint BindLoad(KernelImage image)
        {
            RequireSame(expectedIdentity, image.KernelBaseIdentity());
            uint site = image.RequireObservationProfile();
            Console.Out.WriteLine("WINDOWS_STATIC_KERNEL phase=load-binding identity_equal=True fixed_profile=True"); Console.Out.Flush();
            return site;
        }
        public static void CheckValidation()
        {
            byte[] bytes = KernelImage.StaticFixture(); var image = KernelImage.FromStatic(bytes);
            string identity = image.KernelBaseIdentity();
            RequireSame(identity, KernelImage.FromStatic((byte[])bytes.Clone()).KernelBaseIdentity());
            byte[] changed = (byte[])bytes.Clone(); changed[0x700] ^= 1;
            foreach (string invalid in new [] { null, "", identity + " ", KernelImage.FromStatic(changed).KernelBaseIdentity() }) {
                bool refused = false;
                try { RequireSame(identity, invalid); } catch (InvalidOperationException) { refused = true; }
                if (!refused) throw new InvalidOperationException("static same-run image binding accepted a missing or changed identity");
            }
            bool missing = false;
            try { RequireSame(null, identity); } catch (InvalidOperationException) { missing = true; }
            if (!missing) throw new InvalidOperationException("static image binding accepted an absent preparation identity");
        }
    }
}
