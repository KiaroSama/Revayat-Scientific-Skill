using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;

namespace ScientificSecurity
{
    // Supported-volume qualification reuses the diagnostic's exact token/open/identity seams.
    public static partial class ScratchAccess
    {
        static void RequireSupportedPrivileges(PrivilegeObservation expected)
        {
            Need(expected.inventory.Length == 1 && expected.present && (expected.attributes == 2 || expected.attributes == 3));
        }
        static void RequireSupportedResults(int[] result)
        {
            int count = ScratchVolumeAccess.Masks.Length;
            Need(result != null && result.Length == 2 + count * 5 && result[0] == 0 && result[1] == 0);
            for (int i = 0; i < count; i++) {
                bool synchronize = ScratchVolumeAccess.Masks[i] == 0x100000;
                Need(result[2 + i] == (synchronize ? 0 : unchecked((int)0xC0000022)) &&
                    result[2 + count + i] == (synchronize ? 0x100000 : 0));
            }
        }
        internal static void PrepareSupported(Native.ProcessInfo process, string scratch, string package)
        {
            Need(Path.IsPathFullyQualified(scratch) && Path.GetFullPath(scratch) == Path.GetPathRoot(scratch));
            var items = new [] {
                new DirectoryObservation { path = scratch, label = "root" },
                new DirectoryObservation { path = Path.Combine(scratch, "temp"), label = "temp" }
            };
            IntPtr token = IntPtr.Zero, duplicate = IntPtr.Zero;
            ScratchVolumePolicy lease = null; Exception primary = null; var failures = new List<Exception>();
            string[] fileFrames = null;
            var clock = Stopwatch.StartNew();
            try {
                using (WindowsIdentity current = WindowsIdentity.GetCurrent(true)) Need(current == null);
                foreach (var item in items) { Deadline(clock); Pin(item); }
                Need(items[0].identity.volume == items[1].identity.volume);
                string nativeRoot = NativeNames(scratch, (drive, output) => {
                    uint length = QueryDosDeviceW(drive, output, (uint)output.Length);
                    Native.Check(length != 0, "resolve supported scratch device"); return length;
                })[1];
                Native.Check(Native.OpenProcessToken(process.process, 0xA, out token), "open supported scratch source token");
                Native.Check(DuplicateTokenEx(token, 0xC, IntPtr.Zero, 2, 2, out duplicate), "duplicate supported scratch context");
                var context = new RegistryContext(token, duplicate, package);
                var expected = Privileges(token); RequireSupportedPrivileges(expected); expected.Same(Privileges(duplicate));
                ScratchVolumeAccess.Host(nativeRoot, () => Deadline(clock));
                lease = ScratchAttachment.Policy(scratch, package, true); lease.Install();
                RequireSupportedResults(PolicyProbe(items, nativeRoot, duplicate, context, expected, clock));
                fileFrames = FileCreationFrames("supported", ObserveFileCreation(scratch, items[0].identity, duplicate, context, clock));
                expected.Same(Privileges(token)); expected.Same(Privileges(duplicate)); Deadline(clock);
            }
            catch (Exception failure) { primary = failure; }
            finally {
                foreach (var item in items) {
                    Attempt(failures, () => { if (item.handle != IntPtr.Zero) Same(item.identity, Identity(item.handle)); });
                    Attempt(failures, () => { if (item.handle != IntPtr.Zero) Native.Check(Native.CloseHandle(item.handle), "close supported scratch directory pin"); });
                }
                Attempt(failures, () => { if (duplicate != IntPtr.Zero) Native.Check(Native.CloseHandle(duplicate), "close supported scratch duplicate"); });
                Attempt(failures, () => { if (token != IntPtr.Zero) Native.Check(Native.CloseHandle(token), "close supported scratch source token"); });
            }
            // A failed qualification remains owned by run completion; never restore before Job cleanup.
            Finish(primary, failures);
            foreach (string frame in fileFrames) Console.Out.WriteLine(frame);
            Console.Out.Flush();
            lease.QualifySupported();
        }
        public static void CheckSupportedValidation()
        {
            var result = new int[2 + ScratchVolumeAccess.Masks.Length * 5];
            for (int i = 0; i < ScratchVolumeAccess.Masks.Length; i++)
                result[2 + i] = i == 2 ? 0 : unchecked((int)0xC0000022);
            result[2 + ScratchVolumeAccess.Masks.Length + 2] = 0x100000;
            RequireSupportedResults(result);
            for (int i = 0; i < 2 + ScratchVolumeAccess.Masks.Length * 2; i++) {
                var changed = (int[])result.Clone(); changed[i] ^= 1; bool refused = false;
                try { RequireSupportedResults(changed); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            foreach (int length in new [] { 0, result.Length - 1, result.Length + 1 }) {
                bool refused = false;
                try { RequireSupportedResults(new int[length]); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            foreach (uint attributes in new uint[] { 0, 1, 2, 3, 4, 0x80000002 }) {
                var bytes = new byte[16]; BitConverter.GetBytes(1U).CopyTo(bytes, 0);
                BitConverter.GetBytes(23U).CopyTo(bytes, 4); BitConverter.GetBytes(attributes).CopyTo(bytes, 12);
                bool refused = false;
                try { RequireSupportedPrivileges(Privileges(bytes)); } catch (InvalidOperationException) { refused = true; }
                Need(refused == (attributes != 2 && attributes != 3));
            }
            foreach (byte[] bytes in new [] { new byte[4], new byte[28] }) {
                bool refused = false;
                try { RequireSupportedPrivileges(Privileges(bytes)); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
        }
    }
}
