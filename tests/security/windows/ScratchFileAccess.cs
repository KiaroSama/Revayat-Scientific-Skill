using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace ScientificSecurity
{
    // Create-only evidence on one owned leaf; never a replacement for ordinary admission.
    public static partial class ScratchAccess
    {
        sealed class FileCreationObservation
        {
            internal IntPtr handle, pin;
            internal uint error;
            internal FileInformation identity;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetFileAttributesW(string path);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetFileInformationByHandle(IntPtr handle, int kind, ref byte information, uint bytes);
        delegate IntPtr FileCreateCall(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
        static void FileCreateRequest(string path, FileCreationObservation value, FileCreateCall create, Func<int> lastError)
        {
            value.handle = create(path, 0x40000000, 3, IntPtr.Zero, 1, 0x80, IntPtr.Zero);
            value.error = Valid(value.handle) ? 0U : unchecked((uint)lastError());
        }
        static void FileAbsent(string path)
        {
            uint attributes = GetFileAttributesW(path);
            int error = attributes == UInt32.MaxValue ? Marshal.GetLastWin32Error() : 0;
            RequireFileAbsent(attributes, error);
        }
        static void RequireFileAbsent(uint attributes, int error)
        { Need(attributes == UInt32.MaxValue && error == 2); }
        static uint FileCreation(bool host, Action<FileCreationObservation> create, Action enter, Action check, Action leave,
            Action<FileCreationObservation> bind, Action<IntPtr> close, Action<FileCreationObservation> remove,
            Action absent, Action<FileCreationObservation> release)
        {
            var value = new FileCreationObservation(); bool entered = false;
            Exception primary = null; var failures = new List<Exception>();
            try {
                absent(); enter(); entered = true; check(); create(value); check();
                Need(Valid(value.handle) ? value.error == 0 : value.handle == Native.InvalidHandle && value.error == 5);
                Need(!host || Valid(value.handle));
            }
            catch (Exception error) { primary = error; }
            finally {
                if (entered) leave();
                bool bound = false, closed = false, removed = false;
                if (Valid(value.handle)) {
                    Attempt(failures, () => { bind(value); bound = true; });
                    Attempt(failures, () => { close(value.handle); closed = true; });
                    if (bound && closed) Attempt(failures, () => { remove(value); removed = true; });
                }
                Attempt(failures, () => release(value));
                if (removed || !Valid(value.handle) && primary == null) Attempt(failures, absent);
            }
            Finish(primary, failures); return value.error;
        }
        static void BindCreatedFile(string path, FileInformation root, FileCreationObservation value)
        {
            value.pin = CreateFileW(path, 0x80, 7, IntPtr.Zero, 3, 0x200000, IntPtr.Zero);
            Native.Check(Valid(value.pin), "pin created scratch comparison file");
            RequirePlain(value.pin, false); value.identity = Identity(value.pin);
            Need(value.identity.volume == root.volume);
            Same(value.identity, Identity(value.handle));
        }
        static void RemoveCreatedFile(string path, FileCreationObservation value)
        {
            IntPtr handle = CreateFileW(path, 0x10080, 3, IntPtr.Zero, 3, 0x200000, IntPtr.Zero);
            Native.Check(Valid(handle), "open bound scratch comparison cleanup");
            Exception primary = null; var failures = new List<Exception>();
            try {
                RequirePlain(handle, false); Same(value.identity, Identity(handle));
                Same(value.identity, Identity(value.pin));
                byte remove = 1;
                Native.Check(SetFileInformationByHandle(handle, 4, ref remove, 1), "mark owned scratch comparison file for deletion");
            }
            catch (Exception error) { primary = error; }
            finally { Attempt(failures, () => Native.Check(Native.CloseHandle(handle), "close scratch comparison deletion handle")); }
            Finish(primary, failures);
        }
        static uint[] ObserveFileCreation(string scratch, FileInformation root, IntPtr duplicate, RegistryContext context, Stopwatch clock)
        {
            string path = Path.Combine(scratch, "scratch-file-control");
            var errors = new uint[2];
            for (int role = 0; role < 2; role++) {
                bool host = role == 0;
                errors[role] = FileCreation(host,
                    value => FileCreateRequest(path, value, CreateFileW, Marshal.GetLastWin32Error),
                    () => {
                        Deadline(clock); RequireHostFileCreation();
                        if (!host) Native.Check(ImpersonateLoggedOnUser(duplicate), "enter scratch file comparison context");
                    }, () => { Deadline(clock); if (!host) context.RequireThread(); },
                    () => { if (!host) Revert(); },
                    value => { Deadline(clock); BindCreatedFile(path, root, value); },
                    handle => Native.Check(Native.CloseHandle(handle), "close scratch file comparison handle"),
                    value => RemoveCreatedFile(path, value),
                    () => { Deadline(clock); FileAbsent(path); },
                    value => { if (Valid(value.pin)) Native.Check(Native.CloseHandle(value.pin), "close scratch file metadata pin"); });
            }
            Deadline(clock);
            return errors;
        }
        static string[] FileCreationFrames(string phase, uint[] errors)
        {
            Need(phase == "supported" || phase == "baseline" || phase == "modified" || phase == "restored");
            Need(errors != null && errors.Length == 2 && errors[0] == 0 && (errors[1] == 0 || errors[1] == 5));
            var frames = new string[2];
            for (int role = 0; role < 2; role++) frames[role] = "WINDOWS_SCRATCH_FILE phase=" + phase + " role=" + (role == 0 ? "host" : "lpac") +
                " opened=" + (errors[role] == 0) + " win32_error=0x" + errors[role].ToString("X8") +
                " cleanup_qualified=True contents_written=False cause_claimed=False admission=False";
            return frames;
        }
        static int[] FilePolicyResult(int[] policy, uint[] errors)
        {
            FileCreationFrames("baseline", errors);
            Need(policy != null && policy.Length == 2 + ScratchVolumeAccess.Masks.Length * 5);
            var result = new int[policy.Length + 2];
            Array.Copy(policy, result, policy.Length);
            result[policy.Length] = unchecked((int)errors[0]);
            result[policy.Length + 1] = unchecked((int)errors[1]);
            return result;
        }
        static List<string> FilePolicyFrames(string phase, int[] result)
        {
            int count = 2 + ScratchVolumeAccess.Masks.Length * 5;
            Need(result != null && result.Length == count + 2);
            var policy = new int[count]; Array.Copy(result, policy, count);
            var frames = ScratchVolumeAccess.Frames(phase, policy);
            frames.AddRange(FileCreationFrames(phase, new uint[] { unchecked((uint)result[count]), unchecked((uint)result[count + 1]) }));
            return frames;
        }
        static bool RejectFilePolicy(int[] result)
        {
            Need(result != null && result.Length == 4 + ScratchVolumeAccess.Masks.Length * 5);
            for (int i = 0; i < ScratchVolumeAccess.Masks.Length; i++)
                if ((ScratchVolumeAccess.Masks[i] & 0xC0003) != 0 && result[2 + i] == 0) return true;
            return false;
        }
        static void RequireHostFileCreation()
        { using (WindowsIdentity current = WindowsIdentity.GetCurrent(true)) Need(current == null); }
        public static void CheckFileCreationValidation()
        {
            int count = ScratchVolumeAccess.Masks.Length;
            var policy = new int[2 + count * 5];
            for (int i = 0; i < count; i++) policy[2 + i] = unchecked((int)0xC0000022);
            foreach (uint fileError in new uint[] { 0, 5 }) {
                int[] result = FilePolicyResult(policy, new uint[] { 0, fileError });
                Need(result.Length == policy.Length + 2 && !RejectFilePolicy(result));
                foreach (string phase in new [] { "baseline", "modified", "restored" }) {
                    List<string> frames = FilePolicyFrames(phase, result);
                    Need(frames.Count == count + 2 && frames[count].Contains("phase=" + phase + " role=host opened=True") &&
                        frames[count + 1].Contains("phase=" + phase + " role=lpac opened=" + (fileError == 0)));
                }
                for (int i = 1; i < count; i++) {
                    int[] changed = (int[])result.Clone(); changed[2 + i] = 0;
                    changed[2 + count + i] = unchecked((int)ScratchVolumeAccess.Masks[i]);
                    Need(RejectFilePolicy(changed) == ((ScratchVolumeAccess.Masks[i] & 0xC0003) != 0));
                }
            }
            foreach (uint[] errors in new [] { new uint[0], new uint[] { 0 }, new uint[] { 5, 5 }, new uint[] { 0, 2 } }) {
                bool refused = false;
                try { FilePolicyResult(policy, errors); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            for (int mode = 0; mode < 9; mode++) {
                int selected = mode, enters = 0, leaves = 0, closes = 0, deletes = 0, absences = 0;
                var original = new InvalidOperationException("fixed create failure");
                var cleanup = new InvalidOperationException("fixed close failure");
                Exception caught = null; uint result = 0;
                try {
                    result = FileCreation(false, value => {
                        if (selected == 1) { value.handle = Native.InvalidHandle; value.error = 5; return; }
                        value.handle = new IntPtr(17);
                        if (selected == 2) throw original;
                        if (selected == 8) value.error = 5;
                    }, () => enters++, () => { if (selected == 3) throw original; }, () => leaves++,
                    value => { if (selected == 4) throw original; }, handle => {
                        Need(handle == new IntPtr(17)); closes++;
                        if (selected == 5 || selected == 2) throw cleanup;
                    }, value => { deletes++; if (selected == 6) throw cleanup; }, () => {
                        absences++; if (selected == 7) throw original;
                    }, value => { });
                }
                catch (Exception error) { caught = error; }
                Need(enters == (selected == 7 ? 0 : 1) && leaves == enters);
                Need(closes == (selected == 1 || selected == 3 || selected == 7 ? 0 : 1));
                Need(deletes == (selected == 0 || selected == 6 || selected == 8 ? 1 : 0));
                Need((caught == null) == (selected == 0 || selected == 1));
                if (selected == 1) Need(result == 5 && absences == 2);
                if (selected == 2) {
                    var group = caught as AggregateException;
                    Need(group != null && group.InnerExceptions.Count == 2 &&
                        Object.ReferenceEquals(group.InnerExceptions[0], original) &&
                        Object.ReferenceEquals(group.InnerExceptions[1], cleanup));
                }
            }
            foreach (uint attributes in new uint[] { 0, 0x10, 0x400, UInt32.MaxValue })
                foreach (int error in new [] { 0, 2, 3, 5 }) {
                    bool refused = false;
                    try { RequireFileAbsent(attributes, error); } catch (InvalidOperationException) { refused = true; }
                    Need(refused == (attributes != UInt32.MaxValue || error != 2));
                }
            foreach (IntPtr handle in new [] { IntPtr.Zero, Native.InvalidHandle, new IntPtr(17) }) {
                int errors = 0, calls = 0;
                var value = new FileCreationObservation();
                FileCreateRequest("fixed-leaf", value, (path, access, share, security, disposition, flags, template) => {
                    calls++; Need(path == "fixed-leaf" && access == 0x40000000 && share == 3 &&
                        security == IntPtr.Zero && disposition == 1 && flags == 0x80 && template == IntPtr.Zero);
                    return handle;
                }, () => { errors++; return 5; });
                Need(calls == 1 && value.handle == handle && errors == (Valid(handle) ? 0 : 1) &&
                    value.error == (Valid(handle) ? 0U : 5U));
            }
            foreach (bool host in new [] { false, true }) foreach (uint error in new uint[] { 0, 2, 5, 80, 183 }) {
                bool refused = false;
                try { FileCreation(host, value => { value.handle = Native.InvalidHandle; value.error = error; },
                    () => { }, () => { }, () => { }, value => { }, handle => { }, value => { }, () => { }, value => { }); }
                catch (InvalidOperationException) { refused = true; }
                Need(refused == (host || error != 5));
            }
        }
    }
}
