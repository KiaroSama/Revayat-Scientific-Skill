using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace ScientificSecurity
{
    // One private default-security event and a fresh access check, never startup-object evidence.
    public static class DefaultDaclControl
    {
        [StructLayout(LayoutKind.Sequential)] struct Name { internal ushort length, maximum; internal IntPtr buffer; }
        [StructLayout(LayoutKind.Sequential)] struct Attributes {
            internal uint length; internal IntPtr root, name; internal uint flags; internal IntPtr descriptor, qos;
        }
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true)]
        static extern bool GetAppContainerNamedObjectPath(IntPtr token, IntPtr sid, uint capacity, IntPtr path, out uint returned);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool DuplicateTokenEx(
            IntPtr token, uint access, IntPtr attributes, int level, int kind, out IntPtr duplicate);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool ImpersonateLoggedOnUser(IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool RevertToSelf();
        [DllImport("ntdll.dll")] static extern int NtCreateEvent(out IntPtr handle, uint access, ref Attributes attributes,
            int type, [MarshalAs(UnmanagedType.U1)] bool initial);
        [DllImport("ntdll.dll")] static extern int NtOpenEvent(out IntPtr handle, uint access, ref Attributes attributes);
        [DllImport("ntdll.dll")] static extern int NtQuerySecurityObject(IntPtr handle, uint info, IntPtr data, uint size, out uint returned);
        [DllImport("ntdll.dll")] static extern int NtClose(IntPtr handle);
        const int Denied = unchecked((int)0xC0000022);
        static void Need(bool value, [System.Runtime.CompilerServices.CallerLineNumber] int source = 0)
        { if (!value) throw new InvalidOperationException("child default-DACL contract failed component=control source_check=" + source); }
        static void NativeResult(bool value, int status, [System.Runtime.CompilerServices.CallerLineNumber] int source = 0)
        {
            if (!value) throw new InvalidOperationException("child default-DACL contract failed component=control source_check=" + source +
                " native_status=0x" + unchecked((uint)status).ToString("X8"));
        }
        static bool Valid(IntPtr handle) { return handle != IntPtr.Zero && handle != Native.InvalidHandle; }
        static void Deadline(Stopwatch clock)
        { if (clock.Elapsed.TotalSeconds > 10) throw new TimeoutException("child default-security preparation exceeded 10 seconds"); }
        static void Attempt(List<Exception> failures, Action action)
        { try { action(); } catch (Exception failure) { failures.Add(failure); } }
        static void Finish(Exception primary, params Action[] actions)
        {
            var failures = new List<Exception>();
            foreach (Action action in actions) Attempt(failures, action);
            if (failures.Count == 0) return;
            if (primary != null) failures.Insert(0, primary);
            throw new AggregateException("child default-security operation/cleanup failed", failures);
        }
        static void NativeClose(ref IntPtr handle)
        {
            IntPtr owned = handle; handle = IntPtr.Zero;
            if (Valid(owned)) { int status = NtClose(owned); NativeResult(status == 0, status); }
        }
        static void TokenClose(ref IntPtr handle)
        {
            IntPtr owned = handle; handle = IntPtr.Zero;
            if (Valid(owned)) Native.Check(Native.CloseHandle(owned), "close child default-security token");
        }
        static void EqualDefault(IntPtr token, byte[] expected)
        {
            byte[] actual = ChildDefaultDacl.Read(token);
            try { ChildDefaultDacl.RequireEqual(expected, actual); }
            finally { Array.Clear(actual, 0, actual.Length); }
        }
        static string DecodePath(byte[] buffer, uint returned)
        {
            Need(buffer != null && buffer.Length == 4096 && returned > 0 && returned <= 2048);
            int end = 0;
            while (end < buffer.Length && (buffer[end] != 0 || buffer[end + 1] != 0)) end += 2;
            Need(end > 2 && end < buffer.Length);
            // The docs do not define successful ReturnLength terminator accounting; use the actual bounded NUL.
            return new UnicodeEncoding(false, false, true).GetString(buffer, 0, end);
        }
        static string ObjectName(string path, uint returned, string suffix)
        {
            Need(path != null && path.Length > 1 && path.Length < 2048 && returned > 0 && returned <= 2048 &&
                path[0] == '\\' && path[path.Length - 1] != '\\' && !path.Contains("\\\\") &&
                suffix != null && suffix.Length == 32);
            foreach (char item in path) Need(item >= 32 && item != 127 && item != '\0');
            foreach (char item in suffix) Need(item >= '0' && item <= '9' || item >= 'a' && item <= 'f');
            return path + "\\ScientificDefaultDacl-" + suffix;
        }
        static bool Opened(int status, IntPtr opened, IntPtr created)
        {
            Need(Valid(created));
            NativeResult(status == 0 ? Valid(opened) && opened != created : status == Denied && opened == IntPtr.Zero, status);
            return status == 0;
        }
        static void RequireObjectPolicy(byte[] descriptor, SecurityIdentifier user, byte[] prepared)
        {
            Need(descriptor != null && descriptor.Length >= 20 && descriptor.Length <= 65536);
            var sd = new RawSecurityDescriptor(descriptor, 0);
            Need((sd.ControlFlags & (ControlFlags.SelfRelative | ControlFlags.DiscretionaryAclPresent)) ==
                (ControlFlags.SelfRelative | ControlFlags.DiscretionaryAclPresent) && sd.Owner != null && sd.Owner.Equals(user) &&
                sd.DiscretionaryAcl != null);
            ChildDefaultDacl.RequireEqual(ChildDefaultDacl.EventPolicy(prepared), ChildDefaultDacl.Binary(sd.DiscretionaryAcl));
        }
        static bool Event(IntPtr token, SecurityIdentifier user, byte[] prepared, RegistryContext context, Stopwatch clock)
        {
            IntPtr text = IntPtr.Zero, name = IntPtr.Zero, created = IntPtr.Zero, opened = IntPtr.Zero, buffer = IntPtr.Zero, pathBuffer = IntPtr.Zero;
            Exception primary = null;
            try {
                Deadline(clock); context.RequireThread();
                pathBuffer = Marshal.AllocHGlobal(4096); uint returned;
                for (int index = 0; index < 4096; index += 2) Marshal.WriteInt16(pathBuffer, index, -1);
                Native.Check(GetAppContainerNamedObjectPath(token, IntPtr.Zero, 2048, pathBuffer, out returned), "resolve exact child private object path");
                byte[] pathBytes = new byte[4096]; string full;
                try {
                    Marshal.Copy(pathBuffer, pathBytes, 0, pathBytes.Length);
                    full = ObjectName(DecodePath(pathBytes, returned), returned, Guid.NewGuid().ToString("N"));
                } finally { Array.Clear(pathBytes, 0, pathBytes.Length); }
                text = Marshal.StringToHGlobalUni(full); name = Marshal.AllocHGlobal(16);
                Marshal.StructureToPtr(new Name { length = checked((ushort)(full.Length * 2)),
                    maximum = checked((ushort)(full.Length * 2 + 2)), buffer = text }, name, false);
                var attributes = new Attributes { length = 48, name = name };
                Deadline(clock); context.RequireThread();
                int status = NtCreateEvent(out created, 0x20002, ref attributes, 0, false);
                NativeResult(status == 0 && Valid(created), status); context.RequireThread(); Deadline(clock);
                buffer = Marshal.AllocHGlobal(65536);
                status = NtQuerySecurityObject(created, 5, buffer, 65536, out returned);
                NativeResult(status == 0 && returned >= 20 && returned <= 65536, status);
                byte[] bytes = new byte[returned];
                try { Marshal.Copy(buffer, bytes, 0, bytes.Length); RequireObjectPolicy(bytes, user, prepared); }
                finally { Array.Clear(bytes, 0, bytes.Length); }
                context.RequireThread(); Deadline(clock);
                status = NtOpenEvent(out opened, 2, ref attributes);
                bool result = Opened(status, opened, created);
                context.RequireThread(); Deadline(clock); return result;
            }
            catch (Exception failure) { primary = failure; throw; }
            finally {
                if (opened == created) opened = IntPtr.Zero; // An inconsistent alias is refused, never closed twice.
                Finish(primary, () => NativeClose(ref opened), () => NativeClose(ref created),
                    () => { if (buffer != IntPtr.Zero) { for (int index = 0; index < 65536; index += 8) Marshal.WriteInt64(buffer, index, 0); Marshal.FreeHGlobal(buffer); } },
                    () => { if (name != IntPtr.Zero) Marshal.FreeHGlobal(name); },
                    () => { if (text != IntPtr.Zero) Marshal.FreeHGlobal(text); },
                    () => { if (pathBuffer != IntPtr.Zero) { try { for (int index = 0; index < 4096; index += 8) Marshal.WriteInt64(pathBuffer, index, 0); } finally { Marshal.FreeHGlobal(pathBuffer); } } });
            }
        }
        static void FinishContext(Exception primary, bool impersonating, Func<bool> revert, Action fatal, params Action[] actions)
        {
            if (impersonating) {
                bool reverted;
                try { reverted = revert(); } catch { fatal(); throw; }
                if (!reverted) { fatal(); throw new InvalidOperationException("child default-security identity was not restored"); }
            }
            Finish(primary, actions);
        }
        internal static bool Prepare(Native.ProcessInfo child, string package, bool changed, Stopwatch clock, out byte[] baseline)
        {
            baseline = null;
            using (WindowsIdentity current = WindowsIdentity.GetCurrent(true)) Need(current == null);
            Need(IntPtr.Size == 8 && Marshal.SizeOf(typeof(Name)) == 16 && Marshal.SizeOf(typeof(Attributes)) == 48);
            IntPtr token = IntPtr.Zero, duplicate = IntPtr.Zero;
            byte[] before = null, prepared = null; bool impersonating = false; Exception primary = null;
            try {
                Need(clock != null && clock.IsRunning); Deadline(clock);
                Native.Check(Native.OpenProcessToken(child.process, 0x8A, out token), "open suspended child default-security token");
                Need(Valid(token)); before = ChildDefaultDacl.Read(token); var user = ChildDefaultDacl.User(token);
                // Validate the same finite policy on every leg, even when no setter runs.
                byte[] candidate = ChildDefaultDacl.WithUser(before, user);
                prepared = changed ? candidate : (byte[])before.Clone();
                if (!changed) Array.Clear(candidate, 0, candidate.Length);
                if (changed) ChildDefaultDacl.Set(token, prepared);
                EqualDefault(token, prepared); Deadline(clock);
                Native.Check(DuplicateTokenEx(token, 0xC, IntPtr.Zero, 2, 2, out duplicate), "duplicate prepared default-security context");
                Need(Valid(duplicate)); var context = new RegistryContext(token, duplicate, package);
                EqualDefault(duplicate, prepared); Deadline(clock);
                Native.Check(ImpersonateLoggedOnUser(duplicate), "enter exact child default-security context");
                impersonating = true; context.RequireThread();
                bool opened = Event(token, user, prepared, context, clock);
                Need(!changed || opened); context.RequireThread(); Deadline(clock);
                baseline = (byte[])before.Clone(); return opened;
            }
            catch (Exception failure) { primary = failure; throw; }
            finally {
                FinishContext(primary, impersonating, RevertToSelf,
                    () => Environment.FailFast("Child default-security reversion failed; outer owner must reap and recover."),
                    () => { if (primary == null && prepared != null) { EqualDefault(token, prepared); Deadline(clock); } },
                    () => TokenClose(ref duplicate), () => TokenClose(ref token),
                    () => { if (before != null) Array.Clear(before, 0, before.Length); },
                    () => { if (prepared != null) Array.Clear(prepared, 0, prepared.Length); });
            }
        }
        static byte[] Descriptor(SecurityIdentifier owner, RawAcl acl)
        {
            var descriptor = new RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent | ControlFlags.SelfRelative,
                owner, owner, null, acl);
            byte[] bytes = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(bytes, 0); return bytes;
        }
        public static void CheckValidation()
        {
            string firstFailure = null, secondFailure = null, native = null;
            try { Need(false); } catch (InvalidOperationException error) { firstFailure = error.Message; }
            try { Need(false); } catch (InvalidOperationException error) { secondFailure = error.Message; }
            try { NativeResult(false, Denied, 73); } catch (InvalidOperationException error) { native = error.Message; }
            Need(firstFailure != secondFailure && System.Text.RegularExpressions.Regex.IsMatch(firstFailure,
                @"^child default-DACL contract failed component=control source_check=[1-9][0-9]{0,3}$") &&
                native == "child default-DACL contract failed component=control source_check=73 native_status=0xC0000022");
            native = null;
            try { Opened(Denied, new IntPtr(2), new IntPtr(1)); }
            catch (InvalidOperationException error) { native = error.Message; }
            Need(System.Text.RegularExpressions.Regex.IsMatch(native,
                @"^child default-DACL contract failed component=control source_check=[1-9][0-9]{0,3} native_status=0xC0000022$"));
            Need(Opened(0, new IntPtr(2), new IntPtr(1)) && !Opened(Denied, IntPtr.Zero, new IntPtr(1)));
            const string path = "\\Sessions\\1\\AppContainerNamedObjects\\fixed";
            Need(ObjectName(path, (uint)path.Length + 1, new string('a', 32)).EndsWith(new string('a', 32), StringComparison.Ordinal));
            foreach (Action invalid in new Action[] {
                () => Opened(0, IntPtr.Zero, new IntPtr(1)), () => Opened(0, new IntPtr(1), new IntPtr(1)),
                () => Opened(Denied, new IntPtr(2), new IntPtr(1)), () => Opened(1, IntPtr.Zero, new IntPtr(1)),
                () => ObjectName("relative", 8, new string('a', 32)),
                () => ObjectName("\\path\\", 7, new string('a', 32)),
                () => ObjectName("\\private\nsentinel", 18, new string('a', 32)),
                () => ObjectName("\\path", 2049, new string('a', 32))
            }) {
                bool refused = false; try { invalid(); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            byte[] pathBytes = new byte[4096];
            for (int index = 0; index < pathBytes.Length; index++) pathBytes[index] = 255;
            byte[] literal = Encoding.Unicode.GetBytes("\\private\\fixed\0"); literal.CopyTo(pathBytes, 0);
            Need(DecodePath(pathBytes, 14) == "\\private\\fixed" && DecodePath(pathBytes, 15) == "\\private\\fixed");
            foreach (int mode in new [] { 0, 1, 2, 3 }) {
                byte[] bad = new byte[4096];
                if (mode == 1) for (int index = 0; index < bad.Length; index++) bad[index] = 255;
                if (mode >= 2) literal.CopyTo(bad, 0);
                bool refused = false;
                try { DecodePath(bad, mode == 2 ? 0U : (mode == 3 ? 2049U : 1U)); }
                catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            var user = new SecurityIdentifier("S-1-5-21-1-2-3-500");
            var other = new SecurityIdentifier("S-1-15-2-3");
            var acl = new RawAcl(2, 2);
            acl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x10000000, user, false, null));
            acl.InsertAce(1, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 2, other, false, null));
            byte[] prepared = ChildDefaultDacl.Binary(acl);
            // Independent event-specific expected masks, not EventPolicy's own output as the oracle.
            var mapped = new RawAcl(2, 2);
            mapped.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x1F0003, user, false, null));
            mapped.InsertAce(1, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 2, other, false, null));
            byte[] bytes = Descriptor(user, mapped); RequireObjectPolicy(bytes, user, prepared);
            foreach (int mode in new [] { 0, 1, 2, 3 }) {
                var wrong = new RawAcl(ChildDefaultDacl.Binary(mapped), 0);
                if (mode == 0) wrong[0] = new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 2, user, false, null);
                if (mode == 1) wrong.RemoveAce(1);
                if (mode == 2) wrong.InsertAce(2, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 1, other, false, null));
                if (mode == 3) { GenericAce first = wrong[0]; wrong[0] = wrong[1]; wrong[1] = first; }
                bool refused = false;
                try { RequireObjectPolicy(Descriptor(user, wrong), user, prepared); }
                catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            var order = new List<string>();
            FinishContext(null, true, () => { order.Add("revert"); return true; },
                () => { throw new InvalidOperationException("unexpected fail-fast"); }, () => order.Add("close"));
            Need(String.Join(",", order) == "revert,close");
            foreach (bool throws in new [] { false, true }) {
                order.Clear(); var fatal = new InvalidOperationException("fixed fatal"); Exception actual = null;
                try {
                    FinishContext(null, true, () => { order.Add("revert"); if (throws) throw fatal; return false; },
                        () => { order.Add("fatal"); throw fatal; }, () => order.Add("close"));
                } catch (Exception error) { actual = error; }
                Need(Object.ReferenceEquals(actual, fatal) && String.Join(",", order) == "revert,fatal");
            }
            foreach (Action invalid in new Action[] {
                () => RequireObjectPolicy(new byte[19], user, prepared),
                () => RequireObjectPolicy(bytes, new SecurityIdentifier("S-1-5-32-546"), prepared),
                () => { byte[] changed = (byte[])bytes.Clone(); changed[0] = 0; RequireObjectPolicy(changed, user, prepared); }
            }) {
                bool refused = false; try { invalid(); } catch (ArgumentException) { refused = true; }
                catch (InvalidOperationException) { refused = true; } Need(refused);
            }
            var failure = new InvalidOperationException("fixed primary"); int attempts = 0; AggregateException caught = null;
            try { Finish(failure, () => { attempts++; throw new InvalidOperationException("fixed close"); }, () => attempts++); }
            catch (AggregateException error) { caught = error; }
            Need(attempts == 2 && caught != null && caught.InnerExceptions.Count == 2 && Object.ReferenceEquals(caught.InnerExceptions[0], failure));
        }
    }
}
