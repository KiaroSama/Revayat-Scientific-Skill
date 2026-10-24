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
        [DllImport("ntdll.dll")] static extern int NtCreateDirectoryObject(out IntPtr handle, uint access, ref Attributes attributes);
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
        static uint Session(IntPtr token)
        {
            IntPtr data = Marshal.AllocHGlobal(4);
            try {
                uint returned;
                Native.Check(Native.GetTokenInformation(token, 12, data, 4, out returned), "query exact child object session");
                Need(returned == 4); return unchecked((uint)Marshal.ReadInt32(data));
            }
            finally { Marshal.WriteInt32(data, 0); Marshal.FreeHGlobal(data); }
        }
        static string ObjectName(string path, uint returned, string suffix, string package, uint session)
        {
            Need(path != null && path.Length > 1 && path.Length < 2048 && returned > 0 && returned <= 2048 &&
                suffix != null && suffix.Length == 32 && package != null);
            var sid = new SecurityIdentifier(package);
            Need(sid.Value == package && package.StartsWith("S-1-15-2-", StringComparison.Ordinal));
            string relative = "AppContainerNamedObjects\\" + package;
            string qualified = "Sessions\\" + session.ToString(System.Globalization.CultureInfo.InvariantCulture) + "\\" + relative;
            Need(path == relative || path == qualified || path == "\\" + qualified);
            foreach (char item in suffix) Need(item >= '0' && item <= '9' || item >= 'a' && item <= 'f');
            return "\\" + qualified + "\\ScientificDefaultDacl-" + suffix;
        }
        const string EventLeaf = "DefaultDaclEvent";
        const uint DirectoryAccess = 0x20006;
        static RawAcl DirectoryAcl(SecurityIdentifier user, SecurityIdentifier package)
        {
            Need(user != null && package != null && !user.Equals(package));
            var acl = new RawAcl(2, 2);
            foreach (SecurityIdentifier sid in new [] { user, package })
                acl.InsertAce(acl.Count, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed,
                    (int)DirectoryAccess, sid, false, null));
            return acl;
        }
        static byte[] DirectoryDescriptor(SecurityIdentifier user, SecurityIdentifier package)
        {
            var sd = new RawSecurityDescriptor(ControlFlags.SelfRelative | ControlFlags.DiscretionaryAclPresent |
                ControlFlags.DiscretionaryAclProtected, user, user, null, DirectoryAcl(user, package));
            Need(sd.BinaryLength >= 20 && sd.BinaryLength <= 512);
            var bytes = new byte[sd.BinaryLength]; sd.GetBinaryForm(bytes, 0); return bytes;
        }
        static void RequireDirectoryPolicy(byte[] descriptor, SecurityIdentifier user, SecurityIdentifier package)
        {
            Need(descriptor != null && descriptor.Length >= 20 && descriptor.Length <= 65536);
            var sd = new RawSecurityDescriptor(descriptor, 0);
            const ControlFlags required = ControlFlags.SelfRelative | ControlFlags.DiscretionaryAclPresent |
                ControlFlags.DiscretionaryAclProtected;
            Need((sd.ControlFlags & required) == required && sd.Owner != null && sd.Owner.Equals(user) &&
                sd.DiscretionaryAcl != null && System.Linq.Enumerable.SequenceEqual(
                    ChildDefaultDacl.Binary(DirectoryAcl(user, package)), ChildDefaultDacl.Binary(sd.DiscretionaryAcl)));
        }
        static Attributes EventAttributes(IntPtr directory, IntPtr name)
        {
            Need(Valid(directory) && name != IntPtr.Zero);
            return new Attributes { length = 48, root = directory, name = name };
        }
        static bool Opened(int status, IntPtr opened, IntPtr created, IntPtr directory = default(IntPtr))
        {
            Need(Valid(created) && created != directory);
            NativeResult(status == 0 ? Valid(opened) && opened != created && opened != directory :
                status == Denied && opened == IntPtr.Zero, status);
            return status == 0;
        }
        static void FinishObjects(Exception primary, IntPtr opened, IntPtr created, IntPtr directory,
            Action<IntPtr> close, params Action[] actions)
        {
            var cleanup = new List<Action>(); var unique = new HashSet<IntPtr>();
            foreach (IntPtr handle in new [] { opened, created, directory }) {
                if (!Valid(handle) || !unique.Add(handle)) continue;
                IntPtr owned = handle; cleanup.Add(() => close(owned));
            }
            cleanup.AddRange(actions); Finish(primary, cleanup.ToArray());
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
        static bool Event(IntPtr token, string package, SecurityIdentifier user, byte[] prepared, RegistryContext context, Stopwatch clock)
        {
            IntPtr text = IntPtr.Zero, name = IntPtr.Zero, created = IntPtr.Zero, opened = IntPtr.Zero,
                directory = IntPtr.Zero, security = IntPtr.Zero, leaf = IntPtr.Zero, leafName = IntPtr.Zero,
                buffer = IntPtr.Zero, pathBuffer = IntPtr.Zero;
            int securityLength = 0; Exception primary = null;
            try {
                Deadline(clock); context.RequireThread();
                pathBuffer = Marshal.AllocHGlobal(4096); uint returned;
                for (int index = 0; index < 4096; index += 2) Marshal.WriteInt16(pathBuffer, index, -1);
                Native.Check(GetAppContainerNamedObjectPath(token, IntPtr.Zero, 2048, pathBuffer, out returned), "resolve exact child private object path");
                byte[] pathBytes = new byte[4096]; string full;
                try {
                    Marshal.Copy(pathBuffer, pathBytes, 0, pathBytes.Length);
                    full = ObjectName(DecodePath(pathBytes, returned), returned, Guid.NewGuid().ToString("N"), package, Session(token));
                } finally { Array.Clear(pathBytes, 0, pathBytes.Length); }
                text = Marshal.StringToHGlobalUni(full); name = Marshal.AllocHGlobal(16);
                Marshal.StructureToPtr(new Name { length = checked((ushort)(full.Length * 2)),
                    maximum = checked((ushort)(full.Length * 2 + 2)), buffer = text }, name, false);
                var packageSid = new SecurityIdentifier(package);
                byte[] input = DirectoryDescriptor(user, packageSid);
                try {
                    securityLength = input.Length; security = Marshal.AllocHGlobal(securityLength);
                    Marshal.Copy(input, 0, security, input.Length);
                } finally { Array.Clear(input, 0, input.Length); }
                var directoryAttributes = new Attributes { length = 48, name = name, descriptor = security };
                Deadline(clock); context.RequireThread();
                int status = NtCreateDirectoryObject(out directory, DirectoryAccess, ref directoryAttributes);
                NativeResult(status == 0 && Valid(directory), status); context.RequireThread(); Deadline(clock);
                buffer = Marshal.AllocHGlobal(65536);
                status = NtQuerySecurityObject(directory, 5, buffer, 65536, out returned);
                NativeResult(status == 0 && returned >= 20 && returned <= 65536, status);
                byte[] bytes = new byte[returned];
                try { Marshal.Copy(buffer, bytes, 0, bytes.Length); RequireDirectoryPolicy(bytes, user, packageSid); }
                finally { Array.Clear(bytes, 0, bytes.Length); }
                context.RequireThread(); Deadline(clock);
                leaf = Marshal.StringToHGlobalUni(EventLeaf); leafName = Marshal.AllocHGlobal(16);
                Marshal.StructureToPtr(new Name { length = (ushort)(EventLeaf.Length * 2),
                    maximum = (ushort)(EventLeaf.Length * 2 + 2), buffer = leaf }, leafName, false);
                var attributes = EventAttributes(directory, leafName);
                status = NtCreateEvent(out created, 0x20002, ref attributes, 0, false);
                NativeResult(status == 0 && Valid(created) && created != directory, status);
                context.RequireThread(); Deadline(clock);
                status = NtQuerySecurityObject(created, 5, buffer, 65536, out returned);
                NativeResult(status == 0 && returned >= 20 && returned <= 65536, status);
                bytes = new byte[returned];
                try { Marshal.Copy(buffer, bytes, 0, bytes.Length); RequireObjectPolicy(bytes, user, prepared); }
                finally { Array.Clear(bytes, 0, bytes.Length); }
                context.RequireThread(); Deadline(clock);
                status = NtOpenEvent(out opened, 2, ref attributes);
                bool result = Opened(status, opened, created, directory);
                context.RequireThread(); Deadline(clock); return result;
            }
            catch (Exception failure) { primary = failure; throw; }
            finally {
                FinishObjects(primary, opened, created, directory, handle => { int status = NtClose(handle); NativeResult(status == 0, status); },
                    () => { if (buffer != IntPtr.Zero) { try { for (int index = 0; index < 65536; index += 8) Marshal.WriteInt64(buffer, index, 0); } finally { Marshal.FreeHGlobal(buffer); } } },
                    () => { if (security != IntPtr.Zero) { try { for (int index = 0; index < securityLength; index++) Marshal.WriteByte(security, index, 0); } finally { Marshal.FreeHGlobal(security); } } },
                    () => { if (leafName != IntPtr.Zero) Marshal.FreeHGlobal(leafName); },
                    () => { if (leaf != IntPtr.Zero) Marshal.FreeHGlobal(leaf); },
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
        static Exception PreparationFailure(string phase, Exception failure)
        { return new InvalidOperationException("child default-security preparation failed phase=" + phase, failure); }
        internal static bool Prepare(Native.ProcessInfo child, string package, bool changed, Stopwatch clock, out byte[] baseline)
        {
            baseline = null;
            using (WindowsIdentity current = WindowsIdentity.GetCurrent(true)) Need(current == null);
            Need(IntPtr.Size == 8 && Marshal.SizeOf(typeof(Name)) == 16 && Marshal.SizeOf(typeof(Attributes)) == 48);
            IntPtr token = IntPtr.Zero, duplicate = IntPtr.Zero;
            byte[] before = null, prepared = null; bool impersonating = false; Exception primary = null;
            string phase = "open-primary";
            try {
                Need(clock != null && clock.IsRunning); Deadline(clock);
                Native.Check(Native.OpenProcessToken(child.process, 0x8A, out token), "open suspended child default-security token");
                Need(Valid(token)); phase = "read-primary"; before = ChildDefaultDacl.Read(token);
                phase = "read-user"; var user = ChildDefaultDacl.User(token);
                // Validate the same finite policy on every leg, even when no setter runs.
                phase = "candidate"; byte[] candidate = ChildDefaultDacl.WithUser(before, user);
                prepared = changed ? candidate : (byte[])before.Clone();
                if (!changed) Array.Clear(candidate, 0, candidate.Length);
                phase = "set-primary"; if (changed) ChildDefaultDacl.Set(token, prepared);
                phase = "primary-readback"; EqualDefault(token, prepared); Deadline(clock);
                phase = "duplicate-context";
                Native.Check(DuplicateTokenEx(token, 0xC, IntPtr.Zero, 2, 2, out duplicate), "duplicate prepared default-security context");
                Need(Valid(duplicate)); var context = new RegistryContext(token, duplicate, package);
                phase = "duplicate-readback"; EqualDefault(duplicate, prepared); Deadline(clock);
                phase = "effective-context";
                Native.Check(ImpersonateLoggedOnUser(duplicate), "enter exact child default-security context");
                impersonating = true; context.RequireThread();
                phase = "event-control"; bool opened = Event(token, package, user, prepared, context, clock);
                Need(!changed || opened); context.RequireThread(); Deadline(clock);
                baseline = (byte[])before.Clone(); return opened;
            }
            catch (Exception failure) { primary = PreparationFailure(phase, failure); throw primary; }
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
        static void CheckDirectoryValidation()
        {
            var user = new SecurityIdentifier("S-1-5-21-1-2-3-500");
            var package = new SecurityIdentifier("S-1-15-2-3");
            // Independent literal rights/control values; no SDDL conversion or native fixture calls.
            var literalAcl = new RawAcl(2, 2);
            literalAcl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x20006, user, false, null));
            literalAcl.InsertAce(1, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x20006, package, false, null));
            var expected = new RawSecurityDescriptor((ControlFlags)0x9004, user, user, null, literalAcl);
            byte[] bytes = new byte[expected.BinaryLength]; expected.GetBinaryForm(bytes, 0);
            RequireDirectoryPolicy(bytes, user, package);
            var built = new RawSecurityDescriptor(DirectoryDescriptor(user, package), 0);
            Need(built.Owner.Equals(user) && built.Group.Equals(user) &&
                (built.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0 &&
                System.Linq.Enumerable.SequenceEqual(ChildDefaultDacl.Binary(expected.DiscretionaryAcl),
                    ChildDefaultDacl.Binary(built.DiscretionaryAcl)));
            for (int mode = 0; mode < 10; mode++) {
                var wrong = new RawSecurityDescriptor(bytes, 0);
                RawAcl acl = wrong.DiscretionaryAcl;
                if (mode == 0) wrong.Owner = package;
                if (mode == 1) wrong.SetFlags(wrong.ControlFlags & ~ControlFlags.DiscretionaryAclProtected);
                if (mode == 2) wrong.DiscretionaryAcl = null;
                if (mode == 3) acl.RemoveAce(1);
                if (mode == 4) acl.InsertAce(2, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x20006, user, false, null));
                if (mode == 5) { GenericAce first = acl[0]; acl[0] = acl[1]; acl[1] = first; }
                if (mode == 6) acl[0] = new CommonAce(AceFlags.ObjectInherit, AceQualifier.AccessAllowed, 0x20006, user, false, null);
                if (mode == 7) acl[1] = new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x20007, package, false, null);
                if (mode == 8) acl[1] = new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x20006, new SecurityIdentifier("S-1-1-0"), false, null);
                if (mode == 9) acl[1] = new CommonAce(AceFlags.Inherited, AceQualifier.AccessAllowed, 0x20006, package, false, null);
                byte[] invalid = new byte[wrong.BinaryLength]; wrong.GetBinaryForm(invalid, 0);
                bool refused = false;
                try { RequireDirectoryPolicy(invalid, user, package); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            Need(EventAttributes(new IntPtr(3), new IntPtr(4)).root == new IntPtr(3) &&
                EventAttributes(new IntPtr(3), new IntPtr(4)).name == new IntPtr(4) &&
                EventAttributes(new IntPtr(3), new IntPtr(4)).descriptor == IntPtr.Zero &&
                EventAttributes(new IntPtr(3), new IntPtr(4)).flags == 0 && EventLeaf == "DefaultDaclEvent");
            bool aliasRefused = false;
            try { Opened(0, new IntPtr(3), new IntPtr(2), new IntPtr(3)); }
            catch (InvalidOperationException) { aliasRefused = true; }
            Need(aliasRefused);
            foreach (bool aliases in new [] { false, true }) {
                var order = new List<long>(); var primary = new InvalidOperationException("fixed primary");
                AggregateException failure = null;
                try {
                    FinishObjects(primary, new IntPtr(aliases ? 3 : 1), new IntPtr(aliases ? 3 : 2), new IntPtr(3),
                        handle => { order.Add(handle.ToInt64()); throw new InvalidOperationException("fixed close"); },
                        () => order.Add(4));
                } catch (AggregateException error) { failure = error; }
                Need(String.Join(",", order) == (aliases ? "3,4" : "1,2,3,4") && failure != null &&
                    Object.ReferenceEquals(failure.InnerExceptions[0], primary) && failure.InnerExceptions.Count == (aliases ? 2 : 4));
            }
        }
        public static void CheckValidation()
        {
            CheckDirectoryValidation();
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
            var originalFailure = new InvalidOperationException("fixed original");
            Exception wrapped = PreparationFailure("read-primary", originalFailure);
            Need(wrapped.Message == "child default-security preparation failed phase=read-primary" &&
                Object.ReferenceEquals(wrapped.InnerException, originalFailure));
            AggregateException wrappedCleanup = null;
            try { Finish(wrapped, () => { throw new InvalidOperationException("fixed cleanup"); }); }
            catch (AggregateException error) { wrappedCleanup = error; }
            Need(wrappedCleanup != null && Object.ReferenceEquals(wrappedCleanup.InnerExceptions[0], wrapped));
            Need(Opened(0, new IntPtr(2), new IntPtr(1)) && !Opened(Denied, IntPtr.Zero, new IntPtr(1)));
            const string package = "S-1-15-2-3", relative = "AppContainerNamedObjects\\S-1-15-2-3";
            const string path = "\\Sessions\\1\\AppContainerNamedObjects\\S-1-15-2-3";
            string suffix = new string('a', 32), expectedName = path + "\\ScientificDefaultDacl-" + suffix;
            foreach (string accepted in new [] { relative, path.Substring(1), path })
                Need(ObjectName(accepted, (uint)accepted.Length + 1, suffix, package, 1) == expectedName);
            Need(ObjectName(relative, (uint)relative.Length + 1, suffix, package, 0) ==
                "\\Sessions\\0\\AppContainerNamedObjects\\S-1-15-2-3\\ScientificDefaultDacl-" + suffix);
            foreach (string rejected in new [] {
                "\\" + relative, "\\" + path, path + "\\", relative + "\\extra", relative + "0",
                "Sessions\\2\\" + relative, "Sessions\\01\\" + relative,
                "Sessions\\+1\\" + relative, "Global\\" + relative, "AppContainerNamedObjects\\..", "relative"
            }) {
                string message = null;
                try { ObjectName(rejected, (uint)rejected.Length + 1, suffix, package, 1); }
                catch (InvalidOperationException error) { message = error.Message; }
                Need(message != null && !message.Contains(package) && !message.Contains(suffix) &&
                    System.Text.RegularExpressions.Regex.IsMatch(message,
                        @"^child default-DACL contract failed component=control source_check=[1-9][0-9]{0,3}$"));
            }
            foreach (Action invalid in new Action[] {
                () => Opened(0, IntPtr.Zero, new IntPtr(1)), () => Opened(0, new IntPtr(1), new IntPtr(1)),
                () => Opened(Denied, new IntPtr(2), new IntPtr(1)), () => Opened(1, IntPtr.Zero, new IntPtr(1)),
                () => ObjectName("relative", 8, suffix, package, 1),
                () => ObjectName("\\path\\", 7, suffix, package, 1),
                () => ObjectName("\\private\nsentinel", 18, suffix, package, 1),
                () => ObjectName(path, 2049, suffix, package, 1),
                () => ObjectName(relative, 0, suffix, package, 1),
                () => ObjectName(relative, 40, new string('g', 32), package, 1),
                () => ObjectName(relative, 40, "a", package, 1)
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
