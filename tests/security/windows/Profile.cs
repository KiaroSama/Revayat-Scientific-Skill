using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace ScientificSecurity
{
    public static class Profile
    {
        [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
        static extern int CreateAppContainerProfile(string name, string display, string description, IntPtr capabilities, uint count, out IntPtr sid);
        [DllImport("userenv.dll", CharSet = CharSet.Unicode)] static extern int DeleteAppContainerProfile(string name);
        [DllImport("userenv.dll", CharSet = CharSet.Unicode)] static extern int GetAppContainerFolderPath(string sid, out IntPtr path);
        [DllImport("userenv.dll")] static extern int GetAppContainerRegistryLocation(uint access, out IntPtr key);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr token, int kind, IntPtr buffer, uint bytes, out uint returned);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool DuplicateTokenEx(IntPtr token, uint access, IntPtr attributes, int level, int kind, out IntPtr duplicate);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool ImpersonateLoggedOnUser(IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool RevertToSelf();
        [DllImport("advapi32.dll")] static extern IntPtr FreeSid(IntPtr sid);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr handle);
        static readonly Dictionary<string, RegistryKey> registryRoots = new Dictionary<string, RegistryKey>(StringComparer.Ordinal);
        static readonly HashSet<string> registryReadVerified = new HashSet<string>(StringComparer.Ordinal);
        static readonly Dictionary<string, string> registryNames = new Dictionary<string, string>(StringComparer.Ordinal);
        static readonly Dictionary<string, List<Tuple<RegistryKey, string>>> registryEntries =
            new Dictionary<string, List<Tuple<RegistryKey, string>>>(StringComparer.Ordinal);
        [DllImport("ntdll.dll")] static extern int NtQueryKey(IntPtr key, int kind, IntPtr buffer, uint bytes, out uint returned);
        static string RegistryName(SafeRegistryHandle handle)
        {
            const uint capacity = 4096;
            IntPtr buffer = Marshal.AllocHGlobal((int)capacity); bool retained = false;
            try {
                handle.DangerousAddRef(ref retained);
                uint returned;
                int status = NtQueryKey(handle.DangerousGetHandle(), 3, buffer, capacity, out returned);
                if (status != 0 || returned < 4 || returned > capacity)
                    throw new InvalidOperationException("owned profile registry identity query failed or exceeded fixed bound");
                uint length = unchecked((uint)Marshal.ReadInt32(buffer));
                if (length == 0 || (length & 1) != 0 || length > returned - 4)
                    throw new InvalidOperationException("owned profile registry identity length is invalid");
                byte[] bytes = new byte[length]; Marshal.Copy(IntPtr.Add(buffer, 4), bytes, 0, bytes.Length);
                string name = new System.Text.UnicodeEncoding(false, false, true).GetString(bytes);
                if (name.IndexOf('\0') >= 0)
                    throw new InvalidOperationException("owned profile registry identity contains an embedded terminator");
                return name;
            }
            finally { try { if (retained) handle.DangerousRelease(); } finally { Marshal.FreeHGlobal(buffer); } }
        }
        const RegistryRights ReadOnlyRegistryDeny = RegistryRights.SetValue | RegistryRights.CreateSubKey | RegistryRights.Delete
            | RegistryRights.ChangePermissions | RegistryRights.TakeOwnership;
        public static void CheckRegistryMasks()
        {
            if ((RegistryRights.WriteKey & RegistryRights.ReadKey) != RegistryRights.ReadPermissions ||
                (ReadOnlyRegistryDeny & RegistryRights.ReadKey) != 0)
                throw new InvalidOperationException("registry read-only mask must preserve READ_CONTROL");
            foreach (RegistryRights right in new [] { RegistryRights.SetValue, RegistryRights.CreateSubKey,
                RegistryRights.Delete, RegistryRights.ChangePermissions, RegistryRights.TakeOwnership }) {
                if ((ReadOnlyRegistryDeny & right) != right)
                    throw new InvalidOperationException("registry read-only mask omitted a mutation/authority deny");
            }
            if ((ReadOnlyRegistryDeny & (RegistryRights.QueryValues | RegistryRights.EnumerateSubKeys | RegistryRights.Notify)) != 0)
                throw new InvalidOperationException("registry read-only mask denies advertised read operations");
        }
        static void Check(int result, string operation) { if (result != 0) throw new COMException(operation + " HRESULT=0x" + unchecked((uint)result).ToString("X8"), result); }
        static void CheckNative(bool value, string operation) { if (!value) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), operation); }
        static string ValidName(string name)
        {
            const string prefix = "Scientific.Security.";
            if (name == null || !name.StartsWith(prefix, StringComparison.Ordinal) || name.Length != prefix.Length + 32 ||
                name.Substring(prefix.Length).Any(c => !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))))
                throw new ArgumentException("profile must be this run's unique owned moniker");
            return name;
        }
        static string Folder(string sid)
        {
            IntPtr path; Check(GetAppContainerFolderPath(sid, out path), "obtain owned profile folder");
            try { return Path.GetFullPath(Marshal.PtrToStringUni(path)); }
            finally { Marshal.FreeCoTaskMem(path); }
        }
        static void NoLinks(string path)
        {
            var ancestors = new Stack<string>();
            for (string current = Path.GetFullPath(path); !String.IsNullOrEmpty(current); current = Path.GetDirectoryName(current)) {
                if (ancestors.Count >= 64) throw new InvalidOperationException("profile path exceeds ancestor budget");
                ancestors.Push(current);
            }
            while (ancestors.Count != 0) {
                string current = ancestors.Pop();
                try {
                    if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                        throw new InvalidOperationException("owned profile path/ancestor is a reparse point");
                }
                catch (FileNotFoundException) { }
                catch (DirectoryNotFoundException) { }
            }
        }
        public static string CreateSealed(string name, string expectedSid, string receiptPath)
        {
            ValidName(name); IntPtr sid = IntPtr.Zero;
            NoLinks(Path.GetDirectoryName(receiptPath));
            if (File.Exists(receiptPath)) throw new InvalidOperationException("owned profile receipt already exists");
            string expectedParent = Path.GetFullPath(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Packages", name));
            NoLinks(expectedParent);
            if (Directory.Exists(expectedParent) || File.Exists(expectedParent)) throw new InvalidOperationException("refuse an existing unowned profile storage location");
            bool created = false;
            using (var receipt = new StreamWriter(new FileStream(receiptPath, FileMode.CreateNew), new System.Text.UTF8Encoding(false))) {
                receipt.WriteLine(name); receipt.WriteLine(expectedSid); receipt.WriteLine("intent"); receipt.Flush();
            }
            try {
                int result = CreateAppContainerProfile(name, name, "Owned offline scientific CI profile", IntPtr.Zero, 0, out sid);
                if (result != 0) { File.Delete(receiptPath); Check(result, "create unique zero-capability profile"); }
                created = true;
                // Keep the flushed ownership intent immutable across crash/timeout boundaries.
                string actualSid = new SecurityIdentifier(sid).Value;
                if (actualSid != expectedSid) throw new InvalidOperationException("created profile SID differs from assigned package");
                string folder = Folder(actualSid);
                string expected = Path.GetFullPath(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Packages", name, "AC"));
                // The API's profile path must be the exact new owned package location, never a parent tree.
                if (!String.Equals(folder, expected, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("profile API path is outside its unique owned location");
                NoLinks(folder);
                string packageRoot = Path.GetDirectoryName(folder);
                var entries = new List<string>(); var pending = new Queue<string>(); pending.Enqueue(packageRoot);
                while (pending.Count != 0) {
                    foreach (string entry in Directory.EnumerateFileSystemEntries(pending.Dequeue())) {
                        if (entries.Count >= 256) throw new InvalidOperationException("new profile storage exceeds finite seal budget");
                        NoLinks(entry); entries.Add(entry);
                        if (Path.GetRelativePath(packageRoot, entry).Split(Path.DirectorySeparatorChar).Length > 32)
                            throw new InvalidOperationException("new profile storage exceeds finite depth budget");
                        if (Directory.Exists(entry)) pending.Enqueue(entry);
                    }
                }
                foreach (string entry in entries.OrderByDescending(value => value.Length).Concat(new [] { packageRoot }))
                    SealFile(entry, actualSid);
                Console.Out.WriteLine("WINDOWS_PROFILE sealed=true capabilities=0 entries=" + entries.Count);
                Console.Out.Flush(); return folder;
            }
            catch {
                if (created) Check(DeleteAppContainerProfile(name), "remove newly created profile after preparation failure");
                throw;
            }
            finally { if (sid != IntPtr.Zero) FreeSid(sid); }
        }
        static void SealFile(string path, string sid)
        {
            bool directory = Directory.Exists(path);
            FileSystemSecurity acl = directory ? (FileSystemSecurity)new DirectorySecurity() : new FileSecurity();
            var inherit = directory ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None;
            acl.SetAccessRuleProtection(true, false);
            var user = WindowsIdentity.GetCurrent().User;
            // OFF-SCRATCH profile objects must not inherit the token user's owner shortcut.
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier("S-1-3-4"),
                FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership,
                inherit, PropagationFlags.None, AccessControlType.Deny));
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),
                FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership,
                inherit, PropagationFlags.None, AccessControlType.Deny));
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid), FileSystemRights.ReadAndExecute,
                inherit, PropagationFlags.None, AccessControlType.Allow));
            foreach (SecurityIdentifier identity in new [] { user, new SecurityIdentifier("S-1-5-18"), new SecurityIdentifier("S-1-5-32-544") })
                acl.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            if (directory) FileSystemAclExtensions.SetAccessControl(new DirectoryInfo(path), (DirectorySecurity)acl);
            else FileSystemAclExtensions.SetAccessControl(new FileInfo(path), (FileSecurity)acl);
            FileSystemSecurity actual = directory ? (FileSystemSecurity)FileSystemAclExtensions.GetAccessControl(new DirectoryInfo(path))
                : FileSystemAclExtensions.GetAccessControl(new FileInfo(path));
            if (!SealedAccessMatches(acl, actual)) {
                ReportSealDifference(acl, actual, directory);
                throw new InvalidOperationException("owned profile filesystem seal readback differs");
            }
        }
        static bool SealedAccessMatches(ObjectSecurity expected, ObjectSecurity actual)
        {
            if (!expected.AreAccessRulesProtected || !actual.AreAccessRulesProtected ||
                !expected.AreAccessRulesCanonical || !actual.AreAccessRulesCanonical) return false;
            return AccessMatches(new RawSecurityDescriptor(expected.GetSecurityDescriptorBinaryForm(), 0),
                new RawSecurityDescriptor(actual.GetSecurityDescriptorBinaryForm(), 0));
        }
        static bool AccessMatches(RawSecurityDescriptor expected, RawSecurityDescriptor actual)
        {
            // Windows adds resource-manager DACL auto-inheritance bookkeeping (AI/0x0400).
            // Ignore only that observed flag; protection and every ordered ACL byte must match.
            const ControlFlags bookkeeping = ControlFlags.DiscretionaryAclAutoInherited;
            if ((expected.ControlFlags & ~bookkeeping) != (actual.ControlFlags & ~bookkeeping) ||
                (expected.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0 ||
                (actual.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0 ||
                expected.DiscretionaryAcl == null || actual.DiscretionaryAcl == null) return false;
            var left = new byte[expected.DiscretionaryAcl.BinaryLength];
            var right = new byte[actual.DiscretionaryAcl.BinaryLength];
            expected.DiscretionaryAcl.GetBinaryForm(left, 0);
            actual.DiscretionaryAcl.GetBinaryForm(right, 0);
            return left.SequenceEqual(right);
        }
        // Managed-only comparison check; no native/profile/registry operation.
        public static void CheckSealComparison()
        {
            const string policy = "D:P(D;;WDWO;;;OW)(A;;FR;;;WD)";
            var expected = new RawSecurityDescriptor(policy);
            var actual = new RawSecurityDescriptor(policy);
            actual.SetFlags(actual.ControlFlags | ControlFlags.DiscretionaryAclAutoInherited);
            if (!AccessMatches(expected, actual)) throw new InvalidOperationException("DACL bookkeeping check failed");
            foreach (ControlFlags change in new [] { ControlFlags.DiscretionaryAclProtected,
                ControlFlags.DiscretionaryAclPresent, ControlFlags.DiscretionaryAclAutoInheritRequired,
                ControlFlags.SystemAclAutoInherited }) {
                var changed = new RawSecurityDescriptor(policy);
                changed.SetFlags(changed.ControlFlags ^ change);
                if (AccessMatches(expected, changed)) throw new InvalidOperationException("DACL control difference accepted");
            }
            foreach (string changed in new [] { "D:P(A;;FR;;;WD)", "D:P(D;;WD;;;OW)(A;;FR;;;WD)",
                "D:P(D;;WDWO;;;SY)(A;;FR;;;WD)", "D:P(D;OI;WDWO;;;OW)(A;;FR;;;WD)",
                "D:P(A;;FR;;;WD)(D;;WDWO;;;OW)", "D:P(D;;WDWO;;;OW)(A;;FA;;;WD)" }) {
                if (AccessMatches(expected, new RawSecurityDescriptor(changed)))
                    throw new InvalidOperationException("DACL ordered bytes difference accepted");
            }
        }
        static void ReportSealDifference(FileSystemSecurity expected, FileSystemSecurity actual, bool directory)
        {
            var left = new RawSecurityDescriptor(expected.GetSecurityDescriptorBinaryForm(), 0);
            var right = new RawSecurityDescriptor(actual.GetSecurityDescriptorBinaryForm(), 0);
            int leftCount = left.DiscretionaryAcl == null ? -1 : left.DiscretionaryAcl.Count;
            int rightCount = right.DiscretionaryAcl == null ? -1 : right.DiscretionaryAcl.Count;
            Console.Error.WriteLine("WINDOWS_PROFILE_SEAL_DIFF directory=" + directory + " expected_protected=" + expected.AreAccessRulesProtected
                + " actual_protected=" + actual.AreAccessRulesProtected + " expected_canonical=" + expected.AreAccessRulesCanonical
                + " actual_canonical=" + actual.AreAccessRulesCanonical + " expected_control=" + (int)left.ControlFlags
                + " actual_control=" + (int)right.ControlFlags + " expected_rules=" + leftCount + " actual_rules=" + rightCount);
            int count = Math.Min(Math.Min(Math.Max(leftCount, 0), Math.Max(rightCount, 0)), 16);
            for (int index = 0; index < count; index++) {
                var expectedAce = left.DiscretionaryAcl[index] as KnownAce;
                var actualAce = right.DiscretionaryAcl[index] as KnownAce;
                Console.Error.WriteLine("WINDOWS_PROFILE_ACE_DIFF index=" + index + " expected_type=" + left.DiscretionaryAcl[index].AceType
                    + " actual_type=" + right.DiscretionaryAcl[index].AceType + " expected_flags=" + (int)left.DiscretionaryAcl[index].AceFlags
                    + " actual_flags=" + (int)right.DiscretionaryAcl[index].AceFlags + " expected_mask=" + (expectedAce == null ? -1 : expectedAce.AccessMask)
                    + " actual_mask=" + (actualAce == null ? -1 : actualAce.AccessMask) + " identity_equal=" +
                    (expectedAce != null && actualAce != null && expectedAce.SecurityIdentifier.Equals(actualAce.SecurityIdentifier)));
            }
            Console.Error.Flush();
        }
        internal static void SealRegistry(IntPtr process, string name, string packageSid)
        {
            ValidName(name);
            if (registryRoots.ContainsKey(name)) return;
            IntPtr token = IntPtr.Zero, duplicate = IntPtr.Zero, key = IntPtr.Zero;
            bool impersonating = false;
            SafeRegistryHandle keyHandle = null;
            try {
                CheckNative(OpenProcessToken(process, 0xA, out token), "open actual suspended profile token");
                uint size; GetTokenInformation(token, 31, IntPtr.Zero, 0, out size);
                if (size < IntPtr.Size || size > 65536) throw new InvalidOperationException("profile token identity buffer invalid");
                IntPtr identity = Marshal.AllocHGlobal((int)size);
                try {
                    CheckNative(GetTokenInformation(token, 31, identity, size, out size), "query actual profile package SID");
                    if (new SecurityIdentifier(Marshal.ReadIntPtr(identity)).Value != packageSid)
                        throw new InvalidOperationException("registry seal token is not this run's assigned package");
                }
                finally { Marshal.FreeHGlobal(identity); }
                CheckNative(DuplicateTokenEx(token, 0xC, IntPtr.Zero, 2, 2, out duplicate), "duplicate profile impersonation token");
                CheckNative(ImpersonateLoggedOnUser(duplicate), "enter exact profile identity"); impersonating = true;
                int result = GetAppContainerRegistryLocation(0x20019 | 0x40000, out key);
                if (key != IntPtr.Zero) keyHandle = new SafeRegistryHandle(key, true);
                Check(result, "open actual profile registry for seal");
            }
            catch { if (keyHandle != null) keyHandle.Dispose(); throw; }
            finally {
                try {
                    if (impersonating && !RevertToSelf())
                        Environment.FailFast("Owned profile identity restoration failed; outer owner must reap and clean up.");
                }
                finally {
                    if (duplicate != IntPtr.Zero) CloseHandle(duplicate);
                    if (token != IntPtr.Zero) CloseHandle(token);
                }
            }
            RegistryKey root;
            try { root = RegistryKey.FromHandle(keyHandle); }
            catch { if (keyHandle != null) keyHandle.Dispose(); throw; }
            var entries = new List<Tuple<RegistryKey, string>>();
            bool transferred = false;
            try {
                // Collection owns every handle before identity queries or recursion can throw.
                entries.Add(Tuple.Create(root, (string)null)); root = null;
                CollectRegistry(entries, 0, 0);
                SealRegistryEntries(entries, packageSid, false);
                string identity = entries[0].Item2;
                Console.Out.WriteLine("WINDOWS_PROFILE_REGISTRY sealed=true keys=" + entries.Count); Console.Out.Flush();
                registryRoots.Add(name, entries[0].Item1);
                registryNames.Add(name, identity);
                registryEntries.Add(name, entries);
                transferred = true;
            }
            catch {
                registryRoots.Remove(name); registryNames.Remove(name); registryEntries.Remove(name);
                throw;
            }
            finally {
                try { if (!transferred) CloseRegistryEntries(entries); }
                finally { if (root != null) root.Dispose(); }
            }
        }
        internal static void RequireReadOnlyRegistry(IntPtr process, string name, string packageSid)
        {
            ValidName(name); CheckRegistryMasks();
            try {
                RegistryKey root;
                if (!registryRoots.TryGetValue(name, out root))
                    throw new InvalidOperationException("actual owned registry root must be sealed before access controls");
                string identity;
                if (!registryNames.TryGetValue(name, out identity) ||
                    !String.Equals(RegistryName(root.Handle), identity, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("retained owned profile registry identity changed");
                if (!registryReadVerified.Contains(name)) {
                    RequireRegistryAccess(process, packageSid, identity, false);
                    List<Tuple<RegistryKey, string>> entries;
                    if (!registryEntries.TryGetValue(name, out entries))
                        throw new InvalidOperationException("owned registry pre-seal handles were not retained");
                    SealRegistryEntries(entries, packageSid, true);
                    RequireRegistryAccess(process, packageSid, identity, true);
                    registryReadVerified.Add(name);
                    Console.Out.WriteLine("WINDOWS_PROFILE_REGISTRY_READ_PAIR old_denied=true new_read=true individual_mutations_denied=true keys=" + entries.Count);
                    Console.Out.Flush();
                }
                else RequireRegistryAccess(process, packageSid, identity, true);
            }
            catch (Exception failure) {
                try { CloseOwnedRegistry(name); }
                catch (Exception cleanup) { throw new AggregateException("profile registry control and cleanup failed", failure, cleanup); }
                throw;
            }
        }
        static void RequireRegistryAccess(IntPtr process, string packageSid, string identity, bool readable)
        {
            IntPtr token = IntPtr.Zero, duplicate = IntPtr.Zero;
            bool impersonating = false;
            try {
                CheckNative(OpenProcessToken(process, 0xA, out token), "open actual final profile access token");
                uint size;
                bool initial = GetTokenInformation(token, 31, IntPtr.Zero, 0, out size);
                if (initial || Marshal.GetLastWin32Error() != 122 || size < IntPtr.Size || size > 65536)
                    throw new InvalidOperationException("final profile access token package size is invalid");
                IntPtr package = Marshal.AllocHGlobal((int)size);
                try {
                    uint capacity = size;
                    CheckNative(GetTokenInformation(token, 31, package, capacity, out size), "query final profile access package identity");
                    if (size < IntPtr.Size || size > capacity || Marshal.ReadIntPtr(package) == IntPtr.Zero ||
                        new SecurityIdentifier(Marshal.ReadIntPtr(package)).Value != packageSid)
                        throw new InvalidOperationException("final profile access token is not the owned package");
                }
                finally { Marshal.FreeHGlobal(package); }
                CheckNative(DuplicateTokenEx(token, 0xC, IntPtr.Zero, 2, 2, out duplicate), "duplicate final profile access token");
                CheckNative(ImpersonateLoggedOnUser(duplicate), "enter actual final profile access context"); impersonating = true;
                CheckProfileOpen(0x20019, readable, identity);
                if (readable) foreach (uint access in new uint[] { 2, 4, 0x10000, 0x40000, 0x80000 })
                    CheckProfileOpen(access, false, identity);
            }
            finally {
                try {
                    if (impersonating && !RevertToSelf())
                        Environment.FailFast("Read-only profile identity restoration failed; outer owner must reap and clean up.");
                }
                finally {
                    try { if (duplicate != IntPtr.Zero) CheckNative(CloseHandle(duplicate), "close profile access impersonation token"); }
                    finally { if (token != IntPtr.Zero) CheckNative(CloseHandle(token), "close profile access source token"); }
                }
            }
        }
        static void CheckProfileOpen(uint access, bool allowed, string identity)
        {
            IntPtr key = IntPtr.Zero;
            SafeRegistryHandle handle = null;
            try {
                int result = GetAppContainerRegistryLocation(access, out key);
                if (key != IntPtr.Zero) handle = new SafeRegistryHandle(key, true);
                if (result == 0) {
                    if (handle == null || handle.IsInvalid ||
                        !String.Equals(RegistryName(handle), identity, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("profile registry API opened a different or invalid owned root");
                }
                if (allowed) {
                    Check(result, "open actual read-only profile registry");
                    if (handle == null || handle.IsInvalid)
                        throw new InvalidOperationException("profile registry read returned no valid key");
                }
                else if (unchecked((uint)result) != 0x80070005 || key != IntPtr.Zero)
                    throw new InvalidOperationException("profile registry access negative control was not an explicit kernel denial");
            }
            finally { if (handle != null) handle.Dispose(); }
        }
        static void CollectRegistry(List<Tuple<RegistryKey, string>> entries, int index, int depth)
        {
            if (depth > 32) throw new InvalidOperationException("owned profile registry exceeds finite depth budget");
            RegistryKey key = entries[index].Item1;
            entries[index] = Tuple.Create(key, RegistryName(key.Handle));
            string[] children = key.GetSubKeyNames();
            if (children.Length > 256 - entries.Count)
                throw new InvalidOperationException("owned profile registry exceeds finite handle budget");
            foreach (string child in children) {
                if (entries.Count >= 256) throw new InvalidOperationException("owned profile registry exceeds finite handle budget");
                RegistryKey entry = key.OpenSubKey(child, RegistryKeyPermissionCheck.ReadWriteSubTree,
                    RegistryRights.ReadKey | RegistryRights.ChangePermissions);
                if (entry == null) throw new InvalidOperationException("owned profile registry child is unavailable");
                try { entries.Add(Tuple.Create(entry, (string)null)); }
                catch { entry.Dispose(); throw; }
                CollectRegistry(entries, entries.Count - 1, depth + 1);
            }
        }
        static void SealRegistryEntries(List<Tuple<RegistryKey, string>> entries, string sid, bool readOnly)
        {
            if (entries.Count == 0 || entries.Count > 256)
                throw new InvalidOperationException("owned registry seal handle set exceeds fixed bounds");
            // Reverse depth-first collection is child-before-parent; no reopen after either seal.
            for (int index = entries.Count - 1; index >= 0; index--) {
                var entry = entries[index];
                if (!String.Equals(RegistryName(entry.Item1.Handle), entry.Item2, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("retained owned registry child identity changed");
                SealRegistryKey(entry.Item1, sid, readOnly);
            }
        }
        static void CloseRegistryEntries(List<Tuple<RegistryKey, string>> entries)
        {
            var failures = new List<Exception>();
            for (int index = entries.Count - 1; index >= 0; index--) {
                try { entries[index].Item1.Dispose(); }
                catch (Exception error) { failures.Add(error); }
            }
            entries.Clear();
            if (failures.Count != 0) throw new AggregateException("owned registry handle cleanup failed", failures);
        }
        static void SealRegistryKey(RegistryKey key, string sid, bool readOnly)
        {
            var acl = new RegistrySecurity(); acl.SetAccessRuleProtection(true, false);
            acl.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier("S-1-3-4"),
                RegistryRights.ChangePermissions | RegistryRights.TakeOwnership,
                InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Deny));
            acl.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier(sid),
                readOnly ? ReadOnlyRegistryDeny : RegistryRights.WriteKey | RegistryRights.ChangePermissions | RegistryRights.TakeOwnership,
                InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Deny));
            acl.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier(sid), RegistryRights.ReadKey,
                InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
            foreach (SecurityIdentifier identity in new [] { WindowsIdentity.GetCurrent().User, new SecurityIdentifier("S-1-5-18"), new SecurityIdentifier("S-1-5-32-544") })
                acl.AddAccessRule(new RegistryAccessRule(identity, RegistryRights.FullControl,
                    InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
            key.SetAccessControl(acl);
            RegistrySecurity actual = key.GetAccessControl(AccessControlSections.Access);
            if (!SealedAccessMatches(acl, actual))
                throw new InvalidOperationException("owned profile registry seal readback differs");
        }
        static void CloseOwnedRegistry(string name)
        {
            registryReadVerified.Remove(name); registryNames.Remove(name);
            RegistryKey root; List<Tuple<RegistryKey, string>> entries;
            bool hasRoot = registryRoots.TryGetValue(name, out root);
            bool hasEntries = registryEntries.TryGetValue(name, out entries);
            registryRoots.Remove(name); registryEntries.Remove(name);
            if (hasEntries) CloseRegistryEntries(entries);
            else if (hasRoot) root.Dispose();
        }
        public static void DeleteOwned(string name, string receiptPath)
        {
            ValidName(name);
            if (!File.Exists(receiptPath)) return;
            NoLinks(receiptPath);
            string[] receipt = File.ReadAllLines(receiptPath, System.Text.Encoding.UTF8);
            if (receipt.Length != 3 || receipt[0] != name || !receipt[1].StartsWith("S-1-15-2-", StringComparison.Ordinal)
                || (receipt[2] != "created" && receipt[2] != "intent"))
                throw new InvalidOperationException("profile cleanup ownership receipt does not match this run");
            try { CloseOwnedRegistry(name); }
            finally { Check(DeleteAppContainerProfile(name), "delete only the owned profile after worker reaping"); }
        }
    }
}
