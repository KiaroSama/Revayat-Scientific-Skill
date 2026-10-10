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
            if (!actual.AreAccessRulesProtected || actual.GetSecurityDescriptorSddlForm(AccessControlSections.Access)
                != acl.GetSecurityDescriptorSddlForm(AccessControlSections.Access)) {
                ReportSealDifference(acl, actual, directory);
                throw new InvalidOperationException("owned profile filesystem seal readback differs");
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
            try {
                int count = 0;
                SealRegistryTree(root, packageSid, ref count);
                registryRoots.Add(name, root); root = null;
                Console.Out.WriteLine("WINDOWS_PROFILE_REGISTRY sealed=true keys=" + count); Console.Out.Flush();
            }
            finally { if (root != null) root.Dispose(); }
        }
        static void SealRegistryTree(RegistryKey key, string sid, ref int count)
        {
            if (++count > 256) throw new InvalidOperationException("new profile registry exceeds finite seal budget");
            foreach (string child in key.GetSubKeyNames()) {
                using (RegistryKey entry = key.OpenSubKey(child, RegistryKeyPermissionCheck.ReadWriteSubTree,
                    RegistryRights.ReadKey | RegistryRights.ChangePermissions)) {
                    if (entry == null) throw new InvalidOperationException("owned profile registry child is unavailable");
                    SealRegistryTree(entry, sid, ref count);
                }
            }
            var acl = new RegistrySecurity(); acl.SetAccessRuleProtection(true, false);
            acl.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier("S-1-3-4"),
                RegistryRights.ChangePermissions | RegistryRights.TakeOwnership,
                InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Deny));
            acl.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier(sid),
                RegistryRights.WriteKey | RegistryRights.ChangePermissions | RegistryRights.TakeOwnership,
                InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Deny));
            acl.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier(sid), RegistryRights.ReadKey,
                InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
            foreach (SecurityIdentifier identity in new [] { WindowsIdentity.GetCurrent().User, new SecurityIdentifier("S-1-5-18"), new SecurityIdentifier("S-1-5-32-544") })
                acl.AddAccessRule(new RegistryAccessRule(identity, RegistryRights.FullControl,
                    InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
            key.SetAccessControl(acl);
            RegistrySecurity actual = key.GetAccessControl(AccessControlSections.Access);
            if (!actual.AreAccessRulesProtected || actual.GetSecurityDescriptorSddlForm(AccessControlSections.Access)
                != acl.GetSecurityDescriptorSddlForm(AccessControlSections.Access))
                throw new InvalidOperationException("owned profile registry seal readback differs");
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
            RegistryKey registry;
            try { if (registryRoots.TryGetValue(name, out registry)) { registryRoots.Remove(name); registry.Dispose(); } }
            finally { Check(DeleteAppContainerProfile(name), "delete only the owned profile after worker reaping"); }
        }
    }
}
