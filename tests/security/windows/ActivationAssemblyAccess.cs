using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace ScientificSecurity
{
    // The successful host context selects at most three files; not the failed call's attempted-object proof.
    public static class ActivationAssemblyAccess
    {
        [StructLayout(LayoutKind.Sequential)] struct AssemblyInfo {
            internal uint flags, identityBytes, pathType, pathBytes;
            internal long manifestTime;
            internal uint policyType, policyBytes;
            internal long policyTime;
            internal uint satellite, manifestMajor, manifestMinor, policyMajor, policyMinor, directoryBytes;
            internal IntPtr identity, path, policy, directory;
            internal uint files;
        }
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool QueryActCtxW(uint flags,
            IntPtr context, IntPtr index, uint kind, IntPtr buffer, UIntPtr capacity, out UIntPtr returned);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr CreateFileW(
            string path, uint access, uint share, IntPtr attributes, uint disposition, uint flags, IntPtr template);
        static readonly UnicodeEncoding Unicode = new UnicodeEncoding(false, false, true);
        const string ControlsPrefix = "amd64_microsoft.windows.common-controls_6595b64144ccf1df_";
        const string ResourcesPrefix = "amd64_microsoft.windows.c..-controls.resources_6595b64144ccf1df_";
        internal static List<Tuple<string, string>> Query(IntPtr context, string python, List<string> lines)
        {
            var paths = new List<Tuple<string, string>>();
            IntPtr buffer = Marshal.AllocHGlobal(65536), index = IntPtr.Zero;
            Exception primary = null;
            try {
                Clear(buffer); UIntPtr returned;
                Native.Check(QueryActCtxW(0, context, IntPtr.Zero, 2, buffer, new UIntPtr(65536), out returned), "query fixed activation assembly count");
                uint count = ReadCount(buffer, returned, lines);
                index = Marshal.AllocHGlobal(4);
                for (uint item = 1; item <= count; item++) {
                    Clear(buffer); Marshal.WriteInt32(index, (int)item);
                    Native.Check(QueryActCtxW(0, context, index, 3, buffer, new UIntPtr(65536), out returned), "query fixed activation assembly metadata");
                    uint size = RequireSize(returned, 104);
                    var info = (AssemblyInfo)Marshal.PtrToStructure(buffer, typeof(AssemblyInfo));
                    RequirePathType(info.pathType);
                    string path = ReadPath(buffer, size, info.path, info.pathBytes);
                    lines.Add(PathMetadata(path, python, item, size, info.pathType));
                    string label = QualifyFile(path, python, item);
                    paths.Add(Tuple.Create(label, path));
                }
                RequireProfile(paths.Select(value => value.Item1).ToArray(), count);
                return paths;
            }
            catch (Exception failure) { primary = failure; throw; }
            finally {
                Release(primary, () => Clear(buffer), () => Marshal.FreeHGlobal(buffer),
                    () => { if (index != IntPtr.Zero) Marshal.FreeHGlobal(index); });
            }
        }
        static uint RequireSize(UIntPtr returned, uint minimum)
        {
            ulong size = returned.ToUInt64();
            if (size < minimum || size > 65536) throw new InvalidOperationException("activation query returned size exceeds fixed buffer");
            return (uint)size;
        }
        static uint ReadCount(IntPtr buffer, UIntPtr returned, List<string> lines)
        {
            uint size = RequireSize(returned, 64);
            uint count = unchecked((uint)Marshal.ReadInt32(buffer, 8));
            lines.Add("WINDOWS_ACTIVATION_QUERY context=host class=2 returned_bytes=" + size + " assembly_count=" + count + " cause_claimed=False");
            return RequireCount(count);
        }
        static uint RequireCount(uint count)
        {
            if (count < 1 || count > 3) throw new InvalidOperationException("activation assembly count exceeds fixed profile");
            return count;
        }
        static void RequirePathType(uint type)
        {
            if (type != 2) throw new InvalidOperationException("activation manifest is not a Win32 file");
        }
        static string QualifyFile(string path, string python, uint index)
        {
            string label = Qualify(path, python, index);
            NativeFixture.Plain(path);
            return label;
        }
        static void Clear(IntPtr buffer) { Marshal.Copy(new byte[65536], 0, buffer, 65536); }
        static string ReadPath(IntPtr buffer, uint size, IntPtr pointer, uint bytes)
        {
            ulong start = unchecked((ulong)buffer.ToInt64()), address = unchecked((ulong)pointer.ToInt64());
            if (bytes < 2 || bytes > 2048 || (bytes & 1) != 0 || address < start || address - start < 104 ||
                address - start > size || (ulong)bytes + 2 > size - (address - start))
                throw new InvalidOperationException("activation manifest path is outside returned allocation");
            byte[] data = new byte[bytes + 2];
            try {
                Marshal.Copy(pointer, data, 0, data.Length);
                if (data[data.Length - 1] != 0 || data[data.Length - 2] != 0)
                    throw new InvalidOperationException("activation manifest path is unterminated");
                string path = Unicode.GetString(data, 0, (int)bytes);
                if (path.IndexOf('\0') >= 0) throw new InvalidOperationException("activation manifest path has embedded terminator");
                return path;
            }
            finally { Array.Clear(data, 0, data.Length); }
        }
        static string ManifestDirectory()
        { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "WinSxS", "Manifests"); }
        static bool Canonical(string path)
        { return Path.IsPathFullyQualified(path) && String.Equals(Path.GetFullPath(path), path, StringComparison.OrdinalIgnoreCase); }
        static bool Family(string path, string prefix)
        {
            string name = Path.GetFileName(path);
            return name.Length <= 240 && name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
                name.EndsWith(".manifest", StringComparison.OrdinalIgnoreCase) &&
                name.All(c => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.');
        }
        static string PathMetadata(string path, string python, uint index, uint size, uint type)
        {
            return "WINDOWS_ACTIVATION_ASSEMBLY context=host class=3 index=" + index + " returned_bytes=" + size + " path_type=" + type +
                " canonical=" + Canonical(path) + " python_root=" + String.Equals(path, python, StringComparison.OrdinalIgnoreCase) +
                " system_manifests=" + String.Equals(Path.GetDirectoryName(path), ManifestDirectory(), StringComparison.OrdinalIgnoreCase) +
                " common_controls=" + Family(path, ControlsPrefix) + " common_controls_resources=" + Family(path, ResourcesPrefix) + " cause_claimed=False";
        }
        static string Qualify(string path, string python, uint index)
        {
            if (!Canonical(path)) throw new InvalidOperationException("activation manifest path is not canonical");
            if (index == 1 && String.Equals(path, python, StringComparison.OrdinalIgnoreCase)) return "python-root";
            if ((index == 2 || index == 3) && String.Equals(Path.GetDirectoryName(path), ManifestDirectory(), StringComparison.OrdinalIgnoreCase)) {
                if (Family(path, ControlsPrefix)) return "common-controls-manifest";
                if (Family(path, ResourcesPrefix)) return "common-controls-resources-manifest";
            }
            throw new InvalidOperationException("activation manifest is outside the fixed root/Common-Controls profile");
        }
        static void RequireProfile(string[] labels, uint count)
        {
            RequireCount(count);
            if (labels.Length != count || labels[0] != "python-root" || labels.Distinct().Count() != count ||
                (count >= 2 && !labels.Contains("common-controls-manifest")) ||
                (count == 3 && !labels.Contains("common-controls-resources-manifest")) ||
                labels.Any(label => label != "python-root" && label != "common-controls-manifest" && label != "common-controls-resources-manifest"))
                throw new InvalidOperationException("activation assembly families do not match the complete fixed profile");
        }
        internal static void OpenFiles(string context, List<Tuple<string, string>> paths, List<string> lines, Action deadline)
        {
            foreach (var path in paths) {
                deadline();
                IntPtr file = CreateFileW(path.Item2, 0x80000000, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
                int error = file == Native.InvalidHandle ? Marshal.GetLastWin32Error() : 0;
                bool opened = file != Native.InvalidHandle;
                Exception primary = null;
                try {
                    if (file == IntPtr.Zero) throw new InvalidOperationException("activation file returned an invalid success handle");
                    lines.Add("WINDOWS_ACTIVATION_FILE context=" + context + " label=" + path.Item1 + " opened=" + opened +
                        " win32_error=" + error + " contents_read=False cause_claimed=False");
                    if (context == "host" && !opened) throw new InvalidOperationException("activation file host positive control failed");
                    deadline();
                }
                catch (Exception failure) { primary = failure; throw; }
                finally { Release(primary, () => {
                    if (opened && file != IntPtr.Zero) Native.Check(Native.CloseHandle(file), "close fixed activation manifest file");
                }); }
            }
        }
        static void Release(Exception primary, params Action[] actions)
        {
            var failures = new List<Exception>();
            foreach (Action action in actions) StartupActivationAccess.Attempt(failures, action);
            StartupActivationAccess.Finish(primary, failures);
        }
        internal static void CheckCleanupValidation()
        {
            var operation = new InvalidOperationException("fixed assembly operation");
            var first = new InvalidOperationException("fixed assembly first release");
            var second = new InvalidOperationException("fixed assembly second release");
            foreach (bool hasPrimary in new [] { false, true }) {
                var order = new List<int>(); AggregateException caught = null;
                try { Release(hasPrimary ? operation : null,
                    () => { order.Add(1); throw first; }, () => order.Add(2), () => { order.Add(3); throw second; }); }
                catch (AggregateException failure) { caught = failure; }
                int offset = hasPrimary ? 1 : 0;
                if (caught == null || caught.InnerExceptions.Count != offset + 2 || String.Join(",", order) != "1,2,3" ||
                    (hasPrimary && !Object.ReferenceEquals(caught.InnerExceptions[0], operation)) ||
                    !Object.ReferenceEquals(caught.InnerExceptions[offset], first) ||
                    !Object.ReferenceEquals(caught.InnerExceptions[offset + 1], second))
                    throw new InvalidOperationException("assembly releases lost original-first failures or independent cleanup");
            }
            int released = 0; Release(operation, () => released++, () => released++);
            if (released != 2) throw new InvalidOperationException("assembly independent release was skipped");
        }
        public static void CheckValidation(string work)
        {
            CheckCleanupValidation();
            if (Marshal.SizeOf(typeof(AssemblyInfo)) != 104 || Marshal.OffsetOf(typeof(AssemblyInfo), "path").ToInt32() != 72 ||
                Marshal.OffsetOf(typeof(AssemblyInfo), "pathBytes").ToInt32() != 12 || Marshal.OffsetOf(typeof(AssemblyInfo), "pathType").ToInt32() != 8)
                throw new InvalidOperationException("activation assembly ABI differs");
            IntPtr buffer = Marshal.AllocHGlobal(65536);
            try {
                Clear(buffer); byte[] literal = Unicode.GetBytes("C:\\fixed\\python.exe\0");
                IntPtr path = IntPtr.Add(buffer, 104); Marshal.Copy(literal, 0, path, literal.Length);
                if (ReadPath(buffer, (uint)(104 + literal.Length), path, (uint)literal.Length - 2) != "C:\\fixed\\python.exe" ||
                    RequireCount(1) != 1 || RequireCount(2) != 2)
                    throw new InvalidOperationException("activation path/count fixture differs");
                RequirePathType(2);
                var lines = new List<string>();
                foreach (uint count in new uint[] { 0, 1, 2, 3, 4, UInt32.MaxValue }) {
                    lines.Clear(); Marshal.WriteInt32(buffer, 8, unchecked((int)count));
                    if (count >= 1 && count <= 3) {
                        if (ReadCount(buffer, new UIntPtr(64), lines) != count)
                            throw new InvalidOperationException("activation query count fixture differs");
                    }
                    else Refuse(() => ReadCount(buffer, new UIntPtr(64), lines));
                    string expected = "WINDOWS_ACTIVATION_QUERY context=host class=2 returned_bytes=64 assembly_count=" + count + " cause_claimed=False";
                    if (lines.Count != 1 || lines[0] != expected)
                        throw new InvalidOperationException("activation query refusal metadata was lost");
                }
                lines.Clear();
                Refuse(() => ReadCount(buffer, new UIntPtr(63), lines));
                Refuse(() => ReadCount(buffer, new UIntPtr(65537), lines));
                if (lines.Count != 0) throw new InvalidOperationException("unqualified activation query size was logged");
                foreach (Action bad in new Action[] {
                    () => ReadPath(buffer, 104, path, 2), () => ReadPath(buffer, 65536, buffer, 2),
                    () => ReadPath(buffer, 65536, path, 3), () => ReadPath(buffer, 65536, IntPtr.Zero, 2),
                    () => ReadPath(buffer, 65536, path, 0), () => ReadPath(buffer, 65536, path, 2050),
                    () => ReadPath(buffer, 65536, IntPtr.Add(buffer, 65534), 2),
                    () => ReadPath(buffer, 65536, IntPtr.Subtract(buffer, 2), 2),
                    () => RequireSize(new UIntPtr(65537), 104), () => RequireSize(new UIntPtr(103), 104),
                    () => RequireCount(0), () => RequireCount(4), () => RequireCount(UInt32.MaxValue),
                    () => RequirePathType(0), () => RequirePathType(1), () => RequirePathType(3), () => RequirePathType(4)
                }) Refuse(bad);
                // Literal byte fixtures, independent of the strict decoder under test.
                foreach (byte[] bad in new [] {
                    new byte[] { 0x41, 0, 0x42, 0 },
                    new byte[] { 0x41, 0, 0, 0, 0x42, 0, 0, 0 },
                    new byte[] { 0, 0xD8, 0, 0 }
                }) {
                    Clear(buffer); Marshal.Copy(bad, 0, path, bad.Length);
                    Refuse(() => ReadPath(buffer, (uint)(104 + bad.Length), path, (uint)bad.Length - 2));
                }
                string python = Path.Combine(Path.GetFullPath(work), "python.exe");
                string directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "WinSxS", "Manifests");
                const string name = "amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.0.0_none_fixed.manifest";
                string manifest = Path.Combine(directory, name);
                string resources = Path.Combine(directory, "amd64_microsoft.windows.c..-controls.resources_6595b64144ccf1df_6.0.0.0_en-us_fixed.manifest");
                if (Qualify(python, python, 1) != "python-root" || Qualify(manifest, python, 2) != "common-controls-manifest" ||
                    Qualify(manifest, python, 3) != "common-controls-manifest" || Qualify(resources, python, 2) != "common-controls-resources-manifest" ||
                    Qualify(resources, python, 3) != "common-controls-resources-manifest")
                    throw new InvalidOperationException("activation assembly fixed path fixture failed");
                RequireProfile(new [] { "python-root" }, 1);
                RequireProfile(new [] { "python-root", "common-controls-manifest" }, 2);
                RequireProfile(new [] { "python-root", "common-controls-manifest", "common-controls-resources-manifest" }, 3);
                RequireProfile(new [] { "python-root", "common-controls-resources-manifest", "common-controls-manifest" }, 3);
                foreach (Action bad in new Action[] {
                    () => RequireProfile(new string[0], 1),
                    () => RequireProfile(new [] { "python-root", "common-controls-resources-manifest" }, 2),
                    () => RequireProfile(new [] { "python-root", "common-controls-manifest", "common-controls-manifest" }, 3),
                    () => RequireProfile(new [] { "common-controls-manifest", "python-root", "common-controls-resources-manifest" }, 3),
                    () => RequireProfile(new [] { "python-root", "common-controls-manifest", "foreign" }, 3),
                    () => Qualify(resources, python, 1), () => Qualify(resources, python, 4)
                }) Refuse(bad);
                if (PathMetadata("C:\\private\\canary.manifest", python, 3, 104, 2) !=
                    "WINDOWS_ACTIVATION_ASSEMBLY context=host class=3 index=3 returned_bytes=104 path_type=2 canonical=True python_root=False system_manifests=False common_controls=False common_controls_resources=False cause_claimed=False")
                    throw new InvalidOperationException("activation assembly fixed metadata fixture differs");
                foreach (Action bad in new Action[] {
                    () => Qualify("C:\\private\\canary.manifest", python, 2),
                    () => Qualify(Path.Combine(directory + "-sibling", name), python, 2),
                    () => Qualify(Path.Combine(directory, "..", "Manifests", name), python, 2),
                    () => Qualify(Path.Combine(directory, name.Replace("fixed", "fíxed")), python, 2),
                    () => Qualify(Path.Combine(directory, name + ":stream"), python, 2),
                    () => Qualify(Path.Combine(directory, "x.manifest"), python, 2),
                    () => Qualify(Path.Combine(directory, name.Replace(".manifest", ".dll")), python, 2),
                    () => Qualify(Path.Combine(directory, new string('a', 241) + ".manifest"), python, 2),
                    () => Qualify("relative.manifest", python, 2), () => Qualify(manifest, python, 1),
                    () => Qualify(python, python, 2), () => Qualify(python, python, 3)
                }) Refuse(bad);
            }
            finally { try { Clear(buffer); } finally { Marshal.FreeHGlobal(buffer); } }
            CheckReparseValidation(work);
        }
        static void CheckReparseValidation(string work)
        {
            NativeFixture.Plain(work);
            string root = Path.Combine(work, "activation-assembly-fixture-" + Guid.NewGuid().ToString("N"));
            NativeFixture.Plain(root, true);
            bool absent = false;
            try { File.GetAttributes(root); }
            catch (FileNotFoundException) { absent = true; }
            catch (DirectoryNotFoundException) { absent = true; }
            if (!absent) throw new InvalidOperationException("activation fixture collides with existing state");
            Directory.CreateDirectory(root);
            string leaf = Path.Combine(root, "python.exe"), link = Path.Combine(root, "linked");
            bool leafOwned = false, linkOwned = false;
            try {
                File.WriteAllBytes(leaf, new byte[] { 0 });
                if (QualifyFile(leaf, leaf, 1) != "python-root")
                    throw new InvalidOperationException("activation plain-file positive control failed");
                File.Delete(leaf);
                Directory.CreateSymbolicLink(leaf, Path.Combine(root, "absent")); leafOwned = true;
                Refuse(() => QualifyFile(leaf, leaf, 1));
                if ((File.GetAttributes(leaf) & FileAttributes.ReparsePoint) == 0)
                    throw new InvalidOperationException("activation fixture changed dangling link");
                Directory.Delete(leaf); leafOwned = false;
                string actual = Path.Combine(root, "actual"); Directory.CreateDirectory(actual);
                File.WriteAllBytes(Path.Combine(actual, "python.exe"), new byte[] { 0 });
                Directory.CreateSymbolicLink(link, actual); linkOwned = true;
                string alias = Path.Combine(link, "python.exe");
                Refuse(() => QualifyFile(alias, alias, 1));
            }
            finally {
                try { if (leafOwned) Directory.Delete(leaf); }
                finally { try { if (linkOwned) Directory.Delete(link); } finally { Directory.Delete(root, true); } }
            }
        }
        static void Refuse(Action action)
        {
            bool refused = false;
            try { action(); }
            catch (InvalidOperationException) { refused = true; }
            catch (DecoderFallbackException) { refused = true; }
            if (!refused) throw new InvalidOperationException("activation assembly malformed fixture was accepted");
        }
    }
}
