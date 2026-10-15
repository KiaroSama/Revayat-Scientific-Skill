using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace ScientificSecurity
{
    // Owned CI-only configuration for one fixed native fixture; never a target launch/admission path.
    public static class LoaderSnaps
    {
        const string Image = "startup-native.exe";
        const string Parent = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        const string Marker = "ScientificSecurityOwner";
        const string Flag = "0x00000002";
        const uint View64 = 0x100, Read = 0x20019;
        static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
        static readonly UnicodeEncoding Unicode = new UnicodeEncoding(false, false, true);
        static readonly string[] Routines = { "LdrpCallInitRoutine", "LdrpInitializeProcess", "LdrpInitializeNode",
            "LdrInitializeThunk", "BaseDllInitialize" };
        static readonly string[] Modules = { "ntdll.dll", "kernel32.dll", "kernelbase.dll", Image };
        static readonly string[] PythonModules = { "python.exe", "python311.dll", "ucrtbase.dll", "vcruntime140.dll",
            "vcruntime140_1.dll", "version.dll", "ws2_32.dll", "pathcch.dll", "bcrypt.dll", "comctl32.dll",
            "advapi32.dll", "shell32.dll", "ole32.dll", "oleaut32.dll" };

        // Pure bounded parser/ownership checks. No registry, process, or remote-memory calls.
        public static void CheckValidation()
        {
            string run = new string('a', 32), nonce = new string('b', 32);
            string binding = Binding(run, nonce);
            State(run, Path.Combine(Path.GetTempPath(), "security-windows-" + run));
            bool foreignState = false;
            try { State(run, Path.Combine(Path.GetTempPath(), "security-windows-" + new string('c', 32))); }
            catch (InvalidOperationException) { foreignState = true; }
            if (!foreignState) throw new InvalidOperationException("foreign loader-snaps state was accepted");
            if (ParseReceipt(Receipt(run, nonce), run) != binding)
                throw new InvalidOperationException("loader-snaps receipt positive check failed");
            foreach (string bad in new [] { Receipt(run, nonce).Replace(Image, "python.exe"), Receipt(run, nonce) + "extra\n",
                Receipt(new string('c', 32), nonce), Receipt(run, nonce).Replace(nonce, "bad") }) {
                bool rejected = false;
                try { ParseReceipt(bad, run); } catch (InvalidOperationException) { rejected = true; }
                if (!rejected) throw new InvalidOperationException("malformed loader-snaps ownership receipt was accepted");
            }
            string text = "LdrpCallInitRoutine kernelbase.dll status=0xC0000142 C:\\private\\canary 0x123456789ABC";
            byte[] ascii = Encoding.ASCII.GetBytes(text + "\0");
            string classification = Classify(ascii, 0);
            if (!classification.Contains("routine=LdrpCallInitRoutine") || !classification.Contains("module=kernelbase.dll") ||
                !classification.Contains("status=0xC0000142") || classification.Contains("private") || classification.Contains("123456"))
                throw new InvalidOperationException("loader-snaps classifier leaked content or lost fixed diagnostic labels");
            if (Classify(Encoding.Unicode.GetBytes(text + "\0"), 1) != classification)
                throw new InvalidOperationException("loader-snaps Unicode classifier differs from ASCII");
            foreach (var input in new [] { Tuple.Create(new byte[0], (ushort)0), Tuple.Create(new byte[4097], (ushort)0),
                Tuple.Create(new byte[] { 65 }, (ushort)0), Tuple.Create(new byte[] { 65, 0, 66, 0 }, (ushort)0),
                Tuple.Create(new byte[] { 255, 0 }, (ushort)0), Tuple.Create(new byte[] { 65, 0, 0 }, (ushort)1),
                Tuple.Create(new byte[] { 0, 216, 0, 0 }, (ushort)1), Tuple.Create(ascii, (ushort)2) }) {
                if (Classify(input.Item1, input.Item2) != "phase=unknown format_valid=False")
                    throw new InvalidOperationException("malformed loader debug-string bytes were accepted");
            }
            foreach (ushort format in new ushort[] { 0, 1 }) {
                string diagnostic = "LdrpInitializeProcess failed python311.dll status=0xC0000022 C:\\private\\canary 0x123456789ABC";
                byte[] payload = format == 0 ? Encoding.ASCII.GetBytes(diagnostic + "\0") : Encoding.Unicode.GetBytes(diagnostic + "\0");
                string python = Classify(payload, format, true);
                if (python != "phase=failure format_valid=True routine=LdrpInitializeProcess module_mentioned=python311.dll access_denied_literal_present=True" ||
                    Classify(payload, format).Contains("python311.dll"))
                    throw new InvalidOperationException("fixed Python string classification widened native labels or leaked content");
            }
            string missingDll = "LdrpProcessWork - ERROR: Unable to load DLL: C:\\private\\unknown.dll, Parent Module: C:\\private\\python311.dll; C0000022";
            string kind = PythonEvidence(missingDll);
            if (!kind.Contains("message_kind=dll_load_failure") || !kind.Contains("module_mentioned=python311.dll") ||
                !kind.Contains("access_denied_literal_present=True") || kind.Contains("unknown.dll") || kind.Contains("failed_module"))
                throw new InvalidOperationException("Python diagnostic role/redaction fixture failed");
            if (PythonEvidence("manifest assembly SXS image import C00000220 secret.dll") != " access_denied_literal_present=False")
                throw new InvalidOperationException("generic words or embedded status became Python failure evidence");
            if (!PythonEvidence("Activation context generation failed; Dependent Assembly public could not be found")
                .Contains("message_kind=activation_context_failure,assembly_resolution_failure"))
                throw new InvalidOperationException("multiple fixed Python message kinds were hidden");
            string unknown = Classify(Encoding.ASCII.GetBytes("C:\\host\\secret.dll arbitraryRoutine 0xFFFFFFFF\0"), 0);
            if (unknown != "phase=unknown format_valid=True")
                throw new InvalidOperationException("unknown loader debug string disclosed non-allowlisted content");
            foreach (string trap in new [] { "passwordstatus=0xDEADBEEF", "status 0xDEADBEEF", "status=0xDEADBEEFprivate" })
                if (Classify(Encoding.ASCII.GetBytes(trap + "\0"), 0) != "phase=unknown format_valid=True")
                    throw new InvalidOperationException("loader status classifier accepted a non-label or embedded identifier");
        }
        internal static string Classify(byte[] bytes, ushort unicode, bool python = false)
        {
            if (bytes == null || bytes.Length == 0 || bytes.Length > 4096 || unicode > 1 ||
                (unicode == 1 && (bytes.Length < 2 || (bytes.Length & 1) != 0)))
                return "phase=unknown format_valid=False";
            string text;
            try {
                if (unicode == 1) {
                    if (bytes[bytes.Length - 1] != 0 || bytes[bytes.Length - 2] != 0)
                        return "phase=unknown format_valid=False";
                    text = Unicode.GetString(bytes, 0, bytes.Length - 2);
                }
                else {
                    if (bytes[bytes.Length - 1] != 0 || bytes.Any(value => value > 127))
                        return "phase=unknown format_valid=False";
                    text = Encoding.ASCII.GetString(bytes, 0, bytes.Length - 1);
                }
            }
            catch (DecoderFallbackException) { return "phase=unknown format_valid=False"; }
            if (text.IndexOf('\0') >= 0) return "phase=unknown format_valid=False";
            string routine = Routines.FirstOrDefault(value => HasToken(text, value));
            string module = Modules.FirstOrDefault(value => HasToken(text, value));
            var statuses = new List<string>();
            for (int index = 0; !python && index <= text.Length - 6 && statuses.Count < 4; index++) {
                if (!StartsAt(text, index, "status") || (index > 0 && TokenCharacter(text[index - 1]))) continue;
                int cursor = index + 6;
                while (cursor < text.Length && text[cursor] == ' ') cursor++;
                if (cursor >= text.Length || (text[cursor] != '=' && text[cursor] != ':')) continue;
                cursor++;
                while (cursor < text.Length && text[cursor] == ' ') cursor++;
                if (cursor > text.Length - 10 || !StartsAt(text, cursor, "0x")) continue;
                bool hex = true;
                for (int digit = cursor + 2; digit < cursor + 10; digit++)
                    hex &= (text[digit] >= '0' && text[digit] <= '9') || (text[digit] >= 'a' && text[digit] <= 'f') ||
                        (text[digit] >= 'A' && text[digit] <= 'F');
                if (hex && (cursor + 10 == text.Length || !TokenCharacter(text[cursor + 10])))
                    statuses.Add("0x" + text.Substring(cursor + 2, 8).ToUpperInvariant());
            }
            string phase = statuses.Count != 0 || HasToken(text, "error") || HasToken(text, "failed") ? "failure" :
                (routine != null ? "initializer" : "unknown");
            return "phase=" + phase + " format_valid=True" + (routine == null ? "" : " routine=" + routine)
                + (module == null || python ? "" : " module=" + module) + (statuses.Count == 0 ? "" : " status=" + String.Join(",", statuses))
                + (python ? PythonEvidence(text) : "");
        }
        static string PythonEvidence(string text)
        {
            var kinds = new List<string>();
            if (Ordered(text, "LdrpProcessWork - ERROR: Unable to load DLL:", "Parent Module:")) kinds.Add("dll_load_failure");
            if (text.IndexOf("Activation context generation failed", StringComparison.OrdinalIgnoreCase) >= 0)
                kinds.Add("activation_context_failure");
            if (Ordered(text, "Dependent Assembly", "could not be found")) kinds.Add("assembly_resolution_failure");
            if (Ordered(text, "LDR: Process initialization failure for", "NTSTATUS"))
                kinds.Add("process_initialization_wording_candidate");
            var mentions = new List<string>();
            foreach (string name in Modules.Concat(PythonModules)) if (HasToken(text, name)) mentions.Add(name);
            // A DLL message also names its parent. Mentions never identify the failed DLL.
            return (kinds.Count == 0 ? "" : " message_kind=" + String.Join(",", kinds))
                + (mentions.Count == 0 ? "" : " module_mentioned=" + String.Join(",", mentions))
                + " access_denied_literal_present=" + (HasToken(text, "C0000022") || HasToken(text, "0xC0000022"));
        }
        static bool Ordered(string text, string first, string second)
        {
            int index = text.IndexOf(first, StringComparison.OrdinalIgnoreCase);
            return index >= 0 && text.IndexOf(second, index + first.Length, StringComparison.OrdinalIgnoreCase) >= 0;
        }
        static bool TokenCharacter(char value) { return Char.IsLetterOrDigit(value) || value == '_' || value == '.'; }
        static bool StartsAt(string text, int index, string value)
        { return index <= text.Length - value.Length && String.Compare(text, index, value, 0, value.Length, StringComparison.OrdinalIgnoreCase) == 0; }
        static bool HasToken(string text, string value)
        {
            for (int index = 0; index <= text.Length - value.Length; index++)
                if (StartsAt(text, index, value) && (index == 0 || !TokenCharacter(text[index - 1])) &&
                    (index + value.Length == text.Length || !TokenCharacter(text[index + value.Length]))) return true;
            return false;
        }
        static bool Identifier(string value)
        { return value != null && value.Length == 32 && value.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')); }
        static string Binding(string run, string nonce)
        {
            if (!Identifier(run) || !Identifier(nonce)) throw new InvalidOperationException("loader-snaps ownership identifiers are invalid");
            return "Scientific.Security.LoaderSnaps:" + run + ":" + nonce;
        }
        static string Receipt(string run, string nonce) { Binding(run, nonce); return "loader-snaps-v1\n" + Image + "\n" + run + "\n" + nonce + "\n"; }
        static string ParseReceipt(string text, string run)
        {
            if (text == null || text.Length > 256) throw new InvalidOperationException("loader-snaps ownership receipt exceeds fixed bound");
            string[] parts = text.Split('\n');
            if (parts.Length != 5 || parts[0] != "loader-snaps-v1" || parts[1] != Image || parts[2] != run || parts[4] != "")
                throw new InvalidOperationException("loader-snaps ownership receipt does not name this fixed run/image");
            return Binding(run, parts[3]);
        }
        static void State(string run, string state)
        {
            if (!Identifier(run) || !Path.IsPathFullyQualified(state) ||
                Path.GetFileName(Path.TrimEndingDirectorySeparator(Path.GetFullPath(state))) != "security-windows-" + run)
                throw new InvalidOperationException("loader-snaps state is not this run's fixed owned directory");
        }
        static string ReceiptPath(string state)
        {
            if (!Path.IsPathFullyQualified(state)) throw new InvalidOperationException("loader-snaps state must be absolute");
            string path = Path.Combine(Path.GetFullPath(state), "loader-snaps.receipt");
            Plain(path, true); return path;
        }
        static void Plain(string path, bool missingLeaf)
        {
            var ancestors = new Stack<string>(); string entry = Path.GetFullPath(path);
            while (!String.IsNullOrEmpty(entry)) { ancestors.Push(entry); entry = Path.GetDirectoryName(entry); }
            while (ancestors.Count != 0) {
                string current = ancestors.Pop();
                try {
                    if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                        throw new InvalidOperationException("loader-snaps ownership path is a reparse point");
                }
                catch (FileNotFoundException) { if (!(missingLeaf && current == path)) throw; }
                catch (DirectoryNotFoundException) { if (!(missingLeaf && current == path)) throw; }
            }
        }
        public static void Enable(string run, string state, string executable)
        {
            CheckValidation(); State(run, state);
            if (!Path.IsPathFullyQualified(executable) ||
                !String.Equals(Path.GetFullPath(executable), Path.Combine(Path.GetFullPath(state), "python", Image), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("loader snaps are limited to the fixed owned native fixture");
            Plain(executable, false);
            string receipt = ReceiptPath(state), nonce = Guid.NewGuid().ToString("N");
            byte[] bytes = Utf8.GetBytes(Receipt(run, nonce));
            using (var stream = new FileStream(receipt, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                stream.Write(bytes, 0, bytes.Length); stream.Flush(true);
            }
            IntPtr transaction = IntPtr.Zero, parent = IntPtr.Zero, key = IntPtr.Zero;
            try {
                transaction = NewTransaction(); parent = OpenParent(transaction); uint disposition;
                Check(RegCreateKeyTransactedW(parent, Image, 0, null, 0, Read | 2 | 0x10000 | View64,
                    IntPtr.Zero, out key, out disposition, transaction, IntPtr.Zero), "create fixed transactional loader-snaps key");
                if (disposition != 1) throw new InvalidOperationException("pre-existing native-fixture IFEO key collision; no edits permitted");
                WriteString(key, Marker, Binding(run, nonce)); WriteString(key, "GlobalFlag", Flag);
                Verify(key, Binding(run, nonce));
                CheckBool(CommitTransaction(transaction), "commit complete loader-snaps ownership/configuration");
            }
            finally {
                try { CloseAll(key, parent, transaction); }
                finally { key = IntPtr.Zero; parent = IntPtr.Zero; transaction = IntPtr.Zero; }
            }
            // Reopen only after commit; earlier non-transacted opens would abort the transaction.
            IntPtr observed = IntPtr.Zero;
            try {
                parent = OpenParent();
                Check(RegOpenKeyExW(parent, Image, 0, Read | View64, out observed), "read back committed loader-snaps key");
                Verify(observed, Binding(run, nonce));
            }
            finally { CloseAll(observed, parent, IntPtr.Zero); }
        }
        public static void Cleanup(string run, string state)
        {
            State(run, state);
            try { Plain(state, false); }
            catch (FileNotFoundException) { return; }
            catch (DirectoryNotFoundException) { return; }
            string receipt = ReceiptPath(state);
            if (!File.Exists(receipt)) return;
            if (new FileInfo(receipt).Length > 256) throw new InvalidOperationException("loader-snaps cleanup receipt is oversized");
            string owner = ParseReceipt(File.ReadAllText(receipt, Utf8), run);
            IntPtr transaction = IntPtr.Zero, parent = IntPtr.Zero, key = IntPtr.Zero;
            try {
                transaction = NewTransaction(); parent = OpenParent(transaction);
                int opened = RegOpenKeyTransactedW(parent, Image, 0, Read | 0x10000 | View64, out key, transaction, IntPtr.Zero);
                if (opened == 2 && key != IntPtr.Zero)
                    throw new InvalidOperationException("absent loader-snaps key unexpectedly returned a handle");
                if (opened != 2) {
                    Check(opened, "open owned loader-snaps key within cleanup transaction");
                    Verify(key, owner);
                    Check(RegDeleteKeyTransactedW(parent, Image, View64, 0, transaction, IntPtr.Zero), "delete exact verified loader-snaps key transactionally");
                    IntPtr close = key; key = IntPtr.Zero;
                    Check(RegCloseKey(close), "close deleted transactional loader-snaps key");
                    CheckBool(CommitTransaction(transaction), "commit owned loader-snaps cleanup");
                }
            }
            finally {
                try { CloseAll(key, parent, transaction); }
                finally { key = IntPtr.Zero; parent = IntPtr.Zero; transaction = IntPtr.Zero; }
            }
            IntPtr remaining = IntPtr.Zero;
            try {
                parent = OpenParent();
                int opened = RegOpenKeyExW(parent, Image, 0, Read | View64, out remaining);
                if (opened != 2 || remaining != IntPtr.Zero)
                    throw new InvalidOperationException("fixed IFEO loader-snaps cleanup absence was not verified");
            }
            finally { CloseAll(remaining, parent, IntPtr.Zero); }
            File.Delete(receipt);
        }
        static IntPtr OpenParent(IntPtr transaction = default(IntPtr))
        {
            IntPtr parent = IntPtr.Zero;
            IntPtr hive = new IntPtr(unchecked((int)0x80000002));
            int result = transaction == IntPtr.Zero
                ? RegOpenKeyExW(hive, Parent, 0, Read | 4 | View64, out parent)
                : RegOpenKeyTransactedW(hive, Parent, 0, Read | 4 | View64, out parent, transaction, IntPtr.Zero);
            if (result != 0) { if (parent != IntPtr.Zero) RegCloseKey(parent); Check(result, "open existing 64-bit IFEO parent"); }
            return parent;
        }
        static IntPtr NewTransaction()
        {
            IntPtr transaction = CreateTransaction(IntPtr.Zero, IntPtr.Zero, 0, 0, 0, 10000, null);
            if (transaction == IntPtr.Zero || transaction == new IntPtr(-1))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "create bounded loader-snaps ownership transaction");
            return transaction;
        }
        static void WriteString(IntPtr key, string name, string value)
        {
            byte[] data = Encoding.Unicode.GetBytes(value + "\0");
            Check(RegSetValueExW(key, name, 0, 1, data, (uint)data.Length), "write fixed loader-snaps ownership/configuration value");
        }
        static string ReadString(IntPtr key, string name)
        {
            byte[] bytes = new byte[256]; uint length = (uint)bytes.Length, type;
            Check(RegQueryValueExW(key, name, IntPtr.Zero, out type, bytes, ref length), "read fixed loader-snaps value");
            if (type != 1 || length < 2 || length > bytes.Length || (length & 1) != 0 || bytes[length - 1] != 0 || bytes[length - 2] != 0)
                throw new InvalidOperationException("loader-snaps registry value is not a bounded terminated REG_SZ");
            string value = Unicode.GetString(bytes, 0, (int)length - 2);
            if (value.IndexOf('\0') >= 0) throw new InvalidOperationException("loader-snaps registry value contains an embedded terminator");
            return value;
        }
        static void Verify(IntPtr key, string owner)
        {
            uint subkeys, maxSubkey, maxClass, values, maxName, maxData, descriptor;
            Check(RegQueryInfoKeyW(key, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out subkeys, out maxSubkey, out maxClass,
                out values, out maxName, out maxData, out descriptor, IntPtr.Zero), "verify finite loader-snaps key shape");
            if (subkeys != 0 || values != 2 || maxName > 64 || maxData > 256)
                throw new InvalidOperationException("loader-snaps key contains unexpected entries or exceeds ownership bounds");
            var names = new HashSet<string>(StringComparer.Ordinal);
            for (uint index = 0; index < 2; index++) {
                var name = new StringBuilder(65); uint characters = 65, type, dataSize = 256;
                byte[] data = new byte[256];
                Check(RegEnumValueW(key, index, name, ref characters, IntPtr.Zero, out type, data, ref dataSize), "enumerate fixed loader-snaps values");
                if (characters > 64 || dataSize > 256 || type != 1 || !names.Add(name.ToString()))
                    throw new InvalidOperationException("loader-snaps value enumeration violates the exact ownership schema");
            }
            if (!names.SetEquals(new [] { Marker, "GlobalFlag" }) || ReadString(key, Marker) != owner || ReadString(key, "GlobalFlag") != Flag)
                throw new InvalidOperationException("loader-snaps key is not the exact configuration owned by this run");
        }
        static void Check(int result, string operation)
        { if (result != 0) throw new System.ComponentModel.Win32Exception(result, operation); }
        static void CheckBool(bool result, string operation)
        { if (!result) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), operation); }
        static void CloseAll(IntPtr key, IntPtr parent, IntPtr transaction)
        {
            var failures = new List<Exception>();
            try {
                if (key != IntPtr.Zero) Check(RegCloseKey(key), "close loader-snaps key");
            } catch (Exception failure) { failures.Add(failure); }
            finally {
                try {
                    if (parent != IntPtr.Zero) Check(RegCloseKey(parent), "close loader-snaps parent");
                } catch (Exception failure) { failures.Add(failure); }
                finally {
                    try { if (transaction != IntPtr.Zero) CheckBool(CloseHandle(transaction), "close loader-snaps transaction"); }
                    catch (Exception failure) { failures.Add(failure); }
                }
            }
            if (failures.Count != 0) throw new AggregateException("loader-snaps native ownership cleanup failed", failures);
        }
        [DllImport("ktmw32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern IntPtr CreateTransaction(
            IntPtr attributes, IntPtr unitOfWork, uint options, uint isolation, uint isolationFlags, uint timeout, string description);
        [DllImport("ktmw32.dll", SetLastError = true)] static extern bool CommitTransaction(IntPtr transaction);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr handle);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegOpenKeyExW(IntPtr parent, string name, uint options, uint access, out IntPtr key);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegCreateKeyTransactedW(IntPtr parent, string name, uint reserved, string className,
            uint options, uint access, IntPtr attributes, out IntPtr key, out uint disposition, IntPtr transaction, IntPtr extended);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegOpenKeyTransactedW(IntPtr parent, string name, uint options, uint access,
            out IntPtr key, IntPtr transaction, IntPtr extended);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegDeleteKeyTransactedW(IntPtr parent, string name, uint view,
            uint reserved, IntPtr transaction, IntPtr extended);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegSetValueExW(IntPtr key, string name, uint reserved, uint type, byte[] bytes, uint size);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegQueryValueExW(IntPtr key, string name, IntPtr reserved, out uint type, byte[] bytes, ref uint size);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegQueryInfoKeyW(IntPtr key, IntPtr className, IntPtr classLength, IntPtr reserved,
            out uint subkeys, out uint maxSubkey, out uint maxClass, out uint values, out uint maxName, out uint maxData, out uint security, IntPtr time);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegEnumValueW(IntPtr key, uint index, StringBuilder name, ref uint length,
            IntPtr reserved, out uint type, byte[] bytes, ref uint bytesLength);
        [DllImport("advapi32.dll")] static extern int RegCloseKey(IntPtr key);
    }
}
