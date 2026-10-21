using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace ScientificSecurity
{
    // Owned CI-only configuration for two closed diagnostic roles; never target admission.
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
            string pythonReceipt = Receipt(run, nonce, true);
            if (ParseReceipt(pythonReceipt, run, true) != Binding(run, nonce, true) ||
                Binding(run, nonce, true) == binding || ImageName(true) != "startup-python.exe")
                throw new InvalidOperationException("fixed clone ownership role binding failed");
            foreach (bool role in new [] { false, true }) {
                bool rejected = false;
                try { ParseReceipt(Receipt(run, nonce, !role), run, role); }
                catch (InvalidOperationException) { rejected = true; }
                if (!rejected) throw new InvalidOperationException("cross-role diagnostic receipt was accepted");
            }
            int attempts = 0;
            var primary = new InvalidOperationException("fixed diagnostic operation failure");
            var firstCleanup = new IOException("fixed first cleanup failure");
            var secondCleanup = new IOException("fixed second cleanup failure");
            try {
                FinishRoles(primary, () => { attempts++; throw firstCleanup; }, () => { attempts++; throw secondCleanup; });
                throw new InvalidOperationException("failed diagnostic cleanup was hidden");
            }
            catch (AggregateException failure) {
                if (attempts != 2 || failure.InnerExceptions.Count != 3 ||
                    !Object.ReferenceEquals(failure.InnerExceptions[0], primary) ||
                    !Object.ReferenceEquals(failure.InnerExceptions[1], firstCleanup) ||
                    !Object.ReferenceEquals(failure.InnerExceptions[2], secondCleanup))
                    throw new InvalidOperationException("diagnostic cleanup lost failures or abandoned a role");
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
            CheckFailureTemplates();
            CheckPhrasePresence();
            string unknown = Classify(Encoding.ASCII.GetBytes("C:\\host\\secret.dll arbitraryRoutine 0xFFFFFFFF\0"), 0);
            if (unknown != "phase=unknown format_valid=True")
                throw new InvalidOperationException("unknown loader debug string disclosed non-allowlisted content");
            foreach (string trap in new [] { "passwordstatus=0xDEADBEEF", "status 0xDEADBEEF", "status=0xDEADBEEFprivate" })
                if (Classify(Encoding.ASCII.GetBytes(trap + "\0"), 0) != "phase=unknown format_valid=True")
                    throw new InvalidOperationException("loader status classifier accepted a non-label or embedded identifier");
        }
        static void CheckFailureTemplates()
        {
            string[] records = {
                "Probing for the manifest of DLL \"C:\\private-canary\\hidden.dll\" failed with status 0xc0000022",
                "Querying the active activation context failed with status 0x00000001",
                "SXS: Unable to open registry key \\Registry\\private-canary Status = 0xC0000034",
                "SXS: Unable to open storage root subkey private-canary; Status = 0xFFFFFFFF",
                "SXS: RtlGetAssemblyStorageRoot() unable to resolve storage map entry.  Status = 0x80000000",
                "Initializing the current directory to \"C:\\private-canary\" failed with status 0x00000000",
                "Calling LdrpInitializeKernel32Functions failed with status 0xC0000022",
                "LdrpCodeAuthzInitialize failed with status 0xDEADBEEF"
            };
            string[] ids = { "dll_manifest_probe_failed", "active_actctx_query_failed", "sxs_registry_key_open_failed",
                "sxs_storage_root_subkey_open_failed", "sxs_storage_map_resolution_failed", "current_directory_init_failed",
                "kernel32_functions_init_failed", "code_authz_init_failed" };
            string[] statuses = { "C0000022", "00000001", "C0000034", "FFFFFFFF", "80000000", "00000000", "C0000022", "DEADBEEF" };
            for (int index = 0; index < records.Length; index++) {
                string expected = " diagnostic_template=" + ids[index] + " diagnostic_status32=0x" + statuses[index] + " diagnostic_cause_claimed=False";
                foreach (string prefix in new [] { "", "12ab:34CD @ 00000001 - LdrpInitializeProcess - ERROR: ",
                    "12345678:ABCDEF01 @ 1234567890 - LdrpProcessWork - ERROR: " })
                    foreach (string ending in new [] { "", "\n", "\r\n" })
                        foreach (ushort format in new ushort[] { 0, 1 }) {
                            string text = prefix + records[index] + ending;
                            byte[] payload = format == 0 ? Encoding.ASCII.GetBytes(text + "\0") : Encoding.Unicode.GetBytes(text + "\0");
                            string python = Classify(payload, format, true), native = Classify(payload, format);
                            if (!python.EndsWith(expected, StringComparison.Ordinal) || python.Contains("private-canary") ||
                                python.Contains("12ab") || native.Contains("diagnostic_template="))
                                throw new InvalidOperationException("loader failure template parity or privacy fixture failed");
                        }
                string valid = records[index];
                foreach (string invalid in new [] { " " + valid, valid + " ", valid + "extra", valid + "\r", valid + "\n\n",
                    valid + "\n" + valid, valid.Replace("0x", "0X"), valid.Substring(0, valid.Length - 1),
                    valid + "0", valid.Substring(0, valid.Length - 1) + "G", valid.ToLowerInvariant(),
                    "12ab:34cd @ 00000001 - LdrpInit - WARNING: " + valid,
                    "123:34cd @ 00000001 - LdrpInit - ERROR: " + valid,
                    "12ab:34cd @ 0000001 - LdrpInit - ERROR: " + valid,
                    "12ab:34cd @ 00000001 - LdrpInit - ERROR: 12ab:34cd @ 00000001 - LdrpInit - ERROR: " + valid }) {
                    if (FailureTemplateEvidence(invalid).Length != 0)
                        throw new InvalidOperationException("malformed loader failure template was accepted");
                }
            }
            foreach (string decoy in new [] { "", "private 0xC0000022", records[0].Replace("private-canary", "0xDEADBEEF"),
                records[0].Replace("private-canary", "Calling LdrpInitializeKernel32Functions failed with status "),
                records[2].Replace("private-canary", "one Status = two"), records[0].Replace("hidden.dll", "bad\"name"),
                records[2].Replace("private-canary", "one\ttwo"), records[0].Replace("private-canary", "one\u2028two") }) {
                if (FailureTemplateEvidence(decoy).Length != 0)
                    throw new InvalidOperationException("loader failure substitution decoy was accepted");
            }
            if (FailureTemplateEvidence(new string('x', 4097)).Length != 0)
                throw new InvalidOperationException("oversized loader failure record was accepted");
        }
        static void CheckPhrasePresence()
        {
            string[] phrases = {
                "Probing for the manifest of DLL ", "Querying the active activation context failed with status ",
                "SXS: Unable to open registry key ", "SXS: Unable to open storage root subkey ",
                "SXS: RtlGetAssemblyStorageRoot() unable to resolve storage map entry.", "Initializing the current directory to ",
                "Calling LdrpInitializeKernel32Functions failed with status ", "LdrpCodeAuthzInitialize failed with status ",
                "LDR:MRDATA: Process initialization failed with status ", "Process initialization failed with status ",
                "Querying the known DLL directory link object failed with status ",
                "Walking the import tables of the executable and its static imports failed with status ",
                "Running the init routines of the executable", "Initializing TLS slots failed with status ",
                "Calling KernelbasePostInit failed with status ", "SXS: Attempt to get storage location from subkey ",
                "SXS: Storage resolution failed to insert entry to storage map; Status = ",
                "SXS: Attempt to probe known root of assembly storage (", "Unable to load DLL: ",
                "SXS: Unable to resolve storage root for assembly directory "
            };
            string[] ids = { "manifest_probe", "active_actctx", "sxs_registry", "sxs_storage_subkey", "sxs_storage_map",
                "current_directory", "kernel32_init", "code_authz", "mrdata_init", "process_init", "known_dll_link",
                "import_walk", "import_init", "tls_init", "kernelbase_postinit", "sxs_storage_location",
                "sxs_storage_insert", "sxs_known_root", "dll_load", "sxs_storage_resolve" };
            for (int index = 0; index < phrases.Length; index++) {
                string expectedIds = index == 8 ? "mrdata_init,process_init" : ids[index];
                string expected = " diagnostic_phrase_ids=" + expectedIds + " phrase_presence_only=True";
                if (PhrasePresence(phrases[index]) != expected || PhrasePresence(phrases[index] + phrases[index]) != expected ||
                    PhrasePresence(phrases[index].ToLowerInvariant()).Length != 0)
                    throw new InvalidOperationException("fixed phrase presence, deduplication or case fixture failed");
                foreach (ushort format in new ushort[] { 0, 1 }) {
                    string embedded = "opaque-private-canary[" + phrases[index] + "] 0xDEADBEEF";
                    byte[] payload = format == 0 ? Encoding.ASCII.GetBytes(embedded + "\0") : Encoding.Unicode.GetBytes(embedded + "\0");
                    string python = Classify(payload, format, true), native = Classify(payload, format);
                    if (!python.EndsWith(expected, StringComparison.Ordinal) || python.Contains("private-canary") ||
                        python.Contains("DEADBEEF") || python.Contains("diagnostic_template=") || python.Contains("diagnostic_status32=") ||
                        native.Contains("diagnostic_phrase_ids="))
                        throw new InvalidOperationException("phrase presence gained attribution or leaked opaque data");
                }
            }
            string all = PhrasePresence(String.Join("|", phrases.Reverse()));
            if (all != " diagnostic_phrase_ids=" + String.Join(",", ids) + " phrase_presence_only=True" || all.Length > 1024 ||
                all.Any(value => value > 127) || PhrasePresence("failed error SXS status private-canary").Length != 0)
                throw new InvalidOperationException("phrase presence ordering, output bound or unknown fixture failed");
            foreach (int index in new [] { 12, 15, 17 }) {
                string output = Classify(Encoding.ASCII.GetBytes(phrases[index] + "\0"), 0, true);
                if (!output.StartsWith("phase=unknown format_valid=True", StringComparison.Ordinal))
                    throw new InvalidOperationException("nonfailure phrase changed diagnostic phase");
            }
        }
        static readonly string[][] DiagnosticPhrases = {
            new [] { "manifest_probe", "Probing for the manifest of DLL " },
            new [] { "active_actctx", "Querying the active activation context failed with status " },
            new [] { "sxs_registry", "SXS: Unable to open registry key " },
            new [] { "sxs_storage_subkey", "SXS: Unable to open storage root subkey " },
            new [] { "sxs_storage_map", "SXS: RtlGetAssemblyStorageRoot() unable to resolve storage map entry." },
            new [] { "current_directory", "Initializing the current directory to " },
            new [] { "kernel32_init", "Calling LdrpInitializeKernel32Functions failed with status " },
            new [] { "code_authz", "LdrpCodeAuthzInitialize failed with status " },
            new [] { "mrdata_init", "LDR:MRDATA: Process initialization failed with status " },
            new [] { "process_init", "Process initialization failed with status " },
            new [] { "known_dll_link", "Querying the known DLL directory link object failed with status " },
            new [] { "import_walk", "Walking the import tables of the executable and its static imports failed with status " },
            new [] { "import_init", "Running the init routines of the executable" },
            new [] { "tls_init", "Initializing TLS slots failed with status " },
            new [] { "kernelbase_postinit", "Calling KernelbasePostInit failed with status " },
            new [] { "sxs_storage_location", "SXS: Attempt to get storage location from subkey " },
            new [] { "sxs_storage_insert", "SXS: Storage resolution failed to insert entry to storage map; Status = " },
            new [] { "sxs_known_root", "SXS: Attempt to probe known root of assembly storage (" },
            new [] { "dll_load", "Unable to load DLL: " },
            new [] { "sxs_storage_resolve", "SXS: Unable to resolve storage root for assembly directory " }
        };
        static string PhrasePresence(string text)
        {
            string[] ids = DiagnosticPhrases.Where(value => text.IndexOf(value[1], StringComparison.Ordinal) >= 0)
                .Select(value => value[0]).ToArray();
            return ids.Length == 0 ? "" : " diagnostic_phrase_ids=" + String.Join(",", ids) + " phrase_presence_only=True";
        }
        static readonly string[][] FailureTemplates = {
            new [] { "dll_manifest_probe_failed", "Probing for the manifest of DLL \"", "\" failed with status " },
            new [] { "active_actctx_query_failed", "Querying the active activation context failed with status ", "" },
            new [] { "sxs_registry_key_open_failed", "SXS: Unable to open registry key ", " Status = " },
            new [] { "sxs_storage_root_subkey_open_failed", "SXS: Unable to open storage root subkey ", "; Status = " },
            new [] { "sxs_storage_map_resolution_failed", "SXS: RtlGetAssemblyStorageRoot() unable to resolve storage map entry.  Status = ", "" },
            new [] { "current_directory_init_failed", "Initializing the current directory to \"", "\" failed with status " },
            new [] { "kernel32_functions_init_failed", "Calling LdrpInitializeKernel32Functions failed with status ", "" },
            new [] { "code_authz_init_failed", "LdrpCodeAuthzInitialize failed with status ", "" }
        };
        static bool Digits(string text, int minimum, int maximum, bool hex)
        {
            if (text.Length < minimum || text.Length > maximum) return false;
            foreach (char value in text)
                if (!(value >= '0' && value <= '9') && !(hex && (value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F')))
                    return false;
            return true;
        }
        static string FailureRecord(string text)
        {
            if (text == null || text.Length == 0 || text.Length > 4096) return null;
            if (text.EndsWith("\r\n", StringComparison.Ordinal)) text = text.Substring(0, text.Length - 2);
            else if (text.EndsWith("\n", StringComparison.Ordinal)) text = text.Substring(0, text.Length - 1);
            if (text.IndexOfAny(new [] { '\r', '\n', '\0' }) >= 0) return null;
            const string boundary = " - ERROR: ";
            int end = text.IndexOf(boundary, StringComparison.Ordinal);
            if (end < 0) return text;
            string wrapper = text.Substring(0, end);
            string[] parts = wrapper.Split(new [] { " @ ", " - " }, StringSplitOptions.None);
            if (parts.Length != 3) return null;
            string[] ids = parts[0].Split(':');
            if (ids.Length != 2 || !Digits(ids[0], 4, 8, true) || !Digits(ids[1], 4, 8, true) ||
                !Digits(parts[1], 8, 10, false) || parts[2].Length < 1 || parts[2].Length > 96) return null;
            foreach (char value in parts[2])
                if (!(value >= 'a' && value <= 'z') && !(value >= 'A' && value <= 'Z') &&
                    !(value >= '0' && value <= '9') && value != '_') return null;
            text = text.Substring(end + boundary.Length);
            return text.IndexOf(boundary, StringComparison.Ordinal) < 0 ? text : null;
        }
        static bool OpaqueField(string text, bool quoted)
        {
            if (text.Length == 0 || text.IndexOf("0x", StringComparison.OrdinalIgnoreCase) >= 0) return false;
            foreach (char value in text)
                if (Char.IsControl(value) || value == 0x2028 || value == 0x2029 || quoted && value == '"') return false;
            foreach (string[] template in FailureTemplates)
                if (text.IndexOf(template[1], StringComparison.Ordinal) >= 0 || template[2].Length != 0 &&
                    text.IndexOf(template[2], StringComparison.Ordinal) >= 0) return false;
            return true;
        }
        static string FailureTemplateEvidence(string text)
        {
            string record = FailureRecord(text);
            if (record == null || record.Length < 10) return "";
            string number = record.Substring(record.Length - 10);
            if (!number.StartsWith("0x", StringComparison.Ordinal) || !Digits(number.Substring(2), 8, 8, true)) return "";
            string body = record.Substring(0, record.Length - 10), selected = null;
            foreach (string[] template in FailureTemplates) {
                bool matched = template[2].Length == 0 ? body == template[1] :
                    body.StartsWith(template[1], StringComparison.Ordinal) && body.EndsWith(template[2], StringComparison.Ordinal) &&
                    body.Length > template[1].Length + template[2].Length &&
                    OpaqueField(body.Substring(template[1].Length, body.Length - template[1].Length - template[2].Length), template[1].EndsWith("\"", StringComparison.Ordinal));
                if (!matched) continue;
                if (selected != null) return "";
                selected = template[0];
            }
            if (selected == null) return "";
            uint status;
            if (!UInt32.TryParse(number.Substring(2), System.Globalization.NumberStyles.HexNumber,
                System.Globalization.CultureInfo.InvariantCulture, out status)) return "";
            return " diagnostic_template=" + selected + " diagnostic_status32=0x" + status.ToString("X8") + " diagnostic_cause_claimed=False";
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
                + " access_denied_literal_present=" + (HasToken(text, "C0000022") || HasToken(text, "0xC0000022"))
                + PhrasePresence(text) + FailureTemplateEvidence(text);
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
        static string ImageName(bool python) { return python ? "startup-python.exe" : Image; }
        static string Binding(string run, string nonce, bool python = false)
        {
            if (!Identifier(run) || !Identifier(nonce)) throw new InvalidOperationException("loader-snaps ownership identifiers are invalid");
            return "Scientific.Security.LoaderSnaps:" + (python ? "python-pass:" : "") + run + ":" + nonce;
        }
        static string Receipt(string run, string nonce, bool python = false)
        { Binding(run, nonce, python); return "loader-snaps-v1\n" + ImageName(python) + "\n" + run + "\n" + nonce + "\n"; }
        static string ParseReceipt(string text, string run, bool python = false)
        {
            if (text == null || text.Length > 256) throw new InvalidOperationException("loader-snaps ownership receipt exceeds fixed bound");
            string[] parts = text.Split('\n');
            if (parts.Length != 5 || parts[0] != "loader-snaps-v1" || parts[1] != ImageName(python) || parts[2] != run || parts[4] != "")
                throw new InvalidOperationException("loader-snaps ownership receipt does not name this fixed run/image");
            return Binding(run, parts[3], python);
        }
        static void State(string run, string state)
        {
            if (!Identifier(run) || !Path.IsPathFullyQualified(state) ||
                Path.GetFileName(Path.TrimEndingDirectorySeparator(Path.GetFullPath(state))) != "security-windows-" + run)
                throw new InvalidOperationException("loader-snaps state is not this run's fixed owned directory");
        }
        static string ReceiptPath(string state, bool python = false)
        {
            if (!Path.IsPathFullyQualified(state)) throw new InvalidOperationException("loader-snaps state must be absolute");
            string path = Path.Combine(Path.GetFullPath(state), python ? "loader-snaps-python.receipt" : "loader-snaps.receipt");
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
        { EnableFixed(run, state, executable, false); }
        public static void EnablePython(string run, string state)
        { EnableFixed(run, state, Path.Combine(Path.GetFullPath(state), "python", ImageName(true)), true); }
        static void EnableFixed(string run, string state, string executable, bool python)
        {
            CheckValidation(); State(run, state);
            string image = ImageName(python);
            if (!Path.IsPathFullyQualified(executable) ||
                !String.Equals(Path.GetFullPath(executable), Path.Combine(Path.GetFullPath(state), "python", image), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("loader snaps are limited to the two fixed owned diagnostic roles");
            Plain(executable, false);
            string receipt = ReceiptPath(state, python), nonce = Guid.NewGuid().ToString("N");
            byte[] bytes = Utf8.GetBytes(Receipt(run, nonce, python));
            using (var stream = new FileStream(receipt, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                stream.Write(bytes, 0, bytes.Length); stream.Flush(true);
            }
            IntPtr transaction = IntPtr.Zero, parent = IntPtr.Zero, key = IntPtr.Zero;
            try {
                transaction = NewTransaction(); parent = OpenParent(transaction); uint disposition;
                Check(RegCreateKeyTransactedW(parent, image, 0, null, 0, Read | 2 | 0x10000 | View64,
                    IntPtr.Zero, out key, out disposition, transaction, IntPtr.Zero), "create fixed transactional loader-snaps key");
                if (disposition != 1) throw new InvalidOperationException("pre-existing diagnostic IFEO key collision; no edits permitted");
                WriteString(key, Marker, Binding(run, nonce, python)); WriteString(key, "GlobalFlag", Flag);
                Verify(key, Binding(run, nonce, python));
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
                Check(RegOpenKeyExW(parent, image, 0, Read | View64, out observed), "read back committed loader-snaps key");
                Verify(observed, Binding(run, nonce, python));
            }
            finally { CloseAll(observed, parent, IntPtr.Zero); }
        }
        public static void Cleanup(string run, string state) { Cleanup(run, state, null); }
        public static void Cleanup(string run, string state, Exception primary)
        { Cleanup(run, state, primary, null); }
        public static void Cleanup(string run, string state, Exception primary, IDisposable lease)
        { FinishRoles(primary, () => CleanupFixed(run, state, false), () => CleanupFixed(run, state, true),
            () => { if (lease != null) lease.Dispose(); }); }
        static void FinishRoles(Exception primary, params Action[] actions)
        {
            var failures = new List<Exception>();
            foreach (Action action in actions) {
                try { action(); } catch (Exception failure) { failures.Add(failure); }
            }
            if (failures.Count != 0) {
                if (primary != null) failures.Insert(0, primary);
                throw new AggregateException("owned diagnostic role cleanup failed", failures);
            }
        }
        public static void RequireClean(string run, string state)
        {
            State(run, state);
            foreach (bool python in new [] { false, true }) {
                if (File.Exists(ReceiptPath(state, python))) throw new InvalidOperationException("diagnostic ownership receipt remains before admission");
                IntPtr parent = IntPtr.Zero, key = IntPtr.Zero;
                try {
                    parent = OpenParent();
                    int result = RegOpenKeyExW(parent, ImageName(python), 0, Read | View64, out key);
                    if (result != 2 || key != IntPtr.Zero) throw new InvalidOperationException("diagnostic IFEO absence is unverified before admission");
                }
                finally { CloseAll(key, parent, IntPtr.Zero); }
            }
        }
        static void CleanupFixed(string run, string state, bool python)
        {
            State(run, state);
            string image = ImageName(python);
            try { Plain(state, false); }
            catch (FileNotFoundException) { return; }
            catch (DirectoryNotFoundException) { return; }
            string receipt = ReceiptPath(state, python);
            if (!File.Exists(receipt)) return;
            if (new FileInfo(receipt).Length > 256) throw new InvalidOperationException("loader-snaps cleanup receipt is oversized");
            string owner = ParseReceipt(File.ReadAllText(receipt, Utf8), run, python);
            IntPtr transaction = IntPtr.Zero, parent = IntPtr.Zero, key = IntPtr.Zero;
            try {
                transaction = NewTransaction(); parent = OpenParent(transaction);
                int opened = RegOpenKeyTransactedW(parent, image, 0, Read | 0x10000 | View64, out key, transaction, IntPtr.Zero);
                if (opened == 2 && key != IntPtr.Zero)
                    throw new InvalidOperationException("absent loader-snaps key unexpectedly returned a handle");
                if (opened != 2) {
                    Check(opened, "open owned loader-snaps key within cleanup transaction");
                    Verify(key, owner);
                    Check(RegDeleteKeyTransactedW(parent, image, View64, 0, transaction, IntPtr.Zero), "delete exact verified loader-snaps key transactionally");
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
                int opened = RegOpenKeyExW(parent, image, 0, Read | View64, out remaining);
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
