using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace ScientificSecurity
{
    // Original prepared Python only; a sampled CSR return never establishes its startup cause.
    public static class PythonCsrDispatch
    {
        sealed class Identity
        {
            internal string python;
            internal string[] hashes;
            internal int[] lengths;
            internal ushort language;
            internal string manifestHash;
            internal int manifestLength;
        }
        static Identity prepared;
        static bool hostPositive;
        static readonly string[] Images = { "python.exe", "python311.dll", "vcruntime140.dll" };
        static readonly string[] Imports = { "python-exe", "python311", "vcruntime140" };
        const string HostResult = "pass_code_completed=True raw_process_exit=0x00000000 stdout_empty=True stderr_empty=True";
        internal static void Need(bool value)
        { if (!value) throw new InvalidOperationException("fixed original Python CSR contract failed"); }
        static void Refuse(Action action)
        {
            bool refused = false;
            try { action(); } catch (InvalidOperationException error) { refused = !error.Message.Contains("private-sentinel"); }
            catch (ArgumentException error) { refused = !error.Message.Contains("private-sentinel"); }
            Need(refused);
        }
        public static void CheckPythonValidation(string work)
        {
            KernelImage.CheckPythonDispatchIdentity(); CheckTransport(); CheckHost(); CheckComparison(); CheckIdentity(work);
            string runtime = Path.Combine(Path.GetFullPath("."), "security-windows-" + new string('a', 32), "python");
            string python = Path.Combine(runtime, "python.exe");
            RequirePath(python, python);
            RequireLaunch(python, new [] { "-I", "-B", "-c", "pass" }, runtime, python);
            foreach (Action action in new Action[] {
                () => RequirePath(Path.Combine(runtime, "startup-python.exe"), python),
                () => RequirePath(Path.Combine(runtime, "pythonw.exe"), python),
                () => RequirePath(Path.Combine(Path.GetDirectoryName(runtime), "other", "python.exe"), python),
                () => RequirePath("python.exe", python),
                () => RequireLaunch(python, new [] { "-I", "-B", "-c", "private-sentinel" }, runtime, python),
                () => RequireLaunch(python, new [] { "-I", "-B", "-c", "pass", "extra" }, runtime, python),
                () => RequireLaunch(python, null, runtime, python),
                () => RequireLaunch(python, new [] { "-I", "-B", "-c", "pass" }, Path.GetDirectoryName(runtime), python)
            }) Refuse(action);
            byte[] abc = { 97, 98, 99 };
            const string hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
            RequireBytes(abc, 3, hash);
            Refuse(() => RequireBytes(abc, 4, hash)); Refuse(() => RequireBytes(new byte[] { 97, 98, 100 }, 3, hash));
            Refuse(() => RequireBytes(new byte[0], 0, hash));
            CheckAcquisition(); Sandbox.CheckPythonDispatchRole(); TrustedSetup.CheckPythonDispatchRole();
            Need(prepared == null && !hostPositive);
        }
        static void CheckTransport()
        {
            foreach (bool traced in new [] { false, true }) {
                uint[] codes = { 0, 1, 121, 0x7FFFFFFF, 0xC0000022, 0xC0150002, UInt32.MaxValue };
                foreach (uint code in codes) {
                    var value = new CsrDispatchObservation(traced, pythonPass: true); value.Record(code, "", "");
                    string line = value.Metadata();
                    Need(value.recorded && value.exit == code && value.completed == (code == 0) && !value.receipt && value.characters == 0);
                    Need(line.StartsWith("WINDOWS_PYTHON_CSR_TRANSPORT traced=" + traced + " raw_process_exit=0x" + code.ToString("X8"), StringComparison.Ordinal) &&
                        line.Contains("pass_code_completed=" + (code == 0)) && line.Contains("stdout_empty=True stderr_empty=True") &&
                        line.Contains("invocation_module_verified=False failing_request_verified=False server_operation_verified=False") &&
                        line.EndsWith("cause_claimed=False target_admitted=False production_grant=False undebugged_equivalence_claimed=False", StringComparison.Ordinal) &&
                        line.Length < 1024 && !line.Contains("private-sentinel") && !line.Contains("C:\\private"));
                    Refuse(() => value.Record(code, "", ""));
                    Refuse(() => new CsrDispatchObservation(traced, pythonPass: true).Record(code, "private-sentinel", ""));
                    Refuse(() => new CsrDispatchObservation(traced, pythonPass: true).Record(code, "", "private-sentinel"));
                }
            }
            Refuse(() => new CsrDispatchObservation(true, true, true));
            Need(HostTransport(0, "", "") == HostResult);
            foreach (uint code in new uint[] { 1, 121, 0xC0150002, UInt32.MaxValue })
                Refuse(() => HostTransport(code, "", ""));
            Refuse(() => HostTransport(0, "private-sentinel", ""));
            Refuse(() => HostTransport(0, "", "private-sentinel"));
        }
        static void CheckHost()
        {
            for (int mode = 0; mode < 8; mode++) {
                var order = new List<string>(); Exception caught = null;
                var operation = new InvalidOperationException("fixed host"); var cleanup = new InvalidOperationException("fixed close");
                try {
                    CompleteHost(retain => {
                        order.Add("process-clean"); if (mode != 1) retain("fixed");
                        if (mode == 2 || mode == 7) throw operation;
                        return mode == 6 ? "pass_code_completed=False" : HostResult;
                    }, () => { order.Add("lease-close"); if (mode == 3 || mode == 7) throw cleanup; },
                    line => { order.Add(line == "fixed" ? "metadata" : "positive");
                        if (mode == 4 || mode == 5 && line != "fixed") throw new InvalidOperationException("fixed report"); }, () => order.Add("latch"));
                } catch (Exception error) { caught = error; }
                Need((caught == null) == (mode == 0) && order.Contains("lease-close") && order.Contains("latch") == (mode == 0));
                if (mode == 0) Need(String.Join(",", order) == "process-clean,lease-close,metadata,positive,latch");
                if (mode == 7) {
                    var group = caught as AggregateException;
                    Need(group != null && Object.ReferenceEquals(group.InnerExceptions[0], operation) && Object.ReferenceEquals(group.InnerExceptions[1], cleanup));
                }
            }
        }
        static void CheckComparison()
        {
            var operation = new InvalidOperationException("fixed trace"); var cleanup = new InvalidOperationException("fixed cleanup");
            for (int mode = 0; mode < 7; mode++) {
                var order = new List<string>(); Exception caught = null, result = null;
                try {
                    result = CsrDispatchComparison.Execute(value => {
                        Need(value.python && !value.module); order.Add(value.traced ? "trace" : "undebugged");
                        if (value.traced && (mode == 2 || mode == 3)) throw CsrDispatchComparison.FinishUndebugged(operation,
                            mode == 3 ? new List<Exception> { cleanup } : new List<Exception>(), true, true, true);
                        value.Record(mode == 0 || mode == 4 && !value.traced || mode == 5 && value.traced ? 0U : 0xC0150002U, "", "");
                    }, () => Tuple.Create<Action, Action>(() => order.Add("restore"), () => order.Add("defer")), _ => {
                        order.Add("emit"); if (mode == 6) throw cleanup;
                    }, python: true);
                } catch (Exception error) { caught = error; }
                if (mode == 3) Need(caught is AggregateException && result == null && String.Join(",", order) == "trace,defer");
                else if (mode == 6) {
                    var group = caught as AggregateException;
                    Need(group != null && group.InnerExceptions[0].Message == "fixed Python CSR pass failed raw_process_exit=0xC0150002" &&
                        Object.ReferenceEquals(group.InnerExceptions[1], cleanup) && String.Join(",", order) == "trace,emit,restore");
                } else {
                    Need(caught == null && (mode == 0 ? result == null : result != null) &&
                        String.Join(",", order) == (mode == 2 ? "trace,undebugged,emit,restore" : "trace,emit,undebugged,emit,restore"));
                    if (mode == 2) {
                        var group = result as AggregateException;
                        Need(group != null && Object.ReferenceEquals(group.InnerExceptions[0], operation));
                    }
                    if (mode == 4 || mode == 5) Need(result.Message == "fixed Python CSR pass failed raw_process_exit=0xC0150002");
                }
            }
            CsrDispatchComparison.CheckPythonFailureRetention();
        }
        sealed class CheckLease : IDisposable
        {
            readonly List<int> order; readonly int index; readonly bool fail;
            internal CheckLease(List<int> result, int value, bool failure) { order = result; index = value; fail = failure; }
            public void Dispose() { order.Add(index); if (fail) throw new IOException("fixed close"); }
        }
        static void CheckAcquisition()
        {
            for (int mode = 0; mode < 4; mode++) {
                var order = new List<int>(); Exception caught = null;
                var operation = new IOException("fixed identity");
                try {
                    IDisposable lease = ModuleActivationFixture.Acquire(new Func<IDisposable>[] {
                        () => new CheckLease(order, 0, mode == 3), () => new CheckLease(order, 1, mode == 3),
                        () => { if (mode == 1) throw operation; return new CheckLease(order, 2, mode == 3); }
                    }, values => { Need(values.Count == 3); if (mode == 2 || mode == 3) throw operation; });
                    Need(order.Count == 0); lease.Dispose(); lease.Dispose();
                } catch (Exception error) { caught = error; }
                Need((caught == null) == (mode == 0) && String.Join(",", order) == (mode == 1 ? "1,0" : "2,1,0"));
                if (mode == 3) {
                    var group = caught as AggregateException;
                    Need(group != null && group.InnerExceptions.Count == 4 && Object.ReferenceEquals(group.InnerExceptions[0], operation));
                }
            }
        }
        static void CheckIdentity(string work)
        {
            string owner = Path.Combine(Path.GetFullPath(work), "python-csr-validation-" + Guid.NewGuid().ToString("N"));
            DefaultActivationFixture.Missing(owner); Directory.CreateDirectory(owner);
            string run = new string('c', 32), state = Path.Combine(owner, "security-windows-" + run);
            string runtime = Path.Combine(state, "python"), python = Path.Combine(runtime, "python.exe");
            byte[][] bytes = KernelImage.PythonDispatchFixtures();
            try {
                Directory.CreateDirectory(runtime);
                for (int index = 0; index < Images.Length; index++) File.WriteAllBytes(Path.Combine(runtime, Images[index]), bytes[index]);
                Identity identity = null;
                using (Acquire(python, null, value => identity = value)) { }
                Need(identity != null && identity.python == python && identity.language == 1033 && identity.manifestLength == 3);
                using (Acquire(python, identity, _ => { })) {
                    foreach (string name in Images) {
                        bool refused = false;
                        try { using (new FileStream(Path.Combine(runtime, name), FileMode.Open, FileAccess.Write, FileShare.ReadWrite)) { } }
                        catch (IOException) { refused = true; }
                        Need(refused);
                    }
                }
                for (int index = 0; index < Images.Length; index++) {
                    string path = Path.Combine(runtime, Images[index]); byte[] changed = (byte[])bytes[index].Clone(); changed[changed.Length - 1] ^= 1;
                    File.WriteAllBytes(path, changed); Refuse(() => { using (Acquire(python, identity, _ => { })) { } });
                    File.WriteAllBytes(path, bytes[index]);
                }
                byte[] different = (byte[])bytes[1].Clone(); different[0x580] ^= 1;
                File.WriteAllBytes(Path.Combine(runtime, Images[1]), different);
                Refuse(() => { using (Acquire(python, null, _ => { })) { } });
                File.WriteAllBytes(Path.Combine(runtime, Images[1]), bytes[1]);
                foreach (string name in new [] { "python.exe.config", "python311.dll.manifest", "vcruntime140.dll.config", "python._pth", "python311._pth", "pyvenv.cfg" }) {
                    string sidecar = Path.Combine(runtime, name);
                    File.WriteAllText(sidecar, "unchanged", new System.Text.UTF8Encoding(false, true));
                    Refuse(() => { using (Acquire(python, identity, _ => { })) { } });
                    Need(File.ReadAllText(sidecar, System.Text.Encoding.UTF8) == "unchanged"); File.Delete(sidecar);
                }
                Need(PythonStartupFixture.Runtime(run, state) == runtime);
                Refuse(() => PythonStartupFixture.Runtime(new string('d', 32), state));
                using (Acquire(python, identity, _ => { })) { }
            } finally {
                foreach (byte[] buffer in bytes) Array.Clear(buffer, 0, buffer.Length);
                Directory.Delete(owner, true);
            }
        }
        static void RequirePath(string python, string expected)
        {
            Need(python != null && expected != null && Path.IsPathFullyQualified(python) && Path.IsPathFullyQualified(expected) &&
                python == Path.GetFullPath(python) && python == expected && Path.GetFileName(python) == "python.exe" &&
                Path.GetFileName(Path.GetDirectoryName(python)) == "python");
        }
        static void RequireLaunch(string executable, string[] arguments, string cwd, string expected)
        {
            RequirePath(executable, expected);
            Need(cwd == Path.GetDirectoryName(expected) && arguments != null && arguments.SequenceEqual(new [] { "-I", "-B", "-c", "pass" }));
        }
        static void RequireBytes(byte[] bytes, int length, string hash)
        { Need(bytes != null && length > 0 && length <= 16777216 && bytes.Length == length && ModuleActivationFixture.Digest(bytes) == hash); }
        static Identity Qualify(string python, List<IDisposable> resources, Identity expected)
        {
            Need(resources.Count == 3); var buffers = new List<byte[]>();
            try {
                var candidate = new Identity { python = python, hashes = new string[3], lengths = new int[3] };
                for (int index = 0; index < 3; index++) {
                    byte[] bytes = ModuleActivationFixture.Read((FileStream)resources[index], 16777216); buffers.Add(bytes);
                    KernelImage.QualifyPythonImports(bytes, Imports[index]); candidate.hashes[index] = ModuleActivationFixture.Digest(bytes); candidate.lengths[index] = bytes.Length;
                    if (expected != null) RequireBytes(bytes, expected.lengths[index], expected.hashes[index]);
                }
                var exe = KernelImage.DefaultManifest(buffers[0], false); buffers.Add(exe.Item2);
                var dll = KernelImage.ModuleManifest(buffers[1], false); buffers.Add(dll.Item2);
                Need(exe.Item1 == dll.Item1 && exe.Item2.SequenceEqual(dll.Item2));
                candidate.language = exe.Item1; candidate.manifestHash = ModuleActivationFixture.Digest(exe.Item2); candidate.manifestLength = exe.Item2.Length;
                if (expected != null) Need(candidate.language == expected.language && candidate.manifestHash == expected.manifestHash && candidate.manifestLength == expected.manifestLength);
                KernelImage.QualifyPythonDispatchImage(buffers[0], candidate.hashes[0], candidate.lengths[0], candidate.language, candidate.manifestHash, candidate.manifestLength);
                return candidate;
            } finally { foreach (byte[] bytes in buffers) Array.Clear(bytes, 0, bytes.Length); }
        }
        static IDisposable Acquire(string python, Identity expected, Action<Identity> accept)
        {
            string runtime = Path.GetDirectoryName(python); PythonStartupFixture.Overrides(runtime);
            DefaultActivationFixture.Missing(Path.Combine(runtime, "python311._pth"));
            foreach (string name in Images) DefaultActivationFixture.NoOverrides(Path.Combine(runtime, name));
            return ModuleActivationFixture.Acquire(Images.Select(name => (Func<IDisposable>)(() => PythonStartupFixture.Open(Path.Combine(runtime, name)))).ToArray(),
                values => accept(Qualify(python, values, expected)));
        }
        public static void Prepare(string run, string state)
        {
            Need(prepared == null && !hostPositive); string python = Path.Combine(PythonStartupFixture.Runtime(run, state), "python.exe");
            RequirePath(python, python); Identity candidate = null;
            using (Acquire(python, null, value => candidate = value)) { }
            Need(candidate != null); prepared = candidate;
        }
        internal static string PreparedImage(string python)
        { Need(prepared != null); RequirePath(python, prepared.python); return prepared.python; }
        internal static IDisposable Hold(string python)
        { PreparedImage(python); return Acquire(python, prepared, _ => { }); }
        internal static ushort PreparedLanguage(string python)
        { PreparedImage(python); return prepared.language; }
        internal static void RequireImage(string python, byte[] bytes)
        {
            PreparedImage(python);
            KernelImage.QualifyPythonDispatchImage(bytes, prepared.hashes[0], prepared.lengths[0], prepared.language, prepared.manifestHash, prepared.manifestLength);
        }
        internal static void RequireLaunch(string executable, string[] arguments, string cwd)
        { RequireLaunch(executable, arguments, cwd, PreparedImage(executable)); }
        internal static ActivationBoundaryTrace Observer(string python, Native.ProcessInfo child, Action<string> emit, Action deadline)
        {
            PreparedImage(python);
            return new ActivationBoundaryTrace(child.process, child.thread, child.pid, child.tid, python, prepared.hashes[0], emit,
                resource: true, resourceDeadline: deadline, dispatch: true, pythonDispatch: true);
        }
        internal static void RequireHostPositive(string python)
        { PreparedImage(python); Need(hostPositive); }
        internal static string HostTransport(uint exit, string text, string errors)
        {
            var value = new CsrDispatchObservation(true, pythonPass: true); value.Record(exit, text, errors);
            Need(value.completed); return HostResult;
        }
        public static void RunHost(string python)
        {
            Need(!hostPositive); IDisposable held = Hold(python);
            CompleteHost(retain => TrustedSetup.RunPythonCsrDispatch(python, retain), held.Dispose,
                line => { Console.Out.WriteLine(line); Console.Out.Flush(); }, () => hostPositive = true);
        }
        static void CompleteHost(Func<Action<string>, string> run, Action close, Action<string> emit, Action accept)
        {
            Exception primary = null; string metadata = null;
            try {
                string result = run(line => { Need(metadata == null && line != null && line.Length <= 4096); metadata = line; });
                Need(result == HostResult && metadata != null);
            } catch (Exception error) { primary = error; throw; }
            finally {
                try { close(); } catch (Exception cleanup) {
                    if (primary != null) throw new AggregateException("Python CSR host operation/lease cleanup failed", primary, cleanup);
                    throw;
                }
            }
            emit(metadata);
            emit("WINDOWS_PYTHON_CSR_HOST positive=True cleanup_complete=True invocation_module_verified=False failing_request_verified=False server_operation_verified=False cause_claimed=False target_admitted=False production_grant=False undebugged_equivalence_claimed=False");
            accept();
        }
    }
    public static partial class CsrDispatchComparison
    {
        static Exception pythonRetained;
        public static void RunPython(string run, string state, string python, string root, string scratch, string powershell,
            string chromium, string moniker, string profileFolder, int tcpPort, int udpPort)
        {
            Need(pythonRetained == null); PythonCsrDispatch.RequireHostPositive(python); LoaderSnaps.RequireClean(run, state);
            pythonRetained = Execute(value => Sandbox.ObservePythonCsrDispatch(python, root, scratch, powershell, chromium,
                moniker, profileFolder, tcpPort, udpPort, value), () => {
                    var lease = RegistryPolicyLease.Begin(run, state);
                    return Tuple.Create<Action, Action>(lease.Dispose, lease.DeferRecovery);
                }, line => { Console.Out.WriteLine(line); Console.Out.Flush(); }, python: true);
        }
        internal static void CheckPythonFailureRetention()
        {
            Need(retained == null && moduleRetained == null && pythonRetained == null);
            var first = new Exception("fixed explicit"); var second = new Exception("fixed module");
            var third = new Exception("fixed Python"); var later = new Exception("fixed later");
            retained = first; moduleRetained = second; pythonRetained = third;
            var combined = PreserveFailure(later) as AggregateException;
            var roles = combined == null ? null : combined.InnerExceptions[0] as AggregateException;
            var earlier = roles == null ? null : roles.InnerExceptions[0] as AggregateException;
            Need(earlier != null && Object.ReferenceEquals(earlier.InnerExceptions[0], first) && Object.ReferenceEquals(earlier.InnerExceptions[1], second) &&
                Object.ReferenceEquals(roles.InnerExceptions[1], third) && Object.ReferenceEquals(combined.InnerExceptions[1], later));
            Need(PreserveFailure(null) == null);
        }
    }
    public static partial class TrustedSetup
    {
        internal static string RunPythonCsrDispatch(string python, Action<string> retainMetadata)
        {
            string image = PythonCsrDispatch.PreparedImage(python);
            return RunFixed(image, new [] { "-I", "-B", "-c", "pass" }, Path.GetDirectoryName(image), true,
                entryPython: python, retainMetadata: retainMetadata, resource: true, dispatch: true, pythonDispatch: true);
        }
        internal static void CheckPythonDispatchRole()
        {
            foreach (Action action in new Action[] {
                () => RunFixed(null, null, null, false, pythonDispatch: true),
                () => RunFixed(null, null, null, true, entryPython: "fixed", retainMetadata: _ => { }, resource: true, pythonDispatch: true),
                () => RunFixed(null, null, null, true, SelfActivationRole.ExplicitId2, "fixed", _ => { }, true, dispatch: true, pythonDispatch: true),
                () => RunFixed(null, null, null, true, entryPython: "fixed", retainMetadata: _ => { }, resource: true, dispatch: true, moduleDispatch: true, pythonDispatch: true),
                () => Run(Path.Combine(Path.GetFullPath("."), "python", "python.exe"), new [] { "-I", "-B", "-c", "pass" }, Path.GetFullPath("."))
            }) {
                bool refused = false; try { action(); } catch (ArgumentException) { refused = true; }
                PythonCsrDispatch.Need(refused);
            }
            PythonCsrDispatch.Need(Stage("python.exe", "create-before") == "WINDOWS_SETUP_STAGE tool=python.exe stage=create-before");
        }
    }
    public static partial class Sandbox
    {
        internal static void ObservePythonCsrDispatch(string python, string root, string scratch, string powershell,
            string chromium, string moniker, string profileFolder, int tcpPort, int udpPort, CsrDispatchObservation observation)
        {
            PythonCsrDispatch.Need(observation != null && observation.python && !observation.module);
            PythonCsrDispatch.RequireHostPositive(python);
            RunFixed(python, root, scratch, powershell, chromium, moniker, profileFolder, true, tcpPort, udpPort,
                false, false, false, false, false, false, false, 0, dispatch: observation);
        }
        internal static void CheckPythonDispatchRole()
        {
            foreach (Action action in new Action[] {
                () => RunFixed(null, null, null, null, null, null, null, false, 0, 0, false, false, false, false, false, false, false, 0, dispatch: new CsrDispatchObservation(true, pythonPass: true)),
                () => RunFixed(null, null, null, null, null, null, null, true, 0, 0, false, false, false, false, false, false, false, 0, moduleRole: 2, dispatch: new CsrDispatchObservation(true, pythonPass: true)),
                () => RunFixed(null, null, null, null, null, null, null, true, 0, 0, false, false, false, false, false, false, false, 0, selfActivation: true, dispatch: new CsrDispatchObservation(true, pythonPass: true)),
                () => RunFixed(null, null, null, null, null, null, null, true, 0, 0, false, false, false, false, false, false, false, 0, selfResource: true, dispatch: new CsrDispatchObservation(true, pythonPass: true)),
                () => RunFixed(null, null, null, null, null, null, null, true, 0, 0, false, true, false, false, false, false, false, 0, dispatch: new CsrDispatchObservation(true, pythonPass: true))
            }) {
                bool refused = false; try { action(); } catch (ArgumentException) { refused = true; }
                PythonCsrDispatch.Need(refused);
            }
        }
    }
    public sealed partial class KernelImage
    {
        internal static KernelImage FromPythonDispatchCreation(IntPtr file, IntPtr imageBase, string expectedPath, string digest)
        {
            string expected = PythonCsrDispatch.PreparedImage(expectedPath), actual = EventPath(file);
            Need(actual != null && String.Equals(actual, expected, StringComparison.OrdinalIgnoreCase));
            var image = ReadEventImage(file, imageBase, "fixed-original-python-csr");
            Need(Hash(image.data) == digest); PythonCsrDispatch.RequireImage(expected, image.data);
            return image;
        }
        internal static void QualifyPythonDispatchImage(byte[] bytes, string digest, int length, ushort language, string payloadHash, int payloadLength)
        {
            Need(bytes != null && bytes.Length == length && Hash(bytes) == digest);
            var image = new KernelImage(bytes, 1, "fixed-original-python-csr");
            Need(image.Entry != 0 && image.FullExecutable(image.Entry, 1)); QualifyPythonImports(bytes, "python-exe");
            var manifest = DefaultManifest(bytes, false);
            try { Need(manifest.Item1 == language && manifest.Item2.Length == payloadLength && Hash(manifest.Item2) == payloadHash); }
            finally { Array.Clear(manifest.Item2, 0, manifest.Item2.Length); }
        }
        internal static byte[][] PythonDispatchFixtures()
        {
            byte[][] images = {
                ImportFixture(new [] { "KERNEL32.dll", "python311.dll", "VCRUNTIME140.dll" }),
                ImportFixture(new [] { "ADVAPI32.dll", "bcrypt.dll", "KERNEL32.dll", "VCRUNTIME140.dll", "VERSION.dll", "WS2_32.dll" }),
                ImportFixture(new [] { "KERNEL32.dll" })
            };
            for (int index = 0; index < 2; index++) {
                byte[] image = images[index]; Array.Resize(ref image, 2048); images[index] = image;
                Put(image, 0x188 + 8, 0x600); Put(image, 0x188 + 16, 0x600);
                Put(image, 0x98 + 128, 0x1300); Put(image, 0x98 + 132, 0x100);
                Put16(image, 0x50E, 1); Put(image, 0x510, 24); Put(image, 0x514, 0x80000020);
                Put16(image, 0x52E, 1); Put(image, 0x530, index == 0 ? 1U : 2U); Put(image, 0x534, 0x80000040);
                Put16(image, 0x54E, 1); Put(image, 0x550, 1033); Put(image, 0x554, 0x60);
                Put(image, 0x560, 0x1380); Put(image, 0x564, 3); System.Text.Encoding.ASCII.GetBytes("abc").CopyTo(image, 0x580);
            }
            return images;
        }
        internal static void CheckPythonDispatchIdentity()
        {
            byte[] bytes = PythonDispatchFixtures()[0];
            const string payload = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
            string digest = Hash(bytes); QualifyPythonDispatchImage(bytes, digest, 2048, 1033, payload, 3);
            foreach (Action<byte[]> mutate in new Action<byte[]>[] {
                b => Put(b, 0x98 + 16, 0), b => b[0x300] ^= 1, b => Put(b, 0x530, 2),
                b => Put(b, 0x550, 1034), b => b[0x580] ^= 1, b => Put(b, 0x564, 4)
            }) {
                byte[] bad = (byte[])bytes.Clone(); mutate(bad); bool refused = false;
                try { QualifyPythonDispatchImage(bad, Hash(bad), 2048, 1033, payload, 3); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            foreach (Action action in new Action[] {
                () => QualifyPythonDispatchImage(bytes, digest, 2049, 1033, payload, 3),
                () => QualifyPythonDispatchImage(bytes, payload, 2048, 1033, payload, 3)
            }) { bool refused = false; try { action(); } catch (InvalidOperationException) { refused = true; } Need(refused); }
        }
    }
}
