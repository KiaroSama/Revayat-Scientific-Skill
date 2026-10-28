using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace ScientificSecurity
{
    public static partial class StartupActivationAccess
    {
        static bool dllObserved;
        delegate IntPtr DllCreate(out uint error);
        sealed class DllManifestIdentity
        {
            internal ushort language;
            internal int length, imageLength;
            internal string digest, imageDigest;
        }
        static ActCtx FixedDll(string path)
        { return new ActCtx { size = 56, flags = 8, source = path, resource = new IntPtr(2) }; }
        static void DllNeed(bool value)
        { if (!value) throw new InvalidOperationException("fixed DLL activation evidence is inconclusive"); }
        static DllManifestIdentity ReadDllManifest(string path)
        {
            NativeFixture.Plain(path); DefaultActivationFixture.NoOverrides(path);
            byte[] bytes = null, payload = null;
            try {
                using (var held = ModuleActivationFixture.Open(path)) bytes = ModuleActivationFixture.Read(held, 16777216);
                var manifest = KernelImage.ModuleManifest(bytes, false); payload = manifest.Item2;
                return new DllManifestIdentity { language = manifest.Item1, length = payload.Length,
                    digest = ModuleActivationFixture.Digest(payload), imageLength = bytes.Length,
                    imageDigest = ModuleActivationFixture.Digest(bytes) };
            }
            finally {
                if (payload != null) Array.Clear(payload, 0, payload.Length);
                if (bytes != null) Array.Clear(bytes, 0, bytes.Length);
            }
        }
        static void SameDllManifest(DllManifestIdentity first, DllManifestIdentity later)
        {
            DllNeed(first != null && later != null && first.language == later.language && first.length == later.length &&
                first.imageLength == later.imageLength && first.digest == later.digest && first.imageDigest == later.imageDigest);
        }
        static string DllMetadata(DllManifestIdentity manifest, bool created, uint error, bool released)
        {
            DllNeed(manifest != null && manifest.length > 0 && manifest.length <= 65536);
            DllNeed(created ? error == 0 && released : error != 0 && !released);
            string line = "WINDOWS_DLL_ACTIVATION context=host resource_type=24 resource_id=2 resource_language=" + manifest.language +
                " manifest_bytes=" + manifest.length + " created=" + created + " win32_error=" + error +
                " release_returned=" + released + " cache_reset_claimed=False cause_claimed=False child_equivalence_claimed=False";
            DllNeed(line.Length <= 512); return line;
        }
        // The same finite owner/result seam runs native observation and inert lifecycle fixtures.
        static void ExecuteFixedDll(Func<IDisposable> acquire, Action qualify, DllCreate create, Action<IntPtr> release,
            Action readback, Action deadline, Action<bool, uint, bool> emit)
        {
            IDisposable held = null; IntPtr handle = Native.InvalidHandle;
            uint error = 0; bool created = false, released = false; Exception primary = null;
            var failures = new List<Exception>();
            try {
                deadline(); held = acquire(); DllNeed(held != null); qualify(); deadline();
                handle = create(out error);
                DllNeed(handle != IntPtr.Zero);
                created = handle != Native.InvalidHandle;
                DllNeed(created ? error == 0 : error != 0); deadline();
            }
            catch (Exception failure) { primary = failure; }
            finally {
                if (handle != Native.InvalidHandle && handle != IntPtr.Zero)
                    Attempt(failures, () => { release(handle); released = true; });
            }
            if (primary == null && failures.Count == 0) Attempt(failures, () => { deadline(); readback(); deadline(); });
            if (held != null) Attempt(failures, held.Dispose);
            if (primary != null) failures.Insert(0, primary);
            if (failures.Count != 0) throw new AggregateException("fixed DLL activation operation/finalization failed", failures);
            deadline(); emit(created, error, released); deadline();
        }
        static void SafeFixedDll(Action action)
        {
            try { action(); }
            catch (Exception failure) {
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(RegistryLoaderEvidence.Sanitize(failure)).Throw(); throw;
            }
        }
        public static void ObserveFixedDll(string python)
        {
            SafeFixedDll(() => {
                DllNeed(!dllObserved); dllObserved = true;
                CheckValidation(); RequirePreparationHost();
                string path = Path.Combine(Path.GetDirectoryName(python), "DLLs", "_ctypes.pyd");
                DllManifestIdentity manifest = null; var clock = Stopwatch.StartNew();
                ExecuteFixedDll(() => RegistryLoaderFixture.Hold(python),
                    () => { RequirePreparationHost(); manifest = ReadDllManifest(path); },
                    (out uint error) => {
                        RequirePreparationHost(); ActCtx context = FixedDll(path);
                        IntPtr handle = CreateActCtxW(ref context);
                        error = handle == Native.InvalidHandle ? unchecked((uint)Marshal.GetLastWin32Error()) : 0;
                        return handle;
                    }, handle => ReleaseActCtx(handle),
                    () => { RequirePreparationHost(); SameDllManifest(manifest, ReadDllManifest(path)); },
                    () => Deadline(clock),
                    (created, error, released) => { Console.Out.WriteLine(DllMetadata(manifest, created, error, released)); Console.Out.Flush(); });
            });
        }
        sealed class DllCheckLease : IDisposable
        {
            readonly Action close;
            internal DllCheckLease(Action close) { this.close = close; }
            public void Dispose() { close(); }
        }
        public static void CheckFixedDllValidation()
        {
            var fixedCall = FixedDll(@"C:\owned space\python\DLLs\_ctypes.pyd");
            DllNeed(IntPtr.Size == 8 && Marshal.SizeOf(typeof(ActCtx)) == 56 && fixedCall.size == 56 && fixedCall.flags == 8 &&
                fixedCall.source == @"C:\owned space\python\DLLs\_ctypes.pyd" && fixedCall.resource == new IntPtr(2) &&
                fixedCall.architecture == 0 && fixedCall.language == 0 && fixedCall.assemblyDirectory == null &&
                fixedCall.application == null && fixedCall.module == IntPtr.Zero);
            foreach (IntPtr result in new [] { IntPtr.Zero, Native.InvalidHandle, new IntPtr(7) })
                foreach (uint error in new uint[] { 0, 5, UInt32.MaxValue }) {
                    int releases = 0, closes = 0, reports = 0; Exception caught = null;
                    try {
                        ExecuteFixedDll(() => new DllCheckLease(() => closes++), () => { },
                            (out uint code) => { code = error; return result; },
                            handle => { DllNeed(handle == result); releases++; }, () => { }, () => { },
                            (created, code, released) => {
                                reports++; DllNeed(created == (result != Native.InvalidHandle) && code == error && released == created);
                            });
                    } catch (Exception failure) { caught = failure; }
                    bool validHandle = result != IntPtr.Zero && result != Native.InvalidHandle;
                    bool qualified = result != IntPtr.Zero && (validHandle ? error == 0 : error != 0);
                    DllNeed((caught == null) == qualified && releases == (validHandle ? 1 : 0) && closes == 1 && reports == (qualified ? 1 : 0));
                }
            for (int mode = 0; mode < 8; mode++) {
                var order = new List<string>(); var operation = new IOException("private-dll-path-sentinel");
                var cleanup = new IOException("private-dll-cleanup-sentinel"); Exception caught = null; int deadlines = 0;
                try {
                    SafeFixedDll(() => ExecuteFixedDll(() => {
                        order.Add("acquire"); if (mode == 0) throw operation;
                        return new DllCheckLease(() => { order.Add("close"); if (mode == 5 || mode == 7) throw cleanup; });
                    }, () => { order.Add("qualify"); if (mode == 1) throw operation; },
                    (out uint code) => { order.Add("create"); code = 0; if (mode == 2) throw operation; return new IntPtr(7); },
                    _ => { order.Add("release"); if (mode == 3 || mode == 7) throw cleanup; },
                    () => { order.Add("readback"); if (mode == 4) throw operation; },
                    () => { deadlines++; if (mode == 7 && deadlines == 3) throw operation; },
                    (_, __, ___) => { order.Add("emit"); if (mode == 6) throw operation; }));
                } catch (Exception failure) { caught = failure; }
                DllNeed(caught != null && !caught.ToString().Contains("sentinel"));
                DllNeed(order.Contains("close") == (mode != 0) && order.Contains("release") == (mode >= 3));
                DllNeed(order.Contains("emit") == (mode == 6));
                if (mode == 7) {
                    var group = caught as AggregateException;
                    DllNeed(group != null && group.InnerExceptions.Count == 3);
                    var first = group.InnerExceptions[0] as RegistryLoaderEvidence.PrivateFailure;
                    DllNeed(first != null && Object.ReferenceEquals(first.Original, operation));
                }
            }
            var identity = new DllManifestIdentity { language = 1033, length = 4, imageLength = 512, digest = "fixed", imageDigest = "image" };
            SameDllManifest(identity, identity);
            DllNeed(DllMetadata(identity, true, 0, true).Contains("created=True win32_error=0 release_returned=True"));
            DllNeed(DllMetadata(identity, false, 14001, false).Contains("created=False win32_error=14001 release_returned=False"));
            foreach (Action change in new Action[] {
                () => SameDllManifest(identity, new DllManifestIdentity { language = 0 }),
                () => DllMetadata(identity, true, 5, true), () => DllMetadata(identity, true, 0, false),
                () => DllMetadata(identity, false, 0, false), () => DllMetadata(identity, false, 5, true) }) {
                bool refused = false; try { change(); } catch (InvalidOperationException) { refused = true; } DllNeed(refused);
            }
        }
    }
}
