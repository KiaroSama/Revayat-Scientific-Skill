using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace ScientificSecurity
{
    public static partial class Sandbox
    {
        // Production and inert fixtures share ordering, receipt retention and qualification.
        internal static Exception CompleteRun(Exception primary, Action terminate, Action reap, Action confirm,
            Func<uint?> queryExit, Action closeOutput, Action<Action<byte[], bool>> closeError, Action[] release,
            bool authority, bool trace, bool observed, bool callback, bool undebugged, bool started, bool signaled,
            Func<string> metadata, Action<string> emit)
        {
            var failures = new List<Exception>();
            AttemptCleanup(failures, terminate);
            bool reaped = false, destroyed = false;
            AttemptCleanup(failures, () => { reap(); reaped = true; });
            if (reaped && confirm != null) AttemptCleanup(failures, () => { confirm(); destroyed = true; });
            uint? exit = null;
            if (authority && primary != null && queryExit != null) AttemptCleanup(failures, () => exit = queryExit());
            Exception operation = primary;
            byte[] receipt = null; bool truncatedReceipt = false;
            AttemptCleanup(failures, closeOutput);
            AttemptCleanup(failures, () => closeError(!authority || operation == null ? null : (Action<byte[], bool>)((bytes, truncated) => {
                if (RegistryLoaderEvidence.FromPrefix(bytes, truncated) == null) return;
                if (receipt != null) Array.Clear(receipt, 0, receipt.Length);
                receipt = (byte[])bytes.Clone(); truncatedReceipt = truncated;
            })));
            try {
                if (receipt != null && !(operation is RegistryLoaderEvidence.ReceiptFailure))
                    primary = RegistryLoaderEvidence.Preserve(operation, exit, receipt, truncatedReceipt);
            } catch (Exception projection) { failures.Add(projection); }
            finally { if (receipt != null) Array.Clear(receipt, 0, receipt.Length); }
            foreach (Action action in release) AttemptCleanup(failures, action);
            Exception result = trace ? ExplicitEntryComparison.FinishTrace(primary, failures, observed, destroyed, metadata, emit) :
                undebugged ? CsrDispatchComparison.FinishUndebugged(primary, failures, started, signaled, reaped) :
                CompletionFailure(primary, failures, callback, destroyed);
            return authority ? RegistryLoaderEvidence.Sanitize(result) : result;
        }
        internal static uint? ActualExit(bool started, Func<uint> signal, Func<uint> query)
        {
            if (!started) return null;
            uint observed = signal();
            if (observed == 0x102) return null;
            if (observed != 0) throw new InvalidOperationException("authority failure process signal is unqualified");
            return query();
        }
        internal static void CheckCompletionValidation()
        {
            const string frame = "REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=import-ctypes:import-ctypes-native\n";
            byte[] prefix = System.Text.Encoding.ASCII.GetBytes(frame);
            int queries = 0;
            RegistryAuthorityComparison.Need(ActualExit(false, () => { throw new InvalidOperationException("unexpected signal"); }, () => { queries++; return 1; }) == null);
            RegistryAuthorityComparison.Need(ActualExit(true, () => 0x102, () => { queries++; return 259; }) == null && queries == 0);
            RegistryAuthorityComparison.Need(ActualExit(true, () => 0, () => { queries++; return 259; }) == 259 && queries == 1);
            foreach (bool queryFailure in new [] { false, true }) {
                bool refused = false;
                try { ActualExit(true, () => queryFailure ? 0U : UInt32.MaxValue, () => { throw new InvalidOperationException("fixed query failed"); }); }
                catch (InvalidOperationException) { refused = true; }
                RegistryAuthorityComparison.Need(refused);
            }
            for (int mode = 0; mode < 10; mode++) {
                var order = new List<string>();
                Exception operation = mode == 1 ? (Exception)new InvalidOperationException("private-abort") : new TimeoutException("private-timeout");
                if (mode == 9) {
                    try { new System.Text.UTF8Encoding(false, true).GetString(new byte[] { 0xED, 0xA0, 0x80 }); }
                    catch (System.Text.DecoderFallbackException failure) { operation = failure; }
                }
                Exception cleanup = new InvalidOperationException("private-close");
                var result = CompleteRun(operation, () => order.Add("terminate"),
                    () => { order.Add("reap"); if (mode == 2) throw cleanup; }, null,
                    () => { order.Add("query"); if (mode == 3) throw cleanup; return mode == 4 ? (uint?)null : 125U; },
                    () => order.Add("stdout"), retain => {
                        order.Add("stderr");
                        Capture.DisposeStrict(() => { order.Add("snapshot"); if (mode != 5) retain(prefix, mode == 6); },
                            () => order.Add("writer"), () => order.Add("cancel"), () => order.Add("reader"),
                            () => { order.Add("join"); if (mode == 7) throw cleanup; },
                            () => order.Add("drain"), () => order.Add("buffer"), () => order.Add("capture-close"));
                    }, new Action[] { () => order.Add("thread"), () => order.Add("process"),
                        () => { order.Add("job"); if (mode == 8) throw cleanup; }, () => order.Add("lease") },
                    true, false, false, false, true, true, false, () => "", _ => { });
                RegistryAuthorityComparison.Need(result != null && !(result is ExplicitEntryComparison.QualifiedFailure));
                RegistryAuthorityComparison.Need(String.Join(",", order) == "terminate,reap,query,stdout,stderr,snapshot,writer,cancel,reader,join,snapshot,drain,buffer,capture-close,thread,process,job,lease");
                string report = result.ToString();
                RegistryAuthorityComparison.Need(!report.Contains("private") && !report.Contains("[ED]") && !report.Contains("[A0]") && !report.Contains("[80]"));
                if (mode == 9) {
                    var group = result as AggregateException;
                    var retainedOperation = group == null ? null : group.InnerExceptions[1] as RegistryLoaderEvidence.PrivateFailure;
                    RegistryAuthorityComparison.Need(retainedOperation != null && Object.ReferenceEquals(retainedOperation.Original, operation));
                }
                if (mode != 5) RegistryAuthorityComparison.Need(report.Contains("errors=import-ctypes:import-ctypes-native") &&
                    report.Contains(mode == 3 || mode == 4 ? "primary_exit=none" : "primary_exit=0x0000007D"));
            }
            int captures = 0;
            Exception normal = CompleteRun(null, () => { }, () => { }, null, () => { throw new InvalidOperationException("unexpected query"); },
                () => { }, retain => { RegistryAuthorityComparison.Need(retain == null); captures++; }, new Action[] { () => { } },
                true, false, false, false, true, true, true, () => "", _ => { });
            RegistryAuthorityComparison.Need(normal == null && captures == 1);
            foreach (string role in new [] { "ordinary", "callback", "trace", "undebugged" }) {
                foreach (bool failCleanup in new [] { false, true }) {
                    var order = new List<string>(); var operation = new InvalidOperationException("fixed operation");
                    var cleanup = new InvalidOperationException("fixed cleanup");
                    Exception result = CompleteRun(operation, () => order.Add("terminate"), () => order.Add("reap"),
                        role == "ordinary" || role == "undebugged" ? null : (Action)(() => order.Add("destroy")),
                        () => { throw new InvalidOperationException("unexpected authority query"); },
                        () => order.Add("stdout"), retain => { RegistryAuthorityComparison.Need(retain == null); order.Add("stderr"); },
                        new Action[] { () => { order.Add("thread"); if (failCleanup) throw cleanup; }, () => order.Add("lease") },
                        false, role == "trace", true, role == "callback", role == "undebugged", true, true,
                        () => "fixed", _ => order.Add("emit"));
                    string expected = "terminate,reap," + (role == "trace" || role == "callback" ? "destroy," : "") + "stdout,stderr,thread,lease";
                    if (role == "trace" && !failCleanup) expected += ",emit";
                    RegistryAuthorityComparison.Need(String.Join(",", order) == expected);
                    if (failCleanup) {
                        var group = result as AggregateException;
                        RegistryAuthorityComparison.Need(group != null && Object.ReferenceEquals(group.InnerExceptions[0], operation) && Object.ReferenceEquals(group.InnerExceptions[1], cleanup));
                    } else if (role == "ordinary") RegistryAuthorityComparison.Need(result == null);
                    else if (role == "callback") RegistryAuthorityComparison.Need(result is QualifiedModuleCallbackFailure);
                    else RegistryAuthorityComparison.Need(result is ExplicitEntryComparison.QualifiedFailure &&
                        Object.ReferenceEquals(((ExplicitEntryComparison.QualifiedFailure)result).Original, operation));
                }
            }
        }
        static Exception FinishRun(ref Native.ProcessInfo process, IntPtr job, IntPtr sid, IntPtr attrs, IntPtr env,
            IntPtr descriptor, List<IntPtr> handles, List<IntPtr> values, Capture output, Capture error,
            IDisposable held, LoaderTrace loader, Exception primary, bool started, bool resumed, bool boundedReap,
            bool traceCompletion, bool entryStarted, bool callbackStarted, bool undebugged, bool signaled,
            Func<string> metadata, bool authority)
        {
            Native.ProcessInfo owned = process, retained = process;
            var release = new List<Action> {
                () => { if (owned.thread != IntPtr.Zero) Native.Check(Native.CloseHandle(owned.thread), "close owned child thread"); },
                () => { if (owned.process != IntPtr.Zero) Native.Check(Native.CloseHandle(owned.process), "close owned child process"); }
            };
            foreach (IntPtr handle in handles) release.Add(() => Native.Check(Native.CloseHandle(handle), "close owned standard handle"));
            release.Add(() => {
                if (attrs != IntPtr.Zero) {
                    try { Native.DeleteProcThreadAttributeList(attrs); }
                    finally { Marshal.FreeHGlobal(attrs); }
                }
            });
            foreach (IntPtr value in values) release.Add(() => Marshal.FreeHGlobal(value));
            release.Add(() => { if (env != IntPtr.Zero) Marshal.FreeHGlobal(env); });
            release.Add(() => { if (descriptor != IntPtr.Zero && Native.LocalFree(descriptor) != IntPtr.Zero)
                throw new InvalidOperationException("owned process descriptor cleanup failed"); });
            release.Add(() => { if (sid != IntPtr.Zero && Native.FreeSid(sid) != IntPtr.Zero)
                throw new InvalidOperationException("owned package SID cleanup failed"); });
            release.Add(() => { if (job != IntPtr.Zero) Native.Check(Native.CloseHandle(job), "close owned job"); });
            release.Add(() => { if (held != null) held.Dispose(); });
            try {
                return CompleteRun(primary, () => {
                    if (started && loader != null) {
                        loader.SuppressOriginalAliases(ref owned); loader.TerminateAndDrain(job, retained);
                    } else if (started && !resumed) Native.Check(Native.TerminateProcess(owned.process, 125), "terminate suspended child");
                }, () => { if (job != IntPtr.Zero) ReapJob(job, boundedReap && started ? (Func<uint>)loader.RemainingActivationCleanup : null); },
                started && loader != null ? (Action)loader.ConfirmDestroyed : null,
                () => ActualExit(started, () => Native.WaitForSingleObject(owned.process, 0), () => {
                    uint actual; Native.Check(Native.GetExitCodeProcess(owned.process, out actual), "read actual authority failure exit"); return actual;
                }), () => { if (output != null) output.Dispose(); },
                retain => { if (error != null) error.Dispose(retain); }, release.ToArray(), authority, traceCompletion,
                entryStarted, callbackStarted, undebugged, started, signaled, metadata,
                line => { Console.Out.WriteLine(line); Console.Out.Flush(); });
            } finally { process = owned; }
        }
    }
}
