using System;
using System.Collections.Generic;

namespace ScientificSecurity
{
    // Raw trusted-fixture transport is deliberately separate from successful activation/admission.
    internal sealed class CsrDispatchObservation
    {
        internal readonly bool traced, module;
        internal bool recorded, receipt, completed;
        internal uint exit;
        internal int characters;
        internal CsrDispatchObservation(bool debug, bool moduleId2 = false) { traced = debug; module = moduleId2; }
        internal void Record(uint code, string text, string errors)
        {
            Need(!recorded && text != null && errors != null && text.Length <= (module ? 256 : 128) && errors.Length == 0);
            if (module) {
                ModuleActivationFixture.Result(true, code, text, errors);
                recorded = true; exit = code; characters = text.Length; completed = code == 0;
                return;
            }
            bool complete = SelfActivationFixture.DispatchCompleted(code, text);
            Need(complete || (code & 0x80000000) != 0 && text.Length == 0);
            recorded = true; exit = code; characters = text.Length;
            receipt = SelfActivationFixture.DispatchPreCall(text); completed = complete;
        }
        internal string Metadata()
        {
            Need(recorded);
            if (module) return "WINDOWS_MODULE_CSR_TRANSPORT traced=" + traced + " raw_process_exit=0x" + exit.ToString("X8") +
                " entry_observed=" + completed + " association_proved=" + completed + " completed_wire=" + completed +
                " stdout_chars=" + characters + " process_job_handle_cleanup=True key_readable=True invocation_module_verified=False" +
                " python_equivalence_claimed=False target_admitted=False cause_claimed=False production_grant=False";
            return "WINDOWS_CSR_DISPATCH_TRANSPORT traced=" + traced + " raw_process_exit=0x" + exit.ToString("X8") +
                " pre_call_receipt_observed=" + receipt + " completed_wire=" + completed + " stdout_chars=" + characters +
                " process_job_handle_cleanup=True key_readable=True target_admitted=False cause_claimed=False production_grant=False";
        }
        static void Need(bool value)
        { if (!value) throw new InvalidOperationException("fixed CSR dispatch transport is inconclusive"); }
        internal static void CheckValidation()
        {
            const string wire = "EXPLICIT_ID2_BEFORE_CALL\nWINDOWS_EXPLICIT_ID2_ACTIVATION entry_reached=True created=True win32_error=0x00000000\n";
            var value = new CsrDispatchObservation(false); value.Record(0, wire, "");
            Need(value.receipt && value.completed && value.Metadata().Contains("completed_wire=True"));
            value = new CsrDispatchObservation(true); value.Record(0xC0150002, "", "");
            Need(!value.receipt && !value.completed && value.Metadata().Contains("raw_process_exit=0xC0150002"));
            foreach (var input in new [] {
                Tuple.Create(0U, "", ""), Tuple.Create(1U, "", ""),
                Tuple.Create(0U, "EXPLICIT_ID2_BEFORE_CALL\n", ""), Tuple.Create(0xC0000022U, wire, ""),
                Tuple.Create(0U, wire.Replace("True win32_error", "False win32_error"), ""),
                Tuple.Create(0U, "private-sentinel", ""), Tuple.Create(0U, wire, "private-sentinel"),
                Tuple.Create(0U, new string('x', 129), "")
            }) {
                bool refused = false;
                try { new CsrDispatchObservation(false).Record(input.Item1, input.Item2, input.Item3); }
                catch (InvalidOperationException failure) { refused = !failure.Message.Contains("private-sentinel"); }
                Need(refused);
            }
            bool repeated = false;
            try { value.Record(0xC0150002, "", ""); } catch (InvalidOperationException) { repeated = true; }
            Need(repeated && !value.Metadata().Contains("private-sentinel"));
        }
    }
    public static partial class SelfActivationFixture
    {
        static bool dispatchHostPositive;
        internal static bool DispatchPreCall(string text) { return ObservedPreCall(text); }
        internal static bool DispatchCompleted(uint exit, string text)
        {
            if (exit != 0 || !ObservedPreCall(text)) return false;
            var match = Completed(text.Substring(PreCallReceipt.Length), SelfActivationRole.ExplicitId2);
            return match.Success && Consistent(match);
        }
        internal static void RequireDispatchHostPositive(string python)
        { RequireResourceHostPositive(python); Need(dispatchHostPositive); }
        public static void RunDispatchHost(string python)
        {
            RequireHostPositive(python, SelfActivationRole.ExplicitId2); Need(!dispatchHostPositive);
            IDisposable held = Hold(python, SelfActivationRole.ExplicitId2);
            CompleteDispatchHost(retain => TrustedSetup.RunCsrDispatch(python, retain), held.Dispose,
                line => { Console.Out.WriteLine(line); Console.Out.Flush(); }, () => dispatchHostPositive = true);
        }
        static void CompleteDispatchHost(Func<Action<string>, string> run, Action close, Action<string> emit, Action accept)
        {
            string metadata = null;
            CompleteHost(() => run(line => { Need(metadata == null && line != null); metadata = line; }), close, () => {
                Need(metadata != null); emit(metadata);
                emit("WINDOWS_CSR_DISPATCH_HOST positive=True cleanup_complete=True cause_claimed=False"); accept();
            }, SelfActivationRole.ExplicitId2);
        }
        internal static void CheckDispatchHostValidation()
        {
            foreach (int mode in new [] { 0, 1, 2, 3, 4, 5 }) {
                var order = new List<string>(); bool refused = false;
                try {
                    CompleteDispatchHost(retain => {
                        order.Add("process-clean"); if (mode != 1) retain("fixed");
                        if (mode == 2) throw new InvalidOperationException("fixed host failure");
                        return Success.Replace("WINDOWS_SELF_ACTIVATION", Label(SelfActivationRole.ExplicitId2)).TrimEnd('\n');
                    }, () => { order.Add("lease-close"); if (mode == 3) throw new InvalidOperationException("fixed lease failure"); },
                    line => { order.Add(line == "fixed" ? "metadata" : "positive");
                        if (mode == 4 || mode == 5 && line != "fixed") throw new InvalidOperationException("fixed report failure"); }, () => order.Add("latch"));
                } catch (InvalidOperationException) { refused = true; }
                Need(refused == (mode != 0) && order.Contains("lease-close") && order.Contains("latch") == (mode == 0));
                if (mode == 0) Need(String.Join(",", order) == "process-clean,lease-close,metadata,positive,latch");
            }
        }
    }
}
