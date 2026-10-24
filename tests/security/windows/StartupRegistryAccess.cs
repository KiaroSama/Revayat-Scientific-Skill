using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace ScientificSecurity
{
    // Fixed read-open only; buffered observations never establish the child's attempted object.
    public static class StartupRegistryAccess
    {
        public static void CheckValidation()
        {
            Need(IntPtr.Size == 8 && Marshal.SizeOf(typeof(UnicodeString)) == 16 && Marshal.SizeOf(typeof(ObjectAttributes)) == 48);
            string[] names = { "length", "maximum", "buffer" }; int[] offsets = { 0, 2, 8 };
            for (int index = 0; index < names.Length; index++)
                Need(Marshal.OffsetOf(typeof(UnicodeString), names[index]).ToInt32() == offsets[index]);
            names = new [] { "length", "root", "name", "attributes", "descriptor", "qos" };
            offsets = new [] { 0, 8, 16, 24, 32, 40 };
            for (int index = 0; index < names.Length; index++)
                Need(Marshal.OffsetOf(typeof(ObjectAttributes), names[index]).ToInt32() == offsets[index]);
            byte[] bytes = new UnicodeEncoding(false, false, true).GetBytes(KeyPath + "\0");
            Need(KeyPath == @"\Registry\MACHINE\Software\Microsoft\Windows\CurrentVersion\SideBySide" && Access == 0x20019 &&
                bytes.Length == 142 && bytes[140] == 0 && bytes[141] == 0);
            var text = FixedName(new IntPtr(11)); var attributes = FixedAttributes(new IntPtr(22));
            Need(text.length == 140 && text.maximum == 142 && text.buffer == new IntPtr(11) &&
                attributes.length == 48 && attributes.root == IntPtr.Zero && attributes.name == new IntPtr(22) &&
                attributes.attributes == 0x40 && attributes.descriptor == IntPtr.Zero && attributes.qos == IntPtr.Zero);
            Need(Outcome("host", 0, new IntPtr(1)) ==
                "WINDOWS_STARTUP_REGISTRY context=host label=sxs-policy desired_access=0x00020019 status=0x00000000 opened=True child_equivalence_claimed=False cause_claimed=False");
            Need(Outcome("lpac", unchecked((int)0xC0000022), IntPtr.Zero).Contains("status=0xC0000022 opened=False"));
            foreach (int status in new [] { 0, 1, 0x40000003, Int32.MaxValue })
                Need(Outcome("lpac", status, new IntPtr(1)).Contains("opened=True"));
            foreach (var item in new [] {
                Tuple.Create(0, IntPtr.Zero), Tuple.Create(0, Native.InvalidHandle),
                Tuple.Create(unchecked((int)0xC0000022), new IntPtr(1)), Tuple.Create(-1, Native.InvalidHandle)
            }) Refuse(() => Outcome("lpac", item.Item1, item.Item2));
            Refuse(() => Outcome("private-registry-sentinel", 0, new IntPtr(1)));
            foreach (int status in new [] { 0, 1, 0x40000003, Int32.MaxValue }) Closed(status);
            foreach (int status in new [] { -1, unchecked((int)0xC0000008), unchecked((int)0xC0000235) }) Refuse(() => Closed(status));
            foreach (bool operationFails in new [] { false, true }) {
                int closeAttempts = 0; AggregateException caught = null;
                var operation = new InvalidOperationException("fixed open failure");
                try {
                    ObserveOne("lpac", _ => { }, () => { }, () => { },
                        delegate(ref IntPtr key) { key = new IntPtr(1); if (operationFails) throw operation; return 0; },
                        _ => { closeAttempts++; Closed(unchecked((int)0xC0000008)); });
                }
                catch (AggregateException failure) { caught = failure; }
                if (caught == null) throw new InvalidOperationException("registry close failure was accepted");
                Need(closeAttempts == 1 && caught.InnerExceptions.Count == (operationFails ? 2 : 1) &&
                    (!operationFails || Object.ReferenceEquals(caught.InnerExceptions[0], operation)) &&
                    caught.InnerExceptions[caught.InnerExceptions.Count - 1] is InvalidOperationException);
            }
            foreach (string label in new [] { "host", "lpac" }) {
                var order = new List<string>(); int calls = 0, closes = 0;
                ObserveOne(label, line => order.Add("record"), () => order.Add("deadline"), () => order.Add("qualify"),
                    delegate(ref IntPtr key) { calls++; order.Add("open"); key = new IntPtr(1); return 0; },
                    key => { Need(key == new IntPtr(1)); closes++; order.Add("close"); });
                Need(calls == 1 && closes == 1 && String.Join(",", order) == "deadline,qualify,open,qualify,deadline,record,close");
            }
            int failedCalls = 0, failedCloses = 0, recorded = 0;
            ObserveOne("lpac", _ => recorded++, () => { }, () => { },
                delegate(ref IntPtr key) { failedCalls++; return unchecked((int)0xC0000022); }, _ => failedCloses++);
            Need(failedCalls == 1 && failedCloses == 0 && recorded == 1);
            Refuse(() => ObserveOne("host", _ => { }, () => { }, () => { },
                delegate(ref IntPtr key) { return unchecked((int)0xC0000022); }, _ => { }));
            int inconsistentCloses = 0;
            Refuse(() => ObserveOne("lpac", _ => { }, () => { }, () => { },
                delegate(ref IntPtr key) { key = new IntPtr(1); return -1; }, _ => inconsistentCloses++));
            Need(inconsistentCloses == 1);
            var primary = new InvalidOperationException("fixed primary");
            var cleanup = new InvalidOperationException("fixed cleanup");
            foreach (int failAt in new [] { 0, 1, 2, 3, 4, 5 }) {
                int qualifications = 0, deadlines = 0, calls = 0, closes = 0, records = 0;
                Exception caught = null;
                try {
                    ObserveOne("lpac", _ => { records++; if (failAt == 5) throw primary; },
                        () => { deadlines++; if ((failAt == 0 && deadlines == 1) || (failAt == 4 && deadlines == 2)) throw primary; },
                        () => { qualifications++; if ((failAt == 1 && qualifications == 1) || (failAt == 3 && qualifications == 2)) throw primary; },
                        delegate(ref IntPtr key) { calls++; key = new IntPtr(1); if (failAt == 2) throw primary; return 0; },
                        _ => closes++);
                }
                catch (Exception failure) { caught = failure; }
                Need(Object.ReferenceEquals(caught, primary) && calls == (failAt < 2 ? 0 : 1) &&
                    closes == calls && records == (failAt == 5 ? 1 : 0));
            }
            AggregateException aggregate = null; int attempts = 0;
            try {
                ObserveOne("lpac", _ => { }, () => { }, () => { },
                    delegate(ref IntPtr key) { key = new IntPtr(1); throw primary; }, _ => { attempts++; throw cleanup; });
            }
            catch (AggregateException failure) { aggregate = failure; }
            Need(attempts == 1 && aggregate != null && aggregate.InnerExceptions.Count == 2 &&
                Object.ReferenceEquals(aggregate.InnerExceptions[0], primary) && Object.ReferenceEquals(aggregate.InnerExceptions[1], cleanup));
            attempts = 0; aggregate = null;
            try { Cleanup(primary, () => { attempts++; throw cleanup; }, () => attempts++, () => attempts++); }
            catch (AggregateException failure) { aggregate = failure; }
            Need(attempts == 3 && aggregate != null && Object.ReferenceEquals(aggregate.InnerExceptions[0], primary));
            CheckChildFinalization();
        }
        static void CheckChildFinalization()
        {
            var order = new List<string>();
            FinalizeChild(null, true, () => { order.Add("revert"); return true; },
                () => { throw new InvalidOperationException("unexpected fail-fast"); }, () => order.Add("emit"),
                () => order.Add("duplicate"), () => order.Add("primary"));
            Need(String.Join(",", order) == "revert,duplicate,primary,emit");
            var fatal = new System.IO.IOException("fixed fail-fast");
            foreach (bool throws in new [] { false, true }) {
                order.Clear(); Exception caught = null;
                try {
                    FinalizeChild(null, true, () => { order.Add("revert"); if (throws) throw fatal; return false; },
                        () => { order.Add("fail-fast"); throw fatal; }, () => order.Add("emit"), () => order.Add("close"));
                } catch (Exception failure) { caught = failure; }
                Need(Object.ReferenceEquals(caught, fatal) && String.Join(",", order) == "revert,fail-fast");
            }
            order.Clear(); Refuse(() => FinalizeChild(null, true, () => false, () => order.Add("fail-fast"),
                () => order.Add("emit"), () => order.Add("close")));
            Need(String.Join(",", order) == "fail-fast");
            var primary = new System.IO.IOException("fixed operation"); var close = new System.IO.IOException("fixed close");
            var report = new System.IO.IOException("fixed report");
            foreach (bool impersonating in new [] { false, true }) {
                order.Clear(); AggregateException caught = null;
                try {
                    FinalizeChild(primary, impersonating, () => { order.Add("revert"); return true; }, () => { throw fatal; },
                        () => { order.Add("emit"); throw report; },
                        () => { order.Add("duplicate"); throw close; }, () => order.Add("primary"));
                } catch (AggregateException failure) { caught = failure; }
                Need(caught != null && caught.InnerExceptions.Count == 3 && Object.ReferenceEquals(caught.InnerExceptions[0], primary) &&
                    Object.ReferenceEquals(caught.InnerExceptions[1], close) && Object.ReferenceEquals(caught.InnerExceptions[2], report) &&
                    String.Join(",", order) == (impersonating ? "revert," : "") + "duplicate,primary,emit");
            }
        }
        static void FinalizeChild(Exception primary, bool impersonating, Func<bool> revert, Action failFast, Action emit, params Action[] close)
        {
            if (impersonating) {
                bool reverted;
                try { reverted = revert(); } catch { failFast(); throw; }
                if (!reverted) { failFast(); throw new InvalidOperationException("registry identity restoration did not terminate"); }
            }
            var actions = new List<Action>(close); actions.Add(emit);
            Cleanup(primary, actions.ToArray());
        }
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool DuplicateTokenEx(
            IntPtr token, uint access, IntPtr attributes, int level, int kind, out IntPtr duplicate);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool ImpersonateLoggedOnUser(IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool RevertToSelf();
        static void Deadline(Stopwatch clock)
        { if (clock.Elapsed.TotalSeconds > 10) throw new TimeoutException("fixed child registry comparison exceeded 10 seconds"); }
        internal static int ObserveChild(Native.ProcessInfo child, string package)
        {
            using (WindowsIdentity current = WindowsIdentity.GetCurrent(true))
                if (current != null) throw new InvalidOperationException("registry host is already impersonating");
            IntPtr token = IntPtr.Zero, duplicate = IntPtr.Zero;
            bool impersonating = false; Exception primary = null;
            var lines = new List<string>(); var clock = Stopwatch.StartNew();
            try {
                Observe("host", lines, () => Deadline(clock), () => { });
                Native.Check(Native.OpenProcessToken(child.process, 0xA, out token), "open exact registry primary token");
                Native.Check(DuplicateTokenEx(token, 0xC, IntPtr.Zero, 2, 2, out duplicate), "duplicate exact registry token");
                var context = new RegistryContext(token, duplicate, package);
                Native.Check(ImpersonateLoggedOnUser(duplicate), "enter exact registry LPAC context");
                impersonating = true; context.RequireThread();
                int status = Observe("lpac", lines, () => Deadline(clock), context.RequireThread);
                context.RequireThread(); Deadline(clock);
                return status;
            }
            catch (Exception failure) { primary = failure; throw; }
            finally {
                FinalizeChild(primary, impersonating, RevertToSelf,
                    () => Environment.FailFast("Registry identity restoration failed; outer owner must reap and clean up."),
                    () => { foreach (string line in lines) Console.Out.WriteLine(line); Console.Out.Flush(); },
                    () => { if (duplicate != IntPtr.Zero) Native.Check(Native.CloseHandle(duplicate), "close registry duplicate token"); },
                    () => { if (token != IntPtr.Zero) Native.Check(Native.CloseHandle(token), "close registry primary token"); });
            }
        }
        [StructLayout(LayoutKind.Sequential)] struct UnicodeString { internal ushort length, maximum; internal IntPtr buffer; }
        [StructLayout(LayoutKind.Sequential)] struct ObjectAttributes {
            internal uint length; internal IntPtr root, name; internal uint attributes; internal IntPtr descriptor, qos;
        }
        [DllImport("ntdll.dll")] static extern int NtOpenKey(ref IntPtr key, uint access, ref ObjectAttributes attributes);
        [DllImport("ntdll.dll")] static extern int NtClose(IntPtr key);
        const string KeyPath = @"\Registry\MACHINE\Software\Microsoft\Windows\CurrentVersion\SideBySide";
        const uint Access = 0x20019;
        delegate int OpenKey(ref IntPtr key);
        static void Need(bool value) { if (!value) throw new InvalidOperationException("fixed registry-access contract is invalid"); }
        static void Refuse(Action action)
        {
            bool refused = false;
            try { action(); } catch (InvalidOperationException) { refused = true; }
            Need(refused);
        }
        static bool Valid(IntPtr key) { return key != IntPtr.Zero && key != Native.InvalidHandle; }
        static UnicodeString FixedName(IntPtr text) { return new UnicodeString { length = 140, maximum = 142, buffer = text }; }
        static ObjectAttributes FixedAttributes(IntPtr name)
        { return new ObjectAttributes { length = 48, name = name, attributes = 0x40 }; }
        static string Outcome(string label, int status, IntPtr key)
        {
            Need((label == "host" || label == "lpac") && (status >= 0 ? Valid(key) : key == IntPtr.Zero));
            return "WINDOWS_STARTUP_REGISTRY context=" + label + " label=sxs-policy desired_access=0x00020019 status=0x" +
                unchecked((uint)status).ToString("X8") + " opened=" + (status >= 0) +
                " child_equivalence_claimed=False cause_claimed=False";
        }
        static void Cleanup(Exception primary, params Action[] actions)
        {
            var failures = new List<Exception>();
            foreach (Action action in actions) try { action(); } catch (Exception failure) { failures.Add(failure); }
            if (failures.Count == 0) return;
            if (primary != null) failures.Insert(0, primary);
            throw new AggregateException("fixed registry operation/cleanup failed", failures);
        }
        static int ObserveOne(string label, Action<string> record, Action deadline, Action qualify, OpenKey open, Action<IntPtr> close)
        {
            IntPtr key = IntPtr.Zero; Exception primary = null;
            try {
                deadline(); qualify();
                int status = open(ref key);
                qualify(); deadline();
                record(Outcome(label, status, key));
                if (label == "host" && status < 0) throw new InvalidOperationException("host fixed registry positive control failed");
                return status;
            }
            catch (Exception failure) { primary = failure; throw; }
            finally {
                IntPtr owned = key; key = IntPtr.Zero;
                Cleanup(primary, () => { if (Valid(owned)) close(owned); });
            }
        }
        static int OpenFixed(ref IntPtr key)
        {
            IntPtr text = IntPtr.Zero, name = IntPtr.Zero; Exception primary = null;
            try {
                text = Marshal.StringToHGlobalUni(KeyPath);
                name = Marshal.AllocHGlobal(16);
                Marshal.StructureToPtr(FixedName(text), name, false);
                ObjectAttributes attributes = FixedAttributes(name);
                return NtOpenKey(ref key, Access, ref attributes);
            }
            catch (Exception failure) { primary = failure; throw; }
            finally {
                Cleanup(primary, () => { if (name != IntPtr.Zero) Marshal.FreeHGlobal(name); },
                    () => { if (text != IntPtr.Zero) Marshal.FreeHGlobal(text); });
            }
        }
        static void Closed(int status)
        { if (status < 0) throw new InvalidOperationException("close fixed registry read handle failed"); }
        internal static int Observe(string label, List<string> lines, Action deadline, Action qualify)
        {
            return ObserveOne(label, lines.Add, deadline, qualify, OpenFixed, key => Closed(NtClose(key)));
        }
    }
}
