using System;
using System.Collections.Generic;
using System.Security.AccessControl;

namespace ScientificSecurity
{
    public sealed partial class PrivateCreatorFixture
    {
        static void Rejected(Action action)
        {
            bool rejected = false;
            try { action(); } catch (InvalidOperationException) { rejected = true; }
            Need(rejected);
        }
        // Inert policy/state/removal checks share the production seams; no security API is called.
        public static void CheckValidation()
        {
            string user = "S-1-5-21-101-202-303-1001", package = "S-1-15-2-101-202-303-404-505-606-707";
            foreach (int line in new [] { -1, 0, 1, 9999, 10000, Int32.MaxValue }) {
                string expected = "fixed private creator fixture rejected line=" + (line >= 1 && line <= 9999 ? line : 0) +
                    " field=0 first=0x00000000 second=0x00000000 third=0x00000000";
                Exception caught = null;
                try { Need(false, line); } catch (InvalidOperationException failure) { caught = failure; }
                Need(caught != null && caught.Message == expected);
            }
            Exception policyFailure = null;
            try { PolicyNeed(false, 1, 0xFFFFFFFF, 0, 0x80000000, 123); }
            catch (InvalidOperationException failure) { policyFailure = failure; }
            Need(policyFailure != null && policyFailure.Message == "fixed private creator fixture rejected line=123 field=1 " +
                "first=0xFFFFFFFF second=0x00000000 third=0x80000000");
            Need(true); PolicyNeed(true, 1, 0);
            string text = PolicyText(user, package);
            RequirePolicy(new RawSecurityDescriptor(text), user, package);
            foreach (var sample in new [] {
                new { text = text.Replace("D:P", "D:"), field = 1 },
                new { text = text.Replace("(A;;FA;;;" + package + ")", ""), field = 2 },
                new { text = text.Replace("FA", "FR"), field = 3 },
                new { text = text.Replace("OICI", "OI"), field = 4 },
                new { text = text.Replace("NW", "NR"), field = 5 }
            }) {
                Exception caught = null;
                try { RequirePolicy(new RawSecurityDescriptor(sample.text), user, package); }
                catch (InvalidOperationException failure) { caught = failure; }
                Need(caught != null && caught.Message.Contains(" field=" + sample.field + " first=0x") &&
                    !caught.Message.Contains(user) && !caught.Message.Contains(package) && !caught.Message.Contains("S-1-"));
            }
            foreach (string changed in new [] {
                text.Replace("D:P", "D:"), text.Replace("FA", "FR"), text.Replace("(A;;", "(A;OI;"),
                text.Replace("(A;;", "(D;;"), text.Replace("NW", "NR"), text.Replace("LW", "ME"),
                text.Replace("OICI", "OI"), text.Replace("G:" + user, "G:S-1-5-18"),
                text.Replace("O:" + user, "O:S-1-5-18"), text + "(ML;;NW;;;LW)",
                text.Replace("S:", "(A;;FA;;;SY)S:"), text.Replace("(A;;FA;;;" + package + ")", "")
            }) Rejected(() => RequirePolicy(new RawSecurityDescriptor(changed), user, package));
            Rejected(() => RequirePolicy(new RawSecurityDescriptor(text), "S-1-5-18", package));
            Rejected(() => RequirePolicy(new RawSecurityDescriptor(text), user, "S-1-15-2-1"));
            foreach (string root in new [] { @"D:\", @"Z:\" }) Need(Folder(root) == root + "private-creator");
            foreach (string root in new [] { null, "", @"C:\", @"e:\", @"E:\temp", @"E:/", @"\\server\share\" })
                Rejected(() => Folder(root));
            foreach (string digits in new [] { "0", "12", new string('9', 20) })
                Need(NativeRoot(@"\Device\HarddiskVolume" + digits + "\\"));
            foreach (string name in new [] { @"\\?\E:\", @"\Device\HarddiskVolume\", @"\Device\HarddiskVolume1",
                @"\Device\HarddiskVolume١\", @"\Device\harddiskvolume1\", @"\Device\HarddiskVolume1\temp\" }) Need(!NativeRoot(name));
            var identity = new ScratchAccess.FileInformation { volume = 7, indexHigh = 11, indexLow = 13 };
            Same(identity, identity);
            foreach (int field in new [] { 0, 1, 2 }) {
                var changed = identity;
                if (field == 0) changed.volume++; else if (field == 1) changed.indexHigh++; else changed.indexLow++;
                Rejected(() => Same(identity, changed));
            }
            var state = new Lifecycle();
            Rejected(() => state.Use(() => { })); Rejected(() => state.Seal(() => { }));
            state.Prepare(() => { }); Rejected(() => state.Prepare(() => { }));
            state.Seal(() => { }); Rejected(() => state.Seal(() => { }));
            Rejected(() => state.Remove(() => { }));
            state.Use(() => { }); Rejected(() => state.Use(() => { })); Rejected(() => state.Remove(() => { }));
            state.End(true); state.Use(() => { }); state.End(true);
            state.Remove(() => { }); Need(state.removed); Rejected(() => state.Use(() => { }));
            Rejected(() => state.Remove(() => { }));
            var poisoned = new Lifecycle(); poisoned.Prepare(() => { }); poisoned.Seal(() => { });
            poisoned.Use(() => { });
            int releases = 0;
            Rejected(() => poisoned.Release(() => releases++));
            poisoned.End(false);
            Rejected(() => poisoned.Release(() => releases++)); Need(releases == 0);
            Rejected(() => poisoned.Use(() => { })); Rejected(() => poisoned.Remove(() => { }));
            var cleanRelease = new Lifecycle(); cleanRelease.Prepare(() => { });
            cleanRelease.Release(() => releases++); Need(releases == 1);
            var failed = new Lifecycle();
            Rejected(() => failed.Prepare(() => { throw new InvalidOperationException("fixed prepare"); }));
            Rejected(() => failed.Prepare(() => { })); Rejected(() => failed.Seal(() => { }));
            var failedUse = new Lifecycle(); failedUse.Prepare(() => { }); failedUse.Seal(() => { });
            Rejected(() => failedUse.Use(() => { throw new InvalidOperationException("fixed use"); }));
            failedUse.End(true); Rejected(() => failedUse.Remove(() => { }));
            for (int fault = 0; fault < 8; fault++) {
                int selected = fault; var events = new List<string>();
                var primary = new InvalidOperationException("fixed removal");
                var close = new InvalidOperationException("fixed close"); Exception caught = null;
                try { RemoveBound(() => { events.Add("check"); if (selected == 1) throw primary; },
                    () => { events.Add("pin-close"); if (selected == 2) throw primary; },
                    () => { events.Add("open"); if (selected == 3) throw primary; return new IntPtr(17); },
                    handle => { Need(handle == new IntPtr(17)); events.Add("bind"); if (selected == 4) throw primary; },
                    handle => { events.Add("dispose"); if (selected == 5) throw primary; },
                    handle => { events.Add("close"); if (selected == 6 || selected == 4) throw close; },
                    () => { events.Add("absent"); if (selected == 7) throw primary; }); }
                catch (Exception error) { caught = error; }
                Need((caught == null) == (selected == 0));
                Need(events.Contains("open") == (selected != 1 && selected != 2));
                Need(events.Contains("dispose") == (selected == 0 || selected >= 5));
                Need(events.Contains("close") == (selected == 0 || selected >= 4));
                Need(events.Contains("absent") == (selected == 0 || selected == 7));
                if (selected == 4) {
                    var group = caught as AggregateException;
                    Need(group != null && group.InnerExceptions.Count == 2 &&
                        Object.ReferenceEquals(group.InnerExceptions[0], primary) && Object.ReferenceEquals(group.InnerExceptions[1], close));
                }
            }
        }
    }
}
