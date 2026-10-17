using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml;

namespace ScientificSecurity
{
    // Fixed local event evidence, collected only after the registry intervention is restored.
    public static class StartupActivationEvents
    {
        const string Namespace = "http://schemas.microsoft.com/win/2004/08/events/event";
        public static void CheckValidation()
        {
            DateTime start = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc), end = start.AddSeconds(1);
            string image = @"C:\fixed owned\python.exe";
            string xml = "<Event xmlns='" + Namespace + "'><System><Provider Name='SideBySide'/><EventID>33</EventID>" +
                "<TimeCreated SystemTime='2026-01-01T00:00:00.5000000Z'/><Channel>Application</Channel></System><EventData>" +
                "<Data>" + image + "</Data><Data>Dependent Assembly Microsoft.Windows.Common-Controls,processorArchitecture=amd64 could not be found.</Data>" +
                "</EventData></Event>";
            string line = Classify(xml, image, start, end);
            Need(line.Contains("event_id=33 matched_owned_image=True") && line.Contains("dependent_assembly_not_found=True") &&
                line.Contains("common_controls=True") && line.Contains("amd64=True") && !line.Contains(image) && !line.Contains("Dependent Assembly"));
            Need(Classify(xml.Replace(image, image + ".other"), image, start, end) == null);
            Need(Classify(xml.Replace(image, image.ToUpperInvariant()), image, start, end) == line);
            Need(Classify(xml.Replace("<Provider Name='SideBySide'/>", "<Provider Name='SideBySide' Guid='{00000000-0000-0000-0000-000000000001}' EventSourceName='SideBySide'/>")
                .Replace("<EventID>", "<EventID Qualifiers='0'>"), image, start, end) == line);
            foreach (string invalid in new [] {
                xml.Replace("SideBySide", "Other"), xml.Replace("Application", "System"), xml.Replace(Namespace, "urn:other"),
                xml.Replace("<EventID>33</EventID>", "<EventID>-1</EventID>"),
                xml.Replace("<EventID>33</EventID>", "<EventID><Nested>33</Nested></EventID>"),
                xml.Replace("<Channel>Application</Channel>", "<Channel><Nested>Application</Nested></Channel>"),
                xml.Replace("<Provider Name='SideBySide'/>", "<Provider Name='SideBySide'><Nested/></Provider>"),
                xml.Replace("<TimeCreated SystemTime='2026-01-01T00:00:00.5000000Z'/>", "<TimeCreated SystemTime='2026-01-01T00:00:00.5000000Z'><Nested/></TimeCreated>"),
                xml.Replace("<EventID>33</EventID>", "<EventID><Foreign xmlns='urn:other'>33</Foreign></EventID>"),
                xml.Replace("<Channel>Application</Channel>", "<Channel><Foreign xmlns='urn:other'>Application</Foreign></Channel>"),
                xml.Replace("<Provider Name='SideBySide'/>", "<Provider Name='SideBySide'><Foreign xmlns='urn:other'/></Provider>"),
                xml.Replace("<TimeCreated SystemTime='2026-01-01T00:00:00.5000000Z'/>", "<TimeCreated SystemTime='2026-01-01T00:00:00.5000000Z'><Foreign xmlns='urn:other'/></TimeCreated>"),
                xml.Replace("<Provider Name='SideBySide'/>", "<Provider Name='SideBySide' Unknown='value'/>"),
                xml.Replace("<EventID>", "<EventID Qualifiers='65536'>"), xml.Replace("<EventID>33</EventID>", "<EventID>65536</EventID>"),
                xml.Replace("<Channel>", "<Channel Unknown='value'>"), xml.Replace("<TimeCreated ", "<TimeCreated Unknown='value' "),
                xml.Replace("00:00:00.5000000Z", "00:00:02.5000000Z"),
                xml.Replace("</EventData>", "<Data>" + image + "</Data></EventData>"),
                "<!DOCTYPE Event [<!ENTITY x 'private'>]>" + xml, xml.Replace("</EventData>", "<Other/></EventData>"),
                xml.Replace("<Data>" + image, "<Data><Nested/>" + image), new string('x', 32769)
            }) Refused(() => Classify(invalid, image, start, end));
            string unknown = Classify(xml.Replace("Dependent Assembly Microsoft.Windows.Common-Controls,processorArchitecture=amd64 could not be found.", "private unknown payload"), image, start, end);
            Need(unknown.Contains("dependent_assembly_not_found=False") && !unknown.Contains("private"));
            foreach (int count in new [] { 0, 1, 16, 17 }) {
                int calls = 0, consumed = 0; Exception caught = null;
                try { Enumerate(() => ++calls <= count, () => consumed++); } catch (Exception error) { caught = error; }
                Need(calls == Math.Min(count + 1, 17) && consumed == Math.Min(count, 16) && (caught != null) == (count == 17));
            }
            int closes = 0, uses = 0;
            Need(!UseNext(value => { value.error = 259; }, _ => closes++, _ => uses++));
            Need(UseNext(value => { value.success = true; value.count = 1; value.handle = new IntPtr(1); }, _ => closes++, _ => uses++));
            Need(closes == 1 && uses == 1);
            foreach (Action<Next> invalid in new Action<Next>[] {
                value => { value.error = 1460; }, value => { value.success = true; },
                value => { value.error = 259; value.handle = new IntPtr(1); },
                value => { value.success = true; value.count = 2; value.handle = new IntPtr(1); }
            }) Refused(() => UseNext(invalid, _ => closes++, _ => uses++));
            Need(closes == 3 && uses == 1);
            var operation = new InvalidOperationException("private operation"); var closing = new InvalidOperationException("private close");
            AggregateException aggregate = null;
            try { UseNext(value => { value.handle = new IntPtr(1); throw operation; }, _ => { throw closing; }, _ => { }); }
            catch (AggregateException error) { aggregate = error; }
            Need(aggregate != null && Object.ReferenceEquals(aggregate.InnerExceptions[0], operation) && Object.ReferenceEquals(aggregate.InnerExceptions[1], closing));
            Need(RequiredBytes(false, 122, 4, 0) == 4 && RequiredBytes(false, 122, 65536, 0) == 65536);
            foreach (uint size in new uint[] { 0, 2, 5, 65538 }) Refused(() => RequiredBytes(false, 122, size, 0));
            Refused(() => RequiredBytes(true, 0, 8, 0)); Refused(() => RequiredBytes(false, 5, 8, 0));
            byte[] text = new UnicodeEncoding(false, false, true).GetBytes("<x/>\0");
            Need(Decode(text, (uint)text.Length, (uint)text.Length, 0) == "<x/>");
            Refused(() => Decode(text, (uint)text.Length - 1, (uint)text.Length, 0));
            Refused(() => Decode(text, (uint)text.Length, (uint)text.Length, 1));
            Refused(() => Decode(new byte[] { 0, 0, 0, 0 }, 4, 4, 0));
            var carrier = new EvidenceFailure(operation);
            Need(Object.ReferenceEquals(carrier.Original, operation) && carrier.InnerException == null && !carrier.Message.Contains("private"));
            CheckCollection(xml, image, start, end);
        }
        static void CheckCollection(string xml, string image, DateTime start, DateTime end)
        {
            foreach (int mode in new [] { 0, 1, 2 }) {
                bool renderFailure = mode != 1, releaseFailure = mode == 2;
                var calls = new List<string>(); var operation = new InvalidOperationException("private render");
                var bufferRelease = new InvalidOperationException("private buffer release");
                var eventClose = new InvalidOperationException("private event close");
                var queryClose = new InvalidOperationException("private query close");
                Exception classification = null; byte[] held = null;
                var api = Fixture(xml, 1, calls, bytes => held = bytes);
                var render = api.render;
                api.render = (item, capacity, data) => {
                    if (capacity != 0 && renderFailure) { calls.Add("render-fail"); throw operation; }
                    return render(item, capacity, data);
                };
                if (!renderFailure) api.read = (data, bytes) => {
                    calls.Add("read"); held = bytes;
                    Array.Copy(new UnicodeEncoding(false, false, true).GetBytes(xml.Replace("<EventID>33</EventID>", "<EventID>-1</EventID>") + "\0"), bytes, bytes.Length);
                };
                if (releaseFailure) api.release = (data, capacity) => { calls.Add("release"); throw bufferRelease; };
                api.close = handle => {
                    if (handle == new IntPtr(100)) { calls.Add("query-close"); throw queryClose; }
                    calls.Add("event-close"); throw eventClose;
                };
                AggregateException failure = null;
                try { Collect(api, image, start, end, () => { }, () => 1000); }
                catch (AggregateException error) { failure = error; }
                Need(failure != null && failure.InnerExceptions.Count == (releaseFailure ? 4 : 3));
                classification = failure.InnerExceptions[0];
                Need(renderFailure ? Object.ReferenceEquals(classification, operation) :
                    classification is InvalidOperationException && classification.Message == "fixed SxS event evidence contract failed");
                if (releaseFailure) Need(Object.ReferenceEquals(failure.InnerExceptions[1], bufferRelease));
                int closeIndex = releaseFailure ? 2 : 1;
                Need(Object.ReferenceEquals(failure.InnerExceptions[closeIndex], eventClose) && Object.ReferenceEquals(failure.InnerExceptions[closeIndex + 1], queryClose));
                Need(String.Join(",", calls) == (renderFailure ?
                    "query,next,size,allocate,render-fail,release,event-close,query-close" :
                    "query,next,size,allocate,render,read,release,event-close,query-close"));
                if (held != null) foreach (byte value in held) Need(value == 0);
            }
            foreach (int count in new [] { 0, 1, 16, 17 }) {
                var calls = new List<string>();
                var api = Fixture(xml, count, calls, _ => { }); List<string> lines = null; Exception failure = null;
                try { lines = Collect(api, image, start, end, () => { }, () => 1000); }
                catch (Exception error) { failure = error; }
                Need((failure != null) == (count == 17));
                Need(calls.FindAll(value => value == "render").Count == Math.Min(count, 16));
                Need(calls.FindAll(value => value == "event-close").Count == count);
                Need(calls.FindAll(value => value == "query-close").Count == 1 && calls[calls.Count - 1] == "query-close");
                if (count == 17) Need(calls[calls.Count - 3] == "next" && calls[calls.Count - 2] == "event-close");
                else Need(lines.Count == count + 1 && lines[count].Contains("scanned_count=" + count + " selected_count=" + count));
            }
            {
                var calls = new List<string>(); var api = Fixture(xml.Replace(image, image + ".other"), 1, calls, _ => { });
                List<string> lines = Collect(api, image, start, end, () => { }, () => 1000);
                Need(lines.Count == 1 && lines[0].Contains("scanned_count=1 selected_count=0 status=inconclusive_no_match"));
            }
            {
                var calls = new List<string>(); var api = Fixture(xml, 5, calls, _ => { });
                var render = api.render;
                api.render = (item, capacity, data) => {
                    Rendered result = render(item, capacity, data); if (capacity == 0) result.bytes = 65536; return result;
                };
                Refused(() => Collect(api, image, start, end, () => { }, () => 1000));
                Need(calls.FindAll(value => value == "size").Count == 5 && calls.FindAll(value => value == "allocate").Count == 4);
                Need(calls.FindAll(value => value == "render").Count == 4 && calls.FindAll(value => value == "release").Count == 4);
                Need(calls.FindAll(value => value == "event-close").Count == 5 && calls[calls.Count - 1] == "query-close");
            }
        }
        static EventApi Fixture(string xml, int count, List<string> calls, Action<byte[]> hold)
        {
            byte[] encoded = new UnicodeEncoding(false, false, true).GetBytes(xml + "\0"); int next = 0;
            var closed = new HashSet<IntPtr>();
            return new EventApi {
                query = () => { calls.Add("query"); return new IntPtr(100); },
                next = (query, timeout, value) => {
                    Need(query == new IntPtr(100) && timeout == 1000); calls.Add("next");
                    if (++next > count) { value.error = 259; return; }
                    value.success = true; value.count = 1; value.handle = new IntPtr(next);
                },
                render = (item, capacity, data) => {
                    Need(item.ToInt64() > 0 && item.ToInt64() <= count);
                    calls.Add(capacity == 0 ? "size" : "render");
                    Need(capacity == 0 ? data == IntPtr.Zero : data == new IntPtr(200) && capacity >= encoded.Length);
                    return new Rendered { success = capacity != 0, error = capacity == 0 ? 122 : 0, bytes = (uint)encoded.Length };
                },
                allocate = capacity => { Need(capacity >= encoded.Length); calls.Add("allocate"); return new IntPtr(200); },
                read = (data, bytes) => { Need(data == new IntPtr(200) && bytes.Length == encoded.Length); calls.Add("read"); Array.Copy(encoded, bytes, bytes.Length); hold(bytes); },
                release = (data, capacity) => { Need(data == new IntPtr(200) && capacity >= encoded.Length); calls.Add("release"); },
                close = handle => {
                    Need((handle == new IntPtr(100) || handle.ToInt64() > 0 && handle.ToInt64() <= count) && closed.Add(handle));
                    calls.Add(handle == new IntPtr(100) ? "query-close" : "event-close");
                }
            };
        }
        sealed class EvidenceFailure : Exception
        {
            internal readonly Exception Original;
            internal EvidenceFailure(Exception original) : base("fixed SxS event evidence failed; details withheld") { Original = original; }
        }
        sealed class Next { internal bool success; internal uint count; internal int error; internal IntPtr handle; }
        sealed class Rendered { internal bool success; internal int error; internal uint bytes, properties; }
        sealed class EventApi
        {
            internal Func<IntPtr> query;
            internal Action<IntPtr, uint, Next> next;
            internal Func<IntPtr, uint, IntPtr, Rendered> render;
            internal Func<int, IntPtr> allocate;
            internal Action<IntPtr, byte[]> read;
            internal Action<IntPtr, int> release;
            internal Action<IntPtr> close;
        }
        [DllImport("wevtapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr EvtQuery(IntPtr session, string path, string query, uint flags);
        [DllImport("wevtapi.dll", SetLastError = true)]
        static extern bool EvtNext(IntPtr query, uint capacity, [Out] IntPtr[] events, uint timeout, uint flags, out uint returned);
        [DllImport("wevtapi.dll", SetLastError = true)]
        static extern bool EvtRender(IntPtr context, IntPtr fragment, uint flags, uint capacity, IntPtr buffer, out uint used, out uint properties);
        [DllImport("wevtapi.dll", SetLastError = true)] static extern bool EvtClose(IntPtr handle);
        static void Need(bool value) { if (!value) throw new InvalidOperationException("fixed SxS event evidence contract failed"); }
        static void Refused(Action action)
        { bool refused = false; try { action(); } catch (Exception) { refused = true; } Need(refused); }
        static void AddFailure(List<Exception> failures, Exception error)
        {
            var aggregate = error as AggregateException;
            if (aggregate == null || aggregate.InnerExceptions.Count == 0) failures.Add(error);
            else foreach (Exception inner in aggregate.InnerExceptions) AddFailure(failures, inner);
        }
        static void Finish(Exception primary, params Action[] actions)
        {
            var failures = new List<Exception>();
            if (primary != null) AddFailure(failures, primary);
            int originalCount = failures.Count;
            foreach (Action action in actions) try { action(); } catch (Exception error) { AddFailure(failures, error); }
            if (failures.Count == originalCount) return;
            throw new AggregateException("fixed SxS event operation/cleanup failed", failures);
        }
        static bool UseNext(Action<Next> fetch, Action<IntPtr> close, Action<IntPtr> consume)
        {
            var value = new Next(); Exception primary = null;
            try {
                fetch(value);
                if (!value.success && value.error == 259) { Need(value.count == 0 && value.handle == IntPtr.Zero); return false; }
                Need(value.success && value.count == 1 && value.handle != IntPtr.Zero && value.handle != Native.InvalidHandle);
                consume(value.handle); return true;
            }
            catch (Exception error) { primary = error; throw; }
            finally { Finish(primary, () => { if (value.handle != IntPtr.Zero && value.handle != Native.InvalidHandle) close(value.handle); }); }
        }
        static void Enumerate(Func<bool> next, Action consume)
        {
            for (int count = 0; count <= 16; count++) {
                if (!next()) return;
                Need(count < 16); consume();
            }
        }
        static uint RequiredBytes(bool success, int error, uint bytes, uint properties)
        { Need(!success && error == 122 && bytes >= 4 && bytes <= 65536 && bytes % 2 == 0 && properties == 0); return bytes; }
        static string Decode(byte[] bytes, uint used, uint capacity, uint properties)
        {
            Need(used >= 4 && used <= capacity && used == bytes.Length && used % 2 == 0 && properties == 0);
            Need(bytes[bytes.Length - 2] == 0 && bytes[bytes.Length - 1] == 0);
            string value = new UnicodeEncoding(false, false, true).GetString(bytes, 0, bytes.Length - 2);
            Need(value.IndexOf('\0') < 0); return value;
        }
        static string Render(EventApi api, IntPtr item, ref uint total, Action deadline)
        {
            deadline(); Rendered sizing = api.render(item, 0, IntPtr.Zero);
            uint capacity = RequiredBytes(sizing.success, sizing.error, sizing.bytes, sizing.properties);
            Need(total <= 262144 - capacity); total += capacity;
            IntPtr data = api.allocate((int)capacity); Need(data != IntPtr.Zero && data != Native.InvalidHandle);
            byte[] bytes = null; Exception primary = null;
            try {
                deadline(); Rendered rendered = api.render(item, capacity, data);
                Need(rendered.success && rendered.bytes >= 4 && rendered.bytes <= capacity && rendered.bytes % 2 == 0 && rendered.properties == 0);
                bytes = new byte[rendered.bytes]; api.read(data, bytes);
                return Decode(bytes, rendered.bytes, capacity, rendered.properties);
            }
            catch (Exception failure) { primary = failure; throw; }
            finally { Finish(primary, () => { if (bytes != null) Array.Clear(bytes, 0, bytes.Length); },
                () => api.release(data, (int)capacity)); }
        }
        static XmlElement One(XmlElement parent, string name)
        {
            XmlElement found = null;
            foreach (XmlNode node in parent.ChildNodes) if (node is XmlElement && node.LocalName == name && node.NamespaceURI == Namespace) {
                Need(found == null); found = (XmlElement)node;
            }
            Need(found != null); return found;
        }
        static void Leaf(XmlElement element, bool scalar, params string[] attributes)
        {
            foreach (XmlAttribute attribute in element.Attributes) {
                if (attribute.NamespaceURI == "http://www.w3.org/2000/xmlns/") continue;
                Need(attribute.NamespaceURI.Length == 0 && Array.IndexOf(attributes, attribute.Name) >= 0);
            }
            foreach (XmlNode child in element.ChildNodes) {
                bool whitespace = child.NodeType == XmlNodeType.Whitespace || child.NodeType == XmlNodeType.SignificantWhitespace;
                Need(whitespace || (scalar && (child.NodeType == XmlNodeType.Text || child.NodeType == XmlNodeType.CDATA)));
            }
        }
        static bool Has(string value, string literal) { return value.IndexOf(literal, StringComparison.OrdinalIgnoreCase) >= 0; }
        static string Classify(string xml, string image, DateTime start, DateTime end)
        {
            Need(xml != null && xml.Length > 0 && xml.Length <= 32768 && start.Kind == DateTimeKind.Utc && end.Kind == DateTimeKind.Utc && end >= start);
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 32768 };
            int elements = 0;
            using (var reader = XmlReader.Create(new StringReader(xml), settings))
                while (reader.Read()) { Need(reader.Depth <= 6); if (reader.NodeType == XmlNodeType.Element) Need(++elements <= 256); }
            var document = new XmlDocument { XmlResolver = null };
            using (var reader = XmlReader.Create(new StringReader(xml), settings)) document.Load(reader);
            XmlElement root = document.DocumentElement; Need(root != null && root.LocalName == "Event" && root.NamespaceURI == Namespace);
            XmlElement system = One(root, "System"), data = One(root, "EventData");
            foreach (XmlNode node in root.ChildNodes) if (node is XmlElement) Need(node == system || node == data);
            XmlElement provider = One(system, "Provider"), channel = One(system, "Channel"),
                eventId = One(system, "EventID"), created = One(system, "TimeCreated");
            Leaf(provider, false, "Name", "Guid", "EventSourceName"); Leaf(channel, true);
            Leaf(eventId, true, "Qualifiers"); Leaf(created, false, "SystemTime");
            Guid guid; if (provider.HasAttribute("Guid")) Need(Guid.TryParse(provider.GetAttribute("Guid"), out guid));
            ushort qualifiers; if (eventId.HasAttribute("Qualifiers"))
                Need(UInt16.TryParse(eventId.GetAttribute("Qualifiers"), NumberStyles.None, CultureInfo.InvariantCulture, out qualifiers));
            Need(provider.GetAttribute("Name") == "SideBySide" && channel.InnerText == "Application");
            ushort id; Need(UInt16.TryParse(eventId.InnerText, NumberStyles.None, CultureInfo.InvariantCulture, out id));
            DateTime time = XmlConvert.ToDateTime(created.GetAttribute("SystemTime"), XmlDateTimeSerializationMode.RoundtripKind);
            Need(time.Kind == DateTimeKind.Utc && time >= start && time <= end);
            var values = new List<string>(); int matches = 0, count = 0;
            foreach (XmlNode node in data.ChildNodes) {
                if (!(node is XmlElement)) continue;
                Need(node.LocalName == "Data" && node.NamespaceURI == Namespace && ++count <= 32);
                foreach (XmlNode nested in node.ChildNodes) Need(!(nested is XmlElement));
                string value = node.InnerText; Need(value.Length <= 16384);
                if (String.Equals(value, image, StringComparison.OrdinalIgnoreCase)) matches++;
                else values.Add(value);
            }
            Need(matches <= 1); if (matches == 0) return null;
            string text = String.Join("\n", values);
            return "WINDOWS_SXS_EVENT phase=modified-preflight event_id=" + id + " matched_owned_image=True" +
                " access_denied=" + (Has(text, "access is denied") || Has(text, "access denied")) +
                " dependent_assembly_not_found=" + (Has(text, "Dependent Assembly") && Has(text, "could not be found")) +
                " reference_definition_mismatch=" + (Has(text, "does not match") || Has(text, "not match")) +
                " manifest_invalid=" + (Has(text, "manifest") && Has(text, "invalid")) +
                " common_controls=" + Has(text, "Microsoft.Windows.Common-Controls") +
                " common_controls_resources=" + Has(text, "Microsoft.Windows.Common-Controls.Resources") +
                " vc90_crt=" + Has(text, "Microsoft.VC90.CRT") + " ucrt=" + Has(text, "ucrt") +
                " amd64=" + Has(text, "amd64") + " x86=" + Has(text, "x86") + " producer_verified=False cause_claimed=False";
        }
        internal static void Observe(string python, DateTime start, DateTime end)
        {
            try { Collect(python, start, end); }
            catch (Exception original) { throw new EvidenceFailure(original); }
        }
        static List<string> Collect(EventApi api, string python, DateTime start, DateTime end, Action deadline, Func<uint> timeout)
        {
            var lines = new List<string>(); int scanned = 0; uint total = 0; Exception primary = null;
            IntPtr results = api.query(); Need(results != IntPtr.Zero && results != Native.InvalidHandle);
            try {
                string pending = null;
                Enumerate(() => UseNext(value => { deadline(); api.next(results, timeout(), value); }, api.close, handle => {
                    deadline(); Need(scanned < 16);
                    pending = Classify(Render(api, handle, ref total, deadline), python, start, end); scanned++;
                }), () => { if (pending != null) lines.Add(pending); });
                deadline();
            }
            catch (Exception failure) { primary = failure; throw; }
            finally { Finish(primary, () => api.close(results)); }
            lines.Add("WINDOWS_SXS_EVENTS phase=modified-preflight scanned_count=" + scanned + " selected_count=" + lines.Count +
                " status=" + (lines.Count == 0 ? "inconclusive_no_match" : "evidence_present") + " producer_verified=False cause_claimed=False");
            return lines;
        }
        static void Collect(string python, DateTime start, DateTime end)
        {
            Need(Path.IsPathFullyQualified(python) && Path.GetFileName(python).Equals("python.exe", StringComparison.OrdinalIgnoreCase));
            Need(start.Kind == DateTimeKind.Utc && end.Kind == DateTimeKind.Utc && end >= start && (end - start).TotalSeconds <= 300);
            string query = "*[System[Provider[@Name='SideBySide'] and TimeCreated[@SystemTime>='" +
                XmlConvert.ToString(start, XmlDateTimeSerializationMode.Utc) + "' and @SystemTime<='" +
                XmlConvert.ToString(end, XmlDateTimeSerializationMode.Utc) + "']]]";
            var clock = Stopwatch.StartNew(); Action deadline = () => { if (clock.Elapsed.TotalSeconds >= 5) throw new TimeoutException("fixed SxS query deadline exceeded"); };
            var api = new EventApi {
                query = () => EvtQuery(IntPtr.Zero, "Application", query, 0x201),
                next = (results, timeout, value) => {
                    var handles = new IntPtr[1]; uint count;
                    value.success = EvtNext(results, 1, handles, timeout, 0, out count);
                    value.error = value.success ? 0 : Marshal.GetLastWin32Error(); value.count = count; value.handle = handles[0];
                },
                render = (item, capacity, data) => {
                    uint used, properties; bool success = EvtRender(IntPtr.Zero, item, 1, capacity, data, out used, out properties);
                    int error = success ? 0 : Marshal.GetLastWin32Error();
                    return new Rendered { success = success, error = error, bytes = used, properties = properties };
                },
                allocate = capacity => Marshal.AllocHGlobal(capacity),
                read = (data, bytes) => Marshal.Copy(data, bytes, 0, bytes.Length),
                release = (data, capacity) => {
                    try { for (int index = 0; index < capacity; index++) Marshal.WriteByte(data, index, 0); }
                    finally { Marshal.FreeHGlobal(data); }
                },
                close = handle => Need(EvtClose(handle))
            };
            foreach (string line in Collect(api, python, start, end, deadline,
                () => (uint)Math.Min(1000, Math.Max(0, 5000 - clock.ElapsedMilliseconds)))) Console.Out.WriteLine(line);
            Console.Out.Flush();
        }
    }
}
