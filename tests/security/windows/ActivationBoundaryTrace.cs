using System;
using System.Runtime.InteropServices;

namespace ScientificSecurity
{
    // Fixed caller-local observations on the existing trusted child; no stack or child-content reads.
    public sealed class ActivationBoundaryTrace
    {
        public static void CheckValidation()
        {
            KernelImage.CheckActivationBoundaryValidation();
            LoaderTrace.CheckActivationEventValidation();
            LoaderTrace.CheckActivationDestructionValidation();
            ChildActivationFixture.RequireDiagnosticRole(true, false, false, false, false, false, true);
            ChildActivationFixture.RequireDiagnosticRole(true, false, false, false, false, true, false);
            foreach (bool[] role in new [] {
                new [] { true, false, false, false, false, true, true }, new [] { false, false, false, false, false, false, true },
                new [] { true, true, false, false, false, false, true }, new [] { true, false, true, false, false, false, true },
                new [] { true, false, false, true, false, false, true }, new [] { true, false, false, false, true, false, true }
            }) {
                bool refused = false;
                try { ChildActivationFixture.RequireDiagnosticRole(role[0], role[1], role[2], role[3], role[4], role[5], role[6]); }
                catch (ArgumentException) { refused = true; }
                Need(refused);
            }
            Need(Next(1, 0, 0) == 2 && Next(2, 0, 0) == 3 && Next(3, 1, 0xC0000022) == 4);
            Need(Next(3, 1, 0x80000000) == 4 && Next(3, 1, UInt32.MaxValue) == 4);
            foreach (uint value in new uint[] { 0, 1, 0x7FFFFFFF }) {
                bool refused = false;
                try { Next(3, 1, value); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            foreach (int[] item in new [] { new [] {0,0}, new [] {1,1}, new [] {2,1}, new [] {3,0}, new [] {4,0}, new [] {4,1} }) {
                bool refused = false;
                try { Next(item[0], item[1], 0); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            byte[] baseline = new byte[DebugContext.Size]; Put(baseline, 112, 0x400);
            ulong[] first = { 0x1000, 0 }, post = { 0x2000, 0x3000 };
            bool[] one = { true, false }, two = { true, true };
            byte[] entry = Desired(baseline, baseline, first, one, false);
            byte[] sites = Desired(entry, baseline, post, two, false);
            byte[] restored = Desired(sites, baseline, post, two, true);
            Need(U64(entry, 72) == 0x1000 && U64(sites, 72) == 0x2000 && U64(sites, 80) == 0x3000 &&
                U64(sites, 112) == 0x405 && DebugContext.RawDebugEqual(restored, baseline));
            Need(DebugContext.UnchangedControlInteger(baseline, sites) && U64(baseline, 72) == 0);
            Need(Raw(0x12345678C0000022UL) == "raw_ebx=0xC0000022" && Raw(UInt64.MaxValue) == "raw_ebx=0xFFFFFFFF");
            byte[] scalar = new byte[DebugContext.Size]; Put(scalar, 120, 1); Put(scalar, 144, 0x12345678C0000022UL);
            Need(Raw(U64(scalar, 144)) == "raw_ebx=0xC0000022" && !Raw(U64(scalar, 144)).Contains("raw_eax"));
            Need(Complete(4, true, false) && !Complete(3, true, false) && !Complete(4, false, false) && !Complete(4, true, true));
            Need(Software(1, false, 7, 7, true) && !Software(2, false, 7, 7, true) &&
                !Software(1, true, 7, 7, true) && !Software(1, false, 8, 7, true) && !Software(1, false, 7, 7, false));
            var info = new MemoryInfo { address = new IntPtr(0x1000), allocation = new IntPtr(0x1000),
                size = new UIntPtr(0x1000), state = 0x1000, protect = 0x20, type = 0x1000000 };
            Need(ExecutableRegion(info, 0x1100, 2, 0x1000));
            Need(!ExecutableRegion(info, 0x1FFF, 2, 0x1000) && !ExecutableRegion(info, 0x1100, 2, 0x2000));
            foreach (uint access in new uint[] { 0, 1, 2, 4, 8, 0x120 }) {
                info.protect = access; Need(!ExecutableRegion(info, 0x1100, 2, 0x1000));
            }
            var observer = new ActivationBoundaryTrace(new IntPtr(1), new IntPtr(2), 7, 11, "fixed", "digest", _ => { });
            observer.stage = 4; observer.restored = true; observer.RequireComplete(); observer.Invalidate();
            bool incomplete = false;
            try { observer.RequireComplete(); } catch (InvalidOperationException) { incomplete = true; }
            Need(incomplete);
            var reporting = new InvalidOperationException("private-reporting-sentinel");
            AggregateException retained = null;
            try { RequireCheck(false, "software-ownership", () => { throw reporting; }); }
            catch (AggregateException failure) { retained = failure; }
            Need(retained != null && retained.InnerExceptions.Count == 2 &&
                retained.InnerExceptions[0].Message == "fixed activation observation refused check=software-ownership" &&
                Object.ReferenceEquals(retained.InnerExceptions[1], reporting));
            observer.original = new byte[DebugContext.Size]; observer.eventCode = 0x80000003;
            observer.eventCreator = observer.eventFirst = true;
            string metadata = observer.RefusalMetadata("software-ownership", observer.original);
            Need(metadata.Contains("check=software-ownership stage=4 event_code=0x80000003 creator=True first_chance=True") &&
                metadata.Contains("raw_dr6=0x0000000000000000") && metadata.Contains("raw_dr7=0x0000000000000000") &&
                !metadata.Contains("raw_eax") && !metadata.Contains("digest") && metadata.Length < 768);
            bool reported = false;
            RequireCheck(true, "software-ownership", () => { reported = true; });
            Need(!reported);
            Need(observer.RefusalMetadata("hardware-stage", null).EndsWith("context_read=False"));
            Put(observer.original, 104, UInt64.MaxValue); Put(observer.original, 112, UInt64.MaxValue);
            metadata = observer.RefusalMetadata("hardware-trap", observer.original);
            Need(metadata.Contains("raw_dr6=0xFFFFFFFFFFFFFFFF") && metadata.Contains("raw_dr7=0xFFFFFFFFFFFFFFFF") &&
                !metadata.Contains("raw_eax") && !metadata.Contains("fixed") && !metadata.Contains("digest") && metadata.Length < 768);
            observer.restored = false; observer.invalidated = false; observer.stage = 1;
            bool rejected = false;
            try { observer.AcceptSoftware(12, 0x80000003, true); } catch (InvalidOperationException) { rejected = true; }
            Need(rejected && !observer.initial);
            incomplete = false;
            try { observer.RequireComplete(); } catch (InvalidOperationException) { incomplete = true; }
            Need(incomplete);
            foreach (ulong rtm in new ulong[] { 0, 0x10000 })
                foreach (ulong fixedBit in new ulong[] { 0, 0x400 }) {
                    ulong status = 0xFFFE0FF0UL | rtm, control = 1UL | fixedBit;
                    Need(SoftwareStatus(status, control, 1));
                    foreach (ulong foreign in new ulong[] { 1, 2, 4, 8, 0x1000, 0x2000, 0x4000, 0x8000, 0x100000000 })
                        Need(!SoftwareStatus(status | foreign, control, 1));
                    Need(!SoftwareStatus(status ^ 0x800, control, 1) && !SoftwareStatus(status ^ 0x10, control, 1));
                    foreach (ulong foreign in new ulong[] { 2, 4, 0x100, 0x200, 0x800, 0x2000, 0x10000, 0x40000, 0x100000000 })
                        Need(!SoftwareStatus(status, control | foreign, 1));
                    Need(!SoftwareStatus(status, control | 0x800, 0x801));
                }
            observer.original = new byte[DebugContext.Size]; observer.enabled[0] = true;
            observer.addresses[0] = 0x1000; observer.initial = false;
            byte[] software = new byte[DebugContext.Size]; Put(software, 72, 0x1000);
            Put(software, 104, 0xFFFF0FF0); Put(software, 112, 0x401);
            observer.Ownership(software, false);
            byte[] idleArmed = Desired(observer.original, observer.original, observer.addresses, observer.enabled, false);
            Need(!DebugContext.RawDebugEqual(idleArmed, software));
            Need(U64(software, 112) != observer.Control() &&
                (U64(software, 104) & ~3UL) != (U64(observer.original, 104) & ~3UL));
            foreach (int offset in new [] { 72, 80, 88, 96 }) {
                byte[] foreign = (byte[])software.Clone(); Put(foreign, offset, 0x9999);
                rejected = false;
                try { observer.Ownership(foreign, false); } catch (InvalidOperationException) { rejected = true; }
                Need(rejected);
            }
            Need(!observer.initial && observer.stage == 1);
            string qualifiers = DebugContext.TrapQualifiers(0xFFFF0FF0);
            Need(qualifiers.Contains("rtm_bit_set=True") && qualifiers.Contains("bld_bit_set=True") && qualifiers.Contains("transaction_context=unknown"));
            qualifiers = DebugContext.TrapQualifiers(0xFFFE0FF0);
            Need(qualifiers.Contains("rtm_bit_set=False") && qualifiers.Contains("transaction_context=unknown"));
        }
        [StructLayout(LayoutKind.Sequential)] struct MemoryInfo {
            internal IntPtr address, allocation;
            internal uint allocationProtect; internal ushort partition;
            internal UIntPtr size; internal uint state, protect, type;
        }
        [DllImport("kernel32.dll", SetLastError = true)] static extern UIntPtr VirtualQueryEx(IntPtr process,
            IntPtr address, out MemoryInfo info, UIntPtr bytes);
        readonly IntPtr process, thread;
        readonly uint pid, tid;
        readonly string path, digest;
        readonly Action<string> emit;
        readonly ulong[] addresses = new ulong[2];
        readonly bool[] enabled = new bool[2];
        KernelImage fixture, kernel;
        byte[] original;
        int stage;
        uint eventCode;
        bool eventCreator, eventFirst;
        bool stopped, initial, changed, restored, invalidated, alive = true;
        internal ActivationBoundaryTrace(IntPtr processHandle, IntPtr threadHandle, uint processId, uint threadId,
            string executable, string imageDigest, Action<string> output)
        {
            Need(IntPtr.Size == 8 && Marshal.SizeOf(typeof(MemoryInfo)) == 48 &&
                processHandle != IntPtr.Zero && threadHandle != IntPtr.Zero);
            process = processHandle; thread = threadHandle; pid = processId; tid = threadId;
            path = executable; digest = imageDigest; emit = output;
        }
        static void Need(bool value) { if (!value) throw new InvalidOperationException("fixed activation caller-site observation is inconclusive"); }
        static void RequireCheck(bool value, string check, Action report)
        {
            if (value) return;
            var primary = new InvalidOperationException("fixed activation observation refused check=" + check);
            try { report(); }
            catch (Exception reporting) { throw new AggregateException("activation refusal and reporting failed", primary, reporting); }
            throw primary;
        }
        string RefusalMetadata(string check, byte[] context)
        {
            string value = "phase=activation-refusal check=" + check + " stage=" + stage +
                " event_code=0x" + eventCode.ToString("X8") + " creator=" + eventCreator + " first_chance=" + eventFirst +
                " initial_seen=" + initial + " kernel_qualified=" + (kernel != null);
            if (context == null) return value + " context_read=False";
            value += " context_read=True " + DebugContext.TrapQualifiers(U64(context, 104)) + " raw_dr7=0x" + U64(context, 112).ToString("X16");
            if (original == null) return value + " baseline_present=False";
            for (int index = 0; index < 4; index++)
                value += " dr" + index + "_match=" + (U64(context, 72 + index * 8) ==
                    (index < 2 ? addresses[index] : U64(original, 72 + index * 8)));
            return value + " dr7_exact=" + (U64(context, 112) == Control()) +
                " dr6_unowned_match=" + ((U64(context, 104) & ~3UL) == (U64(original, 104) & ~3UL));
        }
        void Check(bool value, string check, byte[] context = null)
        { if (!value) RequireCheck(false, check, () => emit(RefusalMetadata(check, context))); }
        static ulong U64(byte[] value, int offset) { return BitConverter.ToUInt64(value, offset); }
        static void Put(byte[] value, int offset, ulong number) { BitConverter.GetBytes(number).CopyTo(value, offset); }
        static string Raw(ulong value) { return "raw_ebx=0x" + unchecked((uint)value).ToString("X8"); }
        static int Next(int stage, int slot, uint raw)
        {
            if (stage == 1 && slot == 0) return 2;
            if (stage == 2 && slot == 0) return 3;
            if (stage == 3 && slot == 1 && (raw & 0x80000000) != 0) return 4;
            throw new InvalidOperationException("fixed activation observation order is invalid");
        }
        static bool Complete(int state, bool restoration, bool invalid) { return state == 4 && restoration && !invalid; }
        static bool Software(int state, bool seen, uint eventThread, uint creator, bool first)
        { return state == 1 && !seen && eventThread == creator && first; }
        internal void Stop(uint eventPid, uint eventThread, uint kind)
        {
            Need(eventPid == pid); stopped = true;
            if (kind == 5 || (kind == 4 && eventThread == tid)) alive = false;
        }
        internal void Continued() { stopped = false; }
        byte[] Read() { Need(stopped && alive); return DebugContext.Read(thread); }
        static bool Free(byte[] context)
        {
            for (int offset = 72; offset <= 96; offset += 8) if (U64(context, offset) != 0) return false;
            return (U64(context, 112) & 0xFFFF28FFUL) == 0 && (U64(context, 104) & 0xE00FUL) == 0;
        }
        static byte[] Desired(byte[] before, byte[] baseline, ulong[] sites, bool[] active, bool restore)
        {
            byte[] result = (byte[])before.Clone(); ulong control = U64(baseline, 112);
            for (int index = 0; index < 4; index++) {
                Put(result, 72 + index * 8, restore || index >= 2 ? U64(baseline, 72 + index * 8) : sites[index]);
                if (!restore && index < 2 && active[index]) control |= 1UL << (index * 2);
            }
            Put(result, 104, U64(baseline, 104)); Put(result, 112, control);
            BitConverter.GetBytes(0x100010U).CopyTo(result, 48); return result;
        }
        void Apply(byte[] before, bool restore)
        {
            Need(original != null && stopped && alive);
            byte[] desired = Desired(before, original, addresses, enabled, restore), after = null;
            try {
                changed = true; DebugContext.Write(thread, desired); after = Read();
                Check(DebugContext.RawDebugEqual(desired, after) && DebugContext.UnchangedControlInteger(before, after), "setter-readback", after);
                if (restore) { changed = false; restored = true; }
            }
            finally { Array.Clear(desired, 0, desired.Length); if (after != null) Array.Clear(after, 0, after.Length); }
        }
        ulong Control()
        {
            ulong value = U64(original, 112);
            for (int index = 0; index < 2; index++) if (enabled[index]) value |= 1UL << (index * 2);
            return value;
        }
        static bool SoftwareStatus(ulong status, ulong control, ulong expectedControl)
        {
            return (status & ~0x10000UL) == 0xFFFE0FF0UL && (expectedControl & ~0x405UL) == 0 &&
                ((control ^ expectedControl) & ~0x400UL) == 0;
        }
        void Ownership(byte[] context, bool trap)
        {
            for (int index = 0; index < 4; index++)
                Check(U64(context, 72 + index * 8) == (index < 2 ? addresses[index] : U64(original, 72 + index * 8)),
                    trap ? "hardware-address-ownership" : "software-address-ownership", context);
            if (!trap) Check(SoftwareStatus(U64(context, 104), U64(context, 112), Control()),
                "software-control-ownership", context);
        }
        static bool ExecutableRegion(MemoryInfo info, ulong address, uint bytes, ulong image)
        {
            ulong start = unchecked((ulong)info.address.ToInt64()), size = info.size.ToUInt64();
            uint access = info.protect & 0xFF;
            return bytes != 0 && address >= start && address - start <= size && bytes <= size - (address - start) &&
                info.state == 0x1000 && info.type == 0x1000000 && unchecked((ulong)info.allocation.ToInt64()) == image &&
                (info.protect & 0x100) == 0 && (access == 0x10 || access == 0x20 || access == 0x40 || access == 0x80);
        }
        void RequireExecutable(KernelImage image, uint rva, uint bytes)
        {
            ulong address = image.Address(rva); Need(image.ContainsExecutable(address + bytes - 1));
            MemoryInfo info; UIntPtr size = new UIntPtr((uint)Marshal.SizeOf(typeof(MemoryInfo)));
            Need(VirtualQueryEx(process, new IntPtr((long)address), out info, size).ToUInt64() == size.ToUInt64() &&
                ExecutableRegion(info, address, bytes, image.Base));
        }
        internal void Creation(IntPtr file, IntPtr imageBase)
        {
            Need(stage == 0 && stopped && alive);
            fixture = KernelImage.FromActivationCreation(file, imageBase, path, digest);
            RequireExecutable(fixture, fixture.Entry, 1);
            original = Read(); Need(Free(original));
            addresses[0] = fixture.Address(fixture.Entry); enabled[0] = true; stage = 1;
            Apply(original, false);
            emit("phase=activation-entry-arm create_identity_qualified=True control_integer_unchanged=True");
        }
        internal void Load(IntPtr file, IntPtr imageBase)
        {
            Need(stopped && alive && stage != 0);
            KernelImage candidate = KernelImage.FromActivationSystemLoad(file, imageBase);
            if (candidate == null) return;
            Need(kernel == null && stage == 1); kernel = candidate;
            emit("phase=activation-load module=kernel32.dll identity_equal=True fixed_profile=True");
        }
        internal void Event(uint eventThread, uint code, bool first)
        { eventCode = code; eventCreator = eventThread == tid; eventFirst = first; }
        internal bool AcceptSoftware(uint eventThread, uint code, bool first)
        {
            if (code != 0x80000003) return false;
            Check(Software(stage, initial, eventThread, tid, first), "software-stage");
            byte[] before = Read(); string qualifiers;
            try { Ownership(before, false); qualifiers = DebugContext.TrapQualifiers(U64(before, 104)); initial = true; }
            finally { Array.Clear(before, 0, before.Length); }
            emit("phase=activation-software-stop origin_verified=False ordering_only=True " + qualifiers); return true;
        }
        internal bool SingleStep(uint eventThread, uint code, bool first, IntPtr exceptionAddress)
        {
            if (code != 0x80000004) return false;
            Check(!invalidated && stage >= 1 && stage <= 3 && first && eventThread == tid && original != null, "hardware-stage");
            byte[] before = Read();
            try {
                ulong status = U64(before, 104), cause = status & 0xE00FUL;
                int slot = cause == 1 ? 0 : cause == 2 ? 1 : -1;
                Ownership(before, true);
                Check(slot >= 0 && DebugContext.OwnedTrapSite(eventThread, tid, first, enabled[slot], U64(before, 248), addresses[slot]) &&
                    unchecked((ulong)exceptionAddress.ToInt64()) == U64(before, 248) &&
                    DebugContext.OwnedTrapStatus(status, U64(before, 112), Control(), slot), "hardware-trap", before);
                int next = Next(stage, slot, stage == 3 ? unchecked((uint)U64(before, 144)) : 0);
                if (stage == 1) {
                    Check(initial && kernel != null, "entry-prerequisites", before);
                    RequireExecutable(kernel, KernelImage.WorkerEntryRva, 15); RequireExecutable(kernel, KernelImage.FailureFunnelRva, 2);
                    addresses[0] = kernel.Address(KernelImage.WorkerEntryRva); addresses[1] = kernel.Address(KernelImage.FailureFunnelRva);
                    Need(addresses[0] != addresses[1] && addresses[0] != fixture.Address(fixture.Entry) && addresses[1] != fixture.Address(fixture.Entry));
                    enabled[0] = enabled[1] = true; stage = next; Apply(before, false);
                    emit("phase=activation-entry-hit " + DebugContext.TrapQualifiers(status) + " worker_sites_armed=True control_integer_unchanged=True");
                }
                else {
                    addresses[slot] = 0; enabled[slot] = false; stage = next;
                    if (stage == 4) {
                        Restore();
                        emit("phase=activation-caller-site site=worker-failure-funnel " + Raw(U64(before, 144)) + " " + DebugContext.TrapQualifiers(status) +
                            " caller_local=True producer_verified=False invocation_pair_claimed=False control_integer_unchanged=True");
                        emit("phase=activation-sites-complete restored=True worker_entry_observed=True funnel_observed=True branch_claimed=False cause_claimed=False");
                    }
                    else {
                        Apply(before, false);
                        emit("phase=activation-worker-entry " + DebugContext.TrapQualifiers(status) +
                            " slot_disabled=True scalar_read=False dispatch_route_verified=False control_integer_unchanged=True");
                    }
                }
                return true;
            }
            finally { Array.Clear(before, 0, before.Length); }
        }
        internal void OtherThread() { Invalidate(); throw new InvalidOperationException("fixed activation diagnostic encountered another thread transition"); }
        internal void Unload(IntPtr imageBase)
        {
            ulong address = unchecked((ulong)imageBase.ToInt64());
            if ((fixture != null && fixture.Base == address) || (kernel != null && kernel.Base == address)) {
                Invalidate(); throw new InvalidOperationException("fixed activation diagnostic image unloaded");
            }
        }
        internal void Invalidate() { invalidated = true; }
        internal void RequireComplete() { Need(Complete(stage, restored, invalidated)); }
        internal void Restore()
        {
            if (!changed || !alive || !stopped) return;
            byte[] before = Read();
            try { Apply(before, true); }
            finally { Array.Clear(before, 0, before.Length); }
        }
        internal void Destroyed()
        {
            alive = changed = stopped = false;
            if (original != null) Array.Clear(original, 0, original.Length);
            Array.Clear(addresses, 0, addresses.Length); Array.Clear(enabled, 0, enabled.Length);
            emit("phase=activation-cleanup state_destroyed=True restored_claimed=False");
        }
    }
}
