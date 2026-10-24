using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace ScientificSecurity
{
    // Two fixed creator-thread hardware execute slots. Never modifies code, arguments, results or PEB.
    public sealed class HardwareTrace
    {
        const int ContextSize = 1232, ContextFlags = 48, Dr0 = 72, Dr6 = 104, Dr7 = 112;
        const uint WriteFlags = 0x100010;
        const ulong CauseMask = 0xE00F, OccupiedControl = 0xFFFF28FF;
        [StructLayout(LayoutKind.Sequential)] struct MemoryInfo {
            internal IntPtr address, allocationBase;
            internal uint allocationProtect; internal ushort partition;
            internal UIntPtr size; internal uint state, protect, type;
        }
        [DllImport("kernel32.dll", SetLastError = true)] static extern UIntPtr VirtualQueryEx(IntPtr process, IntPtr address,
            out MemoryInfo info, UIntPtr bytes);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr process,
            IntPtr address, byte[] bytes, UIntPtr count, out UIntPtr read);
        readonly IntPtr process, thread;
        readonly uint pid, tid;
        readonly Action<string> emit;
        readonly Dictionary<string, KernelImage> images = new Dictionary<string, KernelImage>(StringComparer.Ordinal);
        readonly ulong[] entries = new ulong[2], addresses = new ulong[2], returns = new ulong[2], stacks = new ulong[2];
        readonly bool[] enabled = new bool[2], returning = new bool[2];
        byte[] original;
        readonly ulong[] entryStatuses = new ulong[2];
        bool siteConsumed, outerPaired, restored, invalidated;
        bool creatorAlive = true, stopped, modified, completed;

        internal HardwareTrace(IntPtr processHandle, IntPtr threadHandle, uint processId, uint threadId, Action<string> output)
        {
            if (IntPtr.Size != 8 || Marshal.SizeOf(typeof(MemoryInfo)) != 48 || processHandle == IntPtr.Zero || threadHandle == IntPtr.Zero)
                throw new PlatformNotSupportedException("hardware trace requires the verified Windows x64 ABI and owned handles");
            process = processHandle; thread = threadHandle; pid = processId; tid = threadId; emit = output;
        }
        internal void Stop(uint processId, uint threadId, uint kind)
        {
            if (processId != pid) throw new InvalidOperationException("hardware event is not the fixed owned process");
            stopped = true;
            if (kind == 5 || (kind == 4 && threadId == tid)) creatorAlive = false;
        }
        internal void Continued() { stopped = false; }
        void LiveStop()
        {
            if (!stopped || !creatorAlive) throw new InvalidOperationException("hardware context access requires a pending live debug event");
        }
        byte[] ReadContext()
        {
            LiveStop(); return DebugContext.Read(thread);
        }
        static ulong U64(byte[] context, int offset) { return BitConverter.ToUInt64(context, offset); }
        static void Put(byte[] context, int offset, ulong value) { BitConverter.GetBytes(value).CopyTo(context, offset); }
        static bool UnchangedControlInteger(byte[] before, byte[] after)
        {
            return DebugContext.UnchangedControlInteger(before, after);
        }
        static bool FreeDebugState(byte[] context)
        {
            for (int offset = Dr0; offset < Dr6; offset += 8) if (U64(context, offset) != 0) return false;
            return (U64(context, Dr7) & OccupiedControl) == 0 && (U64(context, Dr6) & CauseMask) == 0;
        }
        void Save()
        {
            if (original != null) return;
            original = ReadContext();
            if (!FreeDebugState(original)) throw new InvalidOperationException("hardware trace refuses existing debug-register ownership");
        }
        void RequireOwned(byte[] context)
        {
            ulong control = U64(original, Dr7);
            for (int index = 0; index < 2; index++) {
                if (U64(context, Dr0 + index * 8) != addresses[index])
                    throw new InvalidOperationException("hardware address register changed outside owned protocol");
                if (enabled[index]) control |= 1UL << (index * 2);
            }
            if (U64(context, Dr0 + 16) != U64(original, Dr0 + 16) || U64(context, Dr0 + 24) != U64(original, Dr0 + 24) ||
                U64(context, Dr7) != control || (U64(context, Dr6) & ~3UL) != (U64(original, Dr6) & ~3UL))
                throw new InvalidOperationException("hardware unowned control/status registers changed "
                    + OwnershipMetadata(context, original, U64(original, Dr6), control));
        }
        static string OwnershipMetadata(byte[] current, byte[] baseline, ulong status, ulong control)
        {
            ulong dr6 = U64(current, Dr6), dr7 = U64(current, Dr7);
            return "dr2_match=" + (U64(current, Dr0 + 16) == U64(baseline, Dr0 + 16))
                + " dr3_match=" + (U64(current, Dr0 + 24) == U64(baseline, Dr0 + 24))
                + " dr7_control_match=" + (dr7 == control)
                + " dr6_unowned_match=" + ((dr6 & ~3UL) == (status & ~3UL))
                + " dr6_cause_mask=0x" + (dr6 & CauseMask).ToString("X16")
                + " dr6_other_bits_xor=0x" + ((dr6 ^ status) & ~CauseMask).ToString("X16")
                + " dr6_expected=0x" + status.ToString("X16") + " dr6_actual=0x" + dr6.ToString("X16")
                + " dr7_expected=0x" + control.ToString("X16") + " dr7_actual=0x" + dr7.ToString("X16");
        }
        void Apply(byte[] before, bool restore)
        {
            LiveStop(); byte[] desired = (byte[])before.Clone();
            ulong control = U64(original, Dr7);
            for (int index = 0; index < 4; index++) {
                ulong address = restore || index >= 2 ? U64(original, Dr0 + index * 8) : addresses[index];
                Put(desired, Dr0 + index * 8, address);
                if (!restore && index < 2 && enabled[index]) control |= 1UL << (index * 2);
            }
            Put(desired, Dr6, U64(original, Dr6)); // Set/restore saved configuration, never trap-time RTM payload.
            Put(desired, Dr7, control);
            BitConverter.GetBytes(WriteFlags).CopyTo(desired, ContextFlags);
            modified = true; // A failing setter/readback may still have changed state: always attempt restoration.
            DebugContext.Write(thread, desired);
            byte[] after = ReadContext();
            if (!UnchangedControlInteger(before, after))
                throw new InvalidOperationException("hardware context write altered CONTROL/INTEGER state");
            if (!DebugContext.RawDebugEqual(desired, after))
                throw new InvalidOperationException("hardware debug-register readback differs from exact requested state");
            if (restore) modified = false;
        }
        internal void Load(IntPtr file, IntPtr imageBase)
        {
            if (completed) return;
            LiveStop(); KernelImage image = KernelImage.FromLoad(file, imageBase);
            if (image == null) return;
            if (images.ContainsKey(image.Name)) throw new InvalidOperationException("hardware system image was loaded twice");
            images.Add(image.Name, image);
            if (image.Name != "kernelbase.dll") return; // Ntdll remains a known return image, never a slot1 selector/write.
            uint site = StaticKernelInspection.BindLoad(image); emit(image.KernelBaseIdentity());
            image.RequireCheckpointAddress();
            ulong entry = image.Address(image.Entry), observation = image.Address(site);
            RequireExecutable(entry, image); RequireExecutable(observation, image, 2);
            if (entry == observation) throw new InvalidOperationException("hardware entry and fixed observation site alias");
            Save(); byte[] before = ReadContext(); RequireOwned(before);
            entries[0] = entry; entries[1] = observation;
            addresses[0] = entry; addresses[1] = 0; enabled[0] = true; enabled[1] = false;
            Apply(before, false);
            emit("phase=hardware-arm routine=KernelBaseEntry enabled=True site_enabled=False control_integer_unchanged=True");
        }
        MemoryInfo Region(ulong address, uint bytes)
        {
            MemoryInfo info; uint size = (uint)Marshal.SizeOf(typeof(MemoryInfo));
            UIntPtr returned = VirtualQueryEx(process, new IntPtr(unchecked((long)address)), out info, new UIntPtr(size));
            if (returned.ToUInt64() != size) throw new InvalidOperationException("hardware memory region query is unavailable");
            ulong start = unchecked((ulong)info.address.ToInt64()), length = info.size.ToUInt64();
            if (address < start || address - start > length || bytes > length - (address - start) ||
                info.state != 0x1000 || (info.protect & 0x100) != 0 || (info.protect & 0xFF) == 1)
                throw new InvalidOperationException("hardware memory span is not wholly committed/accessibile");
            return info;
        }
        void RequireExecutable(ulong address, KernelImage image, uint bytes = 1)
        {
            MemoryInfo info = Region(address, bytes); uint protection = info.protect & 0xFF;
            if (!image.ContainsExecutable(address) || !image.ContainsExecutable(address + bytes - 1) || info.type != 0x1000000 ||
                unchecked((ulong)info.allocationBase.ToInt64()) != image.Base ||
                (protection != 0x10 && protection != 0x20 && protection != 0x40 && protection != 0x80))
                throw new InvalidOperationException("hardware routine is not executable within the verified loaded OS image");
        }
        void RequireKnownReturn(ulong address)
        {
            foreach (KernelImage image in images.Values)
                if (image.ContainsExecutable(address)) { RequireExecutable(address, image); return; }
            throw new InvalidOperationException("hardware return address is outside verified OS image execution spans");
        }
        ulong ReturnAddress(ulong stack)
        {
            if ((stack & 7) != 0 || stack > 0x7FFFFFFFFFFFFFFFUL - 8)
                throw new InvalidOperationException("hardware entry stack address is invalid");
            MemoryInfo info = Region(stack, 8); uint protection = info.protect & 0xFF;
            if (info.type != 0x20000 || (protection != 2 && protection != 4 && protection != 8))
                throw new InvalidOperationException("hardware return read is not a bounded private readable stack span");
            byte[] bytes = new byte[8];
            try {
                UIntPtr read;
                Native.Check(ReadProcessMemory(process, new IntPtr(unchecked((long)stack)), bytes, new UIntPtr(8), out read),
                    "read exactly one hardware entry return address");
                if (read.ToUInt64() != 8) throw new InvalidOperationException("hardware return-address read was partial");
                ulong address = BitConverter.ToUInt64(bytes, 0); RequireKnownReturn(address); return address;
            }
            finally { Array.Clear(bytes, 0, bytes.Length); }
        }
        internal bool SingleStep(uint eventThread, uint code, bool firstChance)
        {
            if (code != 0x80000004) return false;
            if (completed) throw new InvalidOperationException("single-step arrived after the fixed observation window closed");
            if (eventThread != tid || !firstChance || original == null)
                throw new InvalidOperationException("hardware single-step cannot be attributed to the owned creator protocol");
            byte[] before = ReadContext();
            ulong eventStatus = U64(before, Dr6), cause = eventStatus & CauseMask;
            int slot = cause == 1 ? 0 : cause == 2 ? 1 : -1;
            ulong control = U64(original, Dr7);
            for (int index = 0; index < 2; index++) {
                if (U64(before, Dr0 + index * 8) != addresses[index])
                    throw new InvalidOperationException("hardware trap address changed outside the owned protocol");
                if (enabled[index]) control |= 1UL << (index * 2);
            }
            if (slot < 0 || !DebugContext.OwnedTrapSite(eventThread, tid, firstChance, enabled[slot], U64(before, 248), addresses[slot]) ||
                U64(before, Dr0 + 16) != U64(original, Dr0 + 16) || U64(before, Dr0 + 24) != U64(original, Dr0 + 24) ||
                !DebugContext.OwnedTrapStatus(eventStatus, U64(before, Dr7), control, slot))
                throw new InvalidOperationException("hardware exception has an unowned, foreign or unsupported trap status");
            if (slot == 1) {
                if (invalidated) throw new InvalidOperationException("one-shot site reached an invalidated diagnostic window");
                RequireSiteWindow(stacks[0] != 0 && returning[0], siteConsumed, returning[1]);
                string scalar;
                try { scalar = RawSiteValue(before) + " " + RawCheckpoint(ReadCheckpoint()); }
                catch { Invalidate(); throw; }
                ConsumeSite(addresses, enabled); Apply(before, false); siteConsumed = true;
                emit("phase=hardware-site site=KernelBaseEarlierByteCompare rva=0x" + (entries[1] - images["kernelbase.dll"].Base).ToString("X8") + " " + scalar + " " + DebugContext.TrapQualifiers(eventStatus) +
                    " observation_scope=attach_window provisional=True slot_disabled=True control_integer_unchanged=True");
                return true;
            }
            ulong stack = U64(before, 152);
            if (!returning[0]) {
                if (unchecked((uint)U64(before, 136)) != 1)
                    throw new InvalidOperationException("hardware KernelBase observation is not PROCESS_ATTACH");
                ulong target = ReturnAddress(stack);
                if (target == entries[slot] || (enabled[1 - slot] && target == addresses[1 - slot]))
                    throw new InvalidOperationException("hardware return breakpoint aliases an active entry/return slot");
                stacks[slot] = stack; returns[slot] = target; entryStatuses[slot] = eventStatus;
                // Entry stays disarmed until this outermost return; recursive calls are intentionally unobserved.
                addresses[slot] = target; returning[slot] = true;
                ArmSiteWindow(entries, addresses, enabled, siteConsumed);
                Apply(before, false);
                emit("phase=hardware-entry routine=KernelBaseEntry reason=PROCESS_ATTACH"
                    + " " + DebugContext.TrapQualifiers(eventStatus)
                    + " outermost_only=True control_integer_unchanged=True");
            }
            else {
                if (returning[1]) throw new InvalidOperationException("one-shot site entered an unsupported callee-return state");
                if (!Pair(stack, stacks[slot], U64(before, 248), returns[slot]))
                    throw new InvalidOperationException("hardware outermost return stack/address pairing is inconclusive");
                uint result = unchecked((uint)U64(before, 120));
                // Observe one KernelBase PROCESS_ATTACH pair, never re-arm for PROCESS_DETACH.
                addresses[0] = addresses[1] = 0; returning[0] = false; enabled[0] = enabled[1] = false;
                Apply(before, false); outerPaired = true;
                emit("phase=hardware-return routine=KernelBaseEntry attach_succeeded=" + (result != 0) + " entry_raw_dr6=0x" + entryStatuses[slot].ToString("X16")
                    + " entry_rtm_bit_set=" + ((entryStatuses[slot] & 0x10000) != 0)
                    + " entry_bld_bit_set=" + ((entryStatuses[slot] & 0x800) != 0)
                    + " " + DebugContext.TrapQualifiers(eventStatus) + " pair_verified=True control_integer_unchanged=True");
                Restore(); // The selected window ends with the first PROCESS_ATTACH pair.
            }
            return true;
        }
        ushort ReadCheckpoint()
        {
            LiveStop(); KernelImage image;
            if (!images.TryGetValue("kernelbase.dll", out image))
                throw new InvalidOperationException("checkpoint read lacks its matched KernelBase image");
            ulong address = image.RequireCheckpointAddress();
            RequireCheckpointRegion(Region(address, 2), address, image.Base, checked((uint)(address - image.Base)));
            byte[] bytes = new byte[2];
            try {
                UIntPtr read;
                bool copied = ReadProcessMemory(process, new IntPtr(unchecked((long)address)), bytes, new UIntPtr(2), out read);
                Native.Check(copied, "read exactly one fixed KernelBase checkpoint WORD");
                return DecodeCheckpoint(copied, read.ToUInt64(), bytes);
            }
            finally { Array.Clear(bytes, 0, bytes.Length); }
        }
        static void RequireCheckpointRegion(MemoryInfo info, ulong address, ulong imageBase, uint expectedRva)
        {
            ulong start = unchecked((ulong)info.address.ToInt64()), length = info.size.ToUInt64();
            if (imageBase == 0 || imageBase > 0x7FFFFFFFFFFFFFFFUL - expectedRva - 2 ||
                address != imageBase + expectedRva || start > address || start > 0x7FFFFFFFFFFFFFFFUL ||
                length > 0x7FFFFFFFFFFFFFFFUL - start || address - start > length || 2UL > length - (address - start) ||
                info.state != 0x1000 || info.type != 0x1000000 || unchecked((ulong)info.allocationBase.ToInt64()) != imageBase ||
                (info.protect != 4 && info.protect != 8))
                throw new InvalidOperationException("checkpoint read is not the complete fixed committed non-executable writable image span");
        }
        static ushort DecodeCheckpoint(bool copied, ulong count, byte[] bytes)
        {
            try {
                if (!copied || count != 2 || bytes == null || bytes.Length != 2)
                    throw new InvalidOperationException("checkpoint read did not return exactly one complete WORD");
                return (ushort)(bytes[0] | (bytes[1] << 8));
            }
            finally { if (bytes != null) Array.Clear(bytes, 0, bytes.Length); }
        }
        static string RawCheckpoint(ushort value) { return "raw_checkpoint=0x" + value.ToString("X4"); }
        static string RawSiteValue(byte[] context)
        { return "raw_eax=0x" + unchecked((uint)U64(context, 120)).ToString("X8"); }
        static void RequireSiteWindow(bool outerPending, bool consumed, bool siteReturning)
        {
            if (!outerPending || consumed || siteReturning)
                throw new InvalidOperationException("one-shot site is outside its unconsumed outer attach window");
        }
        static void ConsumeSite(ulong[] activeAddresses, bool[] activeSlots)
        { activeAddresses[1] = 0; activeSlots[1] = false; }
        static void ArmSiteWindow(ulong[] routineEntries, ulong[] activeAddresses, bool[] activeSlots, bool consumed)
        {
            if (consumed || routineEntries[1] == 0 || routineEntries[1] == activeAddresses[0] || activeSlots[1])
                throw new InvalidOperationException("hardware attach window lacks a distinct inactive unconsumed site");
            activeAddresses[1] = routineEntries[1]; activeSlots[1] = true;
        }
        static void RequireObservationComplete(bool consumed, bool paired, bool restoration)
        {
            if (!consumed || !paired || !restoration)
                throw new InvalidOperationException("one-shot diagnostic is inconclusive: site, outer pair or restoration missing");
        }
        internal void RequireComplete()
        {
            RequireObservationComplete(siteConsumed, outerPaired, restored);
            if (invalidated) throw new InvalidOperationException("one-shot diagnostic window was invalidated after observation");
        }
        internal void Invalidate() { invalidated = true; }
        static bool CanRestore(bool changed, bool alive, bool pending)
        { return changed && alive && pending; }
        static bool Pair(ulong currentStack, ulong entryStack, ulong currentAddress, ulong returnedAddress)
        { return entryStack <= UInt64.MaxValue - 8 && currentStack == entryStack + 8 && currentAddress == returnedAddress; }
        internal void OtherThread(uint eventThread, uint kind)
        {
            if (kind == 2 || (kind == 4 && eventThread != tid))
                throw new InvalidOperationException("hardware creator-only diagnostic encountered another thread transition");
        }
        internal void Unload(IntPtr imageBase)
        {
            if (completed) return;
            ulong address = unchecked((ulong)imageBase.ToInt64());
            foreach (KernelImage image in images.Values)
                if (image.Base == address) {
                    invalidated = true; Restore();
                    emit("phase=hardware-unload observation=inconclusive"); return;
                }
        }
        internal void Restore()
        {
            if (!CanRestore(modified, creatorAlive, stopped)) return;
            byte[] before = ReadContext(); Apply(before, true);
            completed = true; restored = true; Array.Clear(enabled, 0, enabled.Length); Array.Clear(returning, 0, returning.Length);
            emit("phase=hardware-restore restored=True control_integer_unchanged=True");
        }
        internal void Destroyed()
        {
            creatorAlive = false; modified = false;
            if (original != null) Array.Clear(original, 0, original.Length);
            Array.Clear(entries, 0, entries.Length); Array.Clear(addresses, 0, addresses.Length);
            Array.Clear(returns, 0, returns.Length); Array.Clear(stacks, 0, stacks.Length);
            Array.Clear(entryStatuses, 0, entryStatuses.Length);
            emit("phase=hardware-cleanup state_destroyed=True restored_claimed=False");
        }
        static void CheckCheckpointReadValidation()
        {
            const uint expectedRva = 0x39A7E8;
            const ulong imageBase = 0x180000000, address = 0x18039A7E8;
            var info = new MemoryInfo { address = new IntPtr(0x18039A000L), allocationBase = new IntPtr((long)imageBase),
                size = new UIntPtr(0x1000), state = 0x1000, type = 0x1000000, protect = 4 };
            RequireCheckpointRegion(info, address, imageBase, expectedRva);
            MemoryInfo copy = info; copy.protect = 8; RequireCheckpointRegion(copy, address, imageBase, expectedRva);
            foreach (uint protection in new uint[] { 0, 1, 2, 0x10, 0x20, 0x40, 0x80, 0x104, 0x204, 0x404, 0x80000004 }) {
                copy = info; copy.protect = protection; RequireCheckpointRegionRefused(copy, address, imageBase);
            }
            copy = info; copy.state = 0x2000; RequireCheckpointRegionRefused(copy, address, imageBase);
            copy = info; copy.type = 0x20000; RequireCheckpointRegionRefused(copy, address, imageBase);
            copy = info; copy.allocationBase = new IntPtr((long)imageBase + 1); RequireCheckpointRegionRefused(copy, address, imageBase);
            copy = info; copy.address = new IntPtr((long)address + 1); RequireCheckpointRegionRefused(copy, address, imageBase);
            copy = info; copy.size = new UIntPtr(0x7E9); RequireCheckpointRegionRefused(copy, address, imageBase);
            copy = info; copy.size = UIntPtr.Zero; RequireCheckpointRegionRefused(copy, address, imageBase);
            copy = info; copy.size = new UIntPtr(UInt64.MaxValue); RequireCheckpointRegionRefused(copy, address, imageBase);
            RequireCheckpointRegionRefused(info, address + 1, imageBase);
            RequireCheckpointRegionRefused(info, 0x18039B8F8, imageBase);
            RequireCheckpointRegionRefused(info, address, 0);
            var historical = info; historical.address = new IntPtr(0x18039B000L);
            RequireCheckpointRegion(historical, 0x18039B8F8, imageBase, 0x39B8F8);
            RequireCheckpointRegionRefused(historical, 0x18039B8F8, imageBase, 0x39A7E8);
            RequireCheckpointRegionRefused(info, address, imageBase, 0x39B8F8);
            byte[][] bytes = { new byte[] { 0, 0 }, new byte[] { 0x58, 0x02 }, new byte[] { 0x12, 0x34 }, new byte[] { 0xFF, 0xFF } };
            string[] expected = { "raw_checkpoint=0x0000", "raw_checkpoint=0x0258", "raw_checkpoint=0x3412", "raw_checkpoint=0xFFFF" };
            for (int index = 0; index < bytes.Length; index++) {
                string value = RawCheckpoint(DecodeCheckpoint(true, 2, bytes[index]));
                if (value != expected[index] || value.Length != 21) throw new InvalidOperationException("checkpoint scalar lost exact little-endian WORD semantics");
                RequireCheckpointCleared(bytes[index]);
            }
            foreach (ulong count in new ulong[] { 0, 1, 3, UInt64.MaxValue }) {
                byte[] value = { 0x12, 0x34 }; bool refused = false;
                try { DecodeCheckpoint(true, count, value); } catch (InvalidOperationException) { refused = true; }
                if (!refused) throw new InvalidOperationException("checkpoint read accepted a partial or oversized transfer");
                RequireCheckpointCleared(value);
            }
            byte[] failed = { 0x12, 0x34 }; bool failedRefused = false;
            try { DecodeCheckpoint(false, 2, failed); } catch (InvalidOperationException) { failedRefused = true; }
            if (!failedRefused) throw new InvalidOperationException("checkpoint read accepted native failure");
            RequireCheckpointCleared(failed);
            foreach (byte[] malformed in new byte[][] { null, new byte[0], new byte[] { 0x12 }, new byte[] { 1, 2, 3 } }) {
                bool refused = false;
                try { DecodeCheckpoint(true, 2, malformed); } catch (InvalidOperationException) { refused = true; }
                if (!refused) throw new InvalidOperationException("checkpoint read accepted the wrong buffer width");
                if (malformed != null) RequireCheckpointCleared(malformed);
            }
        }
        static void RequireCheckpointRegionRefused(MemoryInfo info, ulong address, ulong imageBase, uint expectedRva = 0x39A7E8)
        {
            bool refused = false;
            try { RequireCheckpointRegion(info, address, imageBase, expectedRva); } catch (InvalidOperationException) { refused = true; }
            if (!refused) throw new InvalidOperationException("checkpoint read accepted an unqualified image region");
        }
        static void RequireCheckpointCleared(byte[] bytes)
        {
            foreach (byte value in bytes) if (value != 0) throw new InvalidOperationException("checkpoint read buffer was not cleared");
        }
        public static void CheckValidation()
        {
            DebugContext.CheckTrapValidation();
            LoaderTrace.CheckValidation();
            Sandbox.CheckCleanupValidation();
            CheckCheckpointReadValidation();
            byte[] before = new byte[ContextSize], after = (byte[])before.Clone();
            Put(before, Dr7, 0x400); Put(after, Dr7, 0x400);
            if (!CanRestore(true, true, true) || CanRestore(true, true, false) || CanRestore(true, false, true) ||
                CanRestore(false, true, true) || !FreeDebugState(before) || !UnchangedControlInteger(before, after) || !Pair(108, 100, 200, 200) ||
                Pair(109, 100, 200, 200) || Pair(108, 100, 201, 200) || Pair(0, UInt64.MaxValue, 200, 200))
                throw new InvalidOperationException("hardware state/return pair positive fixture failed");
            Put(after, Dr0, 100);
            if (FreeDebugState(after) || !UnchangedControlInteger(before, after))
                throw new InvalidOperationException("hardware occupied-register fixture failed");
            Put(after, 152, 1);
            if (UnchangedControlInteger(before, after)) throw new InvalidOperationException("hardware stack mutation fixture was accepted");
            after = (byte[])before.Clone(); Put(after, Dr7, 0x401);
            if (FreeDebugState(after)) throw new InvalidOperationException("hardware enabled collision fixture was accepted");
            after = (byte[])before.Clone(); Put(after, Dr6, 0x4000);
            if (FreeDebugState(after)) throw new InvalidOperationException("hardware foreign single-step cause fixture was accepted");
            foreach (ulong collision in new ulong[] { 0x800, 0x2000, 0x10000, 0xC0000000 }) {
                after = (byte[])before.Clone(); Put(after, Dr7, 0x400 | collision);
                if (FreeDebugState(after)) throw new InvalidOperationException("hardware foreign control fixture was accepted");
            }
            foreach (int offset in new [] { 68, 120, 128, 136, 152, 248 }) {
                after = (byte[])before.Clone(); after[offset] = 1;
                if (UnchangedControlInteger(before, after)) throw new InvalidOperationException("hardware non-debug context mutation was accepted");
            }
            ulong[] entries = { 100, 200 }, active = { 108, 0 };
            bool[] slots = { true, false };
            if (slots[1] || active[1] != 0) throw new InvalidOperationException("event slot was armed before attach window");
            ArmSiteWindow(entries, active, slots, false);
            if (!slots[1] || active[1] != 200) throw new InvalidOperationException("event slot did not arm inside attach window");
            bool rejected = false;
            try { ArmSiteWindow(entries, active, slots, false); } catch (InvalidOperationException) { rejected = true; }
            if (!rejected) throw new InvalidOperationException("one-shot site duplicate window activation was accepted");
            RequireSiteWindow(true, false, false);
            foreach (bool[] state in new [] { new [] { false, false, false }, new [] { true, true, false }, new [] { true, false, true } }) {
                rejected = false;
                try { RequireSiteWindow(state[0], state[1], state[2]); } catch (InvalidOperationException) { rejected = true; }
                if (!rejected) throw new InvalidOperationException("one-shot site accepted inactive, consumed or callee-return state");
            }
            ConsumeSite(active, slots);
            if (active[1] != 0 || slots[1] || active[0] != 108 || !slots[0])
                throw new InvalidOperationException("one-shot site disarm altered its enclosing return slot");
            rejected = false;
            try { ArmSiteWindow(entries, active, slots, true); } catch (InvalidOperationException) { rejected = true; }
            if (!rejected) throw new InvalidOperationException("consumed one-shot site was rearmed");
            foreach (ulong site in new ulong[] { 0, 108 }) {
                rejected = false;
                try { ArmSiteWindow(new ulong[] { 100, site }, active, slots, false); } catch (InvalidOperationException) { rejected = true; }
                if (!rejected) throw new InvalidOperationException("one-shot site accepted a missing or aliased location");
            }
            var closed = new HardwareTrace(new IntPtr(1), new IntPtr(2), 7, 11, _ => { }); closed.completed = true;
            rejected = false;
            try { closed.SingleStep(11, 0x80000004, true); } catch (InvalidOperationException) { rejected = true; }
            if (!rejected) throw new InvalidOperationException("closed window silently accepted a repeated single-step");
            closed.siteConsumed = closed.outerPaired = closed.restored = true; closed.RequireComplete(); closed.Invalidate();
            rejected = false;
            try { closed.RequireComplete(); } catch (InvalidOperationException) { rejected = true; }
            if (!rejected) throw new InvalidOperationException("completed flag hid an invalidated diagnostic window");
            uint[] values = { 0, 0x80000000, UInt32.MaxValue };
            string[] scalar = { "raw_eax=0x00000000", "raw_eax=0x80000000", "raw_eax=0xFFFFFFFF" };
            for (int index = 0; index < values.Length; index++) {
                before = new byte[ContextSize]; Put(before, 120, 0x1234567800000000UL | values[index]);
                string result = RawSiteValue(before);
                if (result != scalar[index] || result.Length != 18 || result.Contains("12345678") || result.Contains("status") || result.Contains("return"))
                    throw new InvalidOperationException("raw site scalar lost low32-only semantics");
            }
            RequireObservationComplete(true, true, true);
            foreach (bool[] state in new [] { new [] { false, true, true }, new [] { true, false, true }, new [] { true, true, false }, new [] { false, false, true } }) {
                rejected = false;
                try { RequireObservationComplete(state[0], state[1], state[2]); } catch (InvalidOperationException) { rejected = true; }
                if (!rejected) throw new InvalidOperationException("diagnostic completion accepted missing site, pair or restoration");
            }
            before = new byte[ContextSize]; after = (byte[])before.Clone();
            const ulong privateAddress = 0x123456789ABCDEF0;
            Put(after, Dr0 + 16, privateAddress); Put(after, Dr6, 0x1001); Put(after, Dr7, 0x401);
            string metadata = OwnershipMetadata(after, before, 0, 0x400);
            if (!metadata.Contains("dr2_match=False") || !metadata.Contains("dr3_match=True") ||
                !metadata.Contains("dr6_unowned_match=False") || !metadata.Contains("dr7_control_match=False") ||
                !metadata.Contains("dr6_cause_mask=0x0000000000000001") ||
                !metadata.Contains("dr6_other_bits_xor=0x0000000000001000") ||
                !metadata.Contains("dr6_expected=0x0000000000000000") || !metadata.Contains("dr6_actual=0x0000000000001001") ||
                metadata.Length > 512 || metadata.Contains(privateAddress.ToString("X16")))
                throw new InvalidOperationException("hardware ownership metadata omitted a predicate or disclosed an address");
        }
    }
}
