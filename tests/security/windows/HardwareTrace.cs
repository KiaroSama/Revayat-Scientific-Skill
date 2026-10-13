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
            int slot = image.Name == "kernelbase.dll" ? 0 : 1;
            uint rva = slot == 0 ? image.Entry : image.RtlUnicodeStringToAnsiString();
            if (rva == 0) throw new InvalidOperationException("hardware fixed system routine has no entry point");
            ulong address = image.Address(rva); RequireExecutable(address, image);
            Save(); byte[] before = ReadContext(); RequireOwned(before);
            if (address == addresses[1 - slot] && enabled[1 - slot])
                throw new InvalidOperationException("hardware entry slots alias");
            entries[slot] = address;
            // The one fixed conversion export is armed only inside verified PROCESS_ATTACH.
            addresses[slot] = slot == 0 ? address : 0; enabled[slot] = slot == 0;
            Apply(before, false);
            emit("phase=hardware-arm routine=" + Routine(slot) + " enabled=" + enabled[slot] + " control_integer_unchanged=True");
        }
        static string Routine(int slot) { return slot == 0 ? "KernelBaseEntry" : "RtlUnicodeStringToAnsiString"; }
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
        void RequireExecutable(ulong address, KernelImage image)
        {
            MemoryInfo info = Region(address, 1); uint protection = info.protect & 0xFF;
            if (!image.ContainsExecutable(address) || info.type != 0x1000000 ||
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
            if (code != 0x80000004 || completed) return false;
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
            ulong stack = U64(before, 152);
            if (!returning[slot]) {
                if (slot == 1 && !InitializerApiBoundary(slot, stacks[0] != 0 && returning[0], returning[1]))
                    throw new InvalidOperationException("hardware initializer API entry is outside the selected KernelBase attach window");
                // RDX is a pointer for the selected API: only read it for the DLL reason in slot0.
                if (slot == 0 && unchecked((uint)U64(before, 136)) != 1)
                    throw new InvalidOperationException("hardware KernelBase observation is not PROCESS_ATTACH");
                ulong target = ReturnAddress(stack);
                if (target == entries[slot] || (enabled[1 - slot] && target == addresses[1 - slot]))
                    throw new InvalidOperationException("hardware return breakpoint aliases an active entry/return slot");
                stacks[slot] = stack; returns[slot] = target; entryStatuses[slot] = eventStatus;
                // Entry stays disarmed until this outermost return; recursive calls are intentionally unobserved.
                addresses[slot] = target; returning[slot] = true;
                if (slot == 0) ArmInitializerApiWindow(entries, addresses, enabled);
                Apply(before, false);
                emit("phase=hardware-entry routine=" + Routine(slot) + (slot == 0 ? " reason=PROCESS_ATTACH" : "")
                    + " " + DebugContext.TrapQualifiers(eventStatus)
                    + " outermost_only=True control_integer_unchanged=True");
            }
            else {
                // A pending outermost initializer API cannot be skipped by an initializer return/unwind.
                if (!InitializerApiBoundary(slot, stacks[0] != 0 && returning[0], returning[1]))
                    throw new InvalidOperationException("hardware initializer API/initializer return nesting is inconclusive");
                if (!Pair(stack, stacks[slot], U64(before, 248), returns[slot]))
                    throw new InvalidOperationException("hardware outermost return stack/address pairing is inconclusive");
                uint result = unchecked((uint)U64(before, 120));
                // Observe one KernelBase PROCESS_ATTACH pair, never re-arm for PROCESS_DETACH.
                CompleteReturn(slot, entries, addresses, returning, enabled);
                Apply(before, false);
                emit("phase=hardware-return routine=" + Routine(slot) + (slot == 0 ? " attach_succeeded=" + (result != 0) :
                    " " + InitializerApiReturn(result)) + " entry_raw_dr6=0x" + entryStatuses[slot].ToString("X16")
                    + " entry_rtm_bit_set=" + ((entryStatuses[slot] & 0x10000) != 0)
                    + " entry_bld_bit_set=" + ((entryStatuses[slot] & 0x800) != 0)
                    + " " + DebugContext.TrapQualifiers(eventStatus) + " pair_verified=True control_integer_unchanged=True");
                if (slot == 0) Restore(); // The selected window ends with the first PROCESS_ATTACH pair.
            }
            return true;
        }
        static void CompleteReturn(int slot, ulong[] routineEntries, ulong[] activeAddresses, bool[] pendingReturns, bool[] activeSlots)
        {
            activeAddresses[slot] = slot == 0 ? 0 : routineEntries[slot]; pendingReturns[slot] = false;
            if (slot == 0) { activeAddresses[1] = 0; activeSlots[0] = activeSlots[1] = false; }
        }
        static bool InitializerApiBoundary(int slot, bool initializerActive, bool apiReturnPending)
        { return slot == 0 ? !apiReturnPending : slot == 1 && initializerActive; }
        static string InitializerApiReturn(uint status)
        { return "native_status=0x" + status.ToString("X8"); }
        static void ArmInitializerApiWindow(ulong[] routineEntries, ulong[] activeAddresses, bool[] activeSlots)
        {
            if (routineEntries[1] == 0 || routineEntries[1] == activeAddresses[0] || activeSlots[1])
                throw new InvalidOperationException("hardware attach window lacks a distinct inactive fixed initializer API entry");
            activeAddresses[1] = routineEntries[1]; activeSlots[1] = true;
        }
        static bool CanRestore(bool changed, bool alive, bool pending)
        { return changed && alive && pending; }
        static bool Pair(ulong currentStack, ulong entryStack, ulong currentAddress, ulong returnedAddress)
        { return entryStack <= UInt64.MaxValue - 8 && currentStack == entryStack + 8 && currentAddress == returnedAddress; }
        internal void OtherThread(uint eventThread, uint kind)
        {
            if (completed) return;
            if (kind == 2 || (kind == 4 && eventThread != tid))
                throw new InvalidOperationException("hardware creator-only diagnostic encountered another thread transition");
        }
        internal void Unload(IntPtr imageBase)
        {
            if (completed) return;
            ulong address = unchecked((ulong)imageBase.ToInt64());
            foreach (KernelImage image in images.Values)
                if (image.Base == address) {
                    Restore();
                    emit("phase=hardware-unload observation=inconclusive"); return;
                }
        }
        internal void Restore()
        {
            if (!CanRestore(modified, creatorAlive, stopped)) return;
            byte[] before = ReadContext(); Apply(before, true);
            completed = true; Array.Clear(enabled, 0, enabled.Length); Array.Clear(returning, 0, returning.Length);
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
        public static void CheckValidation()
        {
            DebugContext.CheckTrapValidation();
            Sandbox.CheckCleanupValidation();
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
            ArmInitializerApiWindow(entries, active, slots);
            if (!slots[1] || active[1] != 200) throw new InvalidOperationException("event slot did not arm inside attach window");
            bool rejected = false;
            try { ArmInitializerApiWindow(entries, active, slots); } catch (InvalidOperationException) { rejected = true; }
            if (!rejected) throw new InvalidOperationException("initializer API slot duplicate window activation was accepted");
            // Old per-slot pairing alone accepted a KB return while the initializer API still awaited return.
            bool oldInitializerPair = Pair(108, 100, 200, 200);
            if (!oldInitializerPair || InitializerApiBoundary(0, true, true) || InitializerApiBoundary(1, false, true) ||
                InitializerApiBoundary(1, false, false) || !InitializerApiBoundary(1, true, false) ||
                !InitializerApiBoundary(1, true, true) || !InitializerApiBoundary(0, true, false))
                throw new InvalidOperationException("initializer API/initializer nesting boundary was accepted incorrectly");
            bool[] pendingReturns = { true, true };
            CompleteReturn(1, entries, active, pendingReturns, slots);
            if (pendingReturns[1] || !pendingReturns[0] || active[1] != entries[1] ||
                !InitializerApiBoundary(0, pendingReturns[0], pendingReturns[1]))
                throw new InvalidOperationException("completed initializer API did not permit its enclosing initializer return");
            CompleteReturn(0, entries, active, pendingReturns, slots);
            if (pendingReturns[0] || slots[0] || slots[1] || active[0] != 0 || active[1] != 0)
                throw new InvalidOperationException("completed initializer retained an active initializer API observation");
            uint[] statusValues = { 0, 0xC0000022, UInt32.MaxValue };
            string[] expectedEvidence = { "native_status=0x00000000", "native_status=0xC0000022", "native_status=0xFFFFFFFF" };
            for (int index = 0; index < statusValues.Length; index++) {
                string result = InitializerApiReturn(statusValues[index]);
                if (result != expectedEvidence[index] || result.Length != 24 ||
                    result.Contains("server_id") || result.Contains("desired_access") || result.Contains("pointer") ||
                    result.Contains("True") || result.Contains("False"))
                    throw new InvalidOperationException("initializer API evidence lost bounded status-only semantics");
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
