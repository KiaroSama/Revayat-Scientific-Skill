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
        const ulong CauseMask = 0xE00F, OccupiedControl = 0xFFFF20FF;
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
        readonly uint[] arguments = new uint[2];
        readonly bool[] enabled = new bool[2], returning = new bool[2];
        byte[] original;
        ulong expectedStatus;
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
            expectedStatus = U64(original, Dr6);
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
                U64(context, Dr7) != control || (U64(context, Dr6) & ~3UL) != (expectedStatus & ~3UL))
                throw new InvalidOperationException("hardware unowned control/status registers changed "
                    + OwnershipMetadata(context, original, expectedStatus, control));
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
            Put(desired, Dr6, restore ? U64(original, Dr6) : expectedStatus);
            Put(desired, Dr7, control);
            BitConverter.GetBytes(WriteFlags).CopyTo(desired, ContextFlags);
            modified = true; // A failing setter/readback may still have changed state: always attempt restoration.
            DebugContext.Write(thread, desired);
            byte[] after = ReadContext();
            if (!UnchangedControlInteger(before, after))
                throw new InvalidOperationException("hardware context write altered CONTROL/INTEGER state");
            for (int offset = Dr0; offset <= Dr7; offset += 8)
                if (U64(desired, offset) != U64(after, offset))
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
            uint rva = slot == 0 ? image.Entry : image.NtCreateEvent();
            if (rva == 0) throw new InvalidOperationException("hardware fixed system routine has no entry point");
            ulong address = image.Address(rva); RequireExecutable(address, image);
            Save(); byte[] before = ReadContext(); RequireOwned(before);
            if (address == addresses[1 - slot] && enabled[1 - slot])
                throw new InvalidOperationException("hardware entry slots alias");
            entries[slot] = address;
            // NtCreateEvent is resolved now but instrumented only inside verified PROCESS_ATTACH.
            addresses[slot] = slot == 0 ? address : 0; enabled[slot] = slot == 0;
            Apply(before, false);
            emit("phase=hardware-arm routine=" + Routine(slot) + " enabled=" + enabled[slot] + " control_integer_unchanged=True");
        }
        static string Routine(int slot) { return slot == 0 ? "KernelBaseEntry" : "NtCreateEvent"; }
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
            byte[] before = ReadContext(); RequireOwned(before);
            ulong cause = U64(before, Dr6) & CauseMask;
            int slot = cause == 1 ? 0 : cause == 2 ? 1 : -1;
            if (slot < 0 || !enabled[slot] || U64(before, 248) != addresses[slot])
                throw new InvalidOperationException("hardware exception has an unowned or ambiguous breakpoint cause");
            ulong stack = U64(before, 152);
            expectedStatus = U64(before, Dr6) & ~(1UL << slot);
            if (!returning[slot]) {
                uint argument = unchecked((uint)U64(before, 136));
                if (slot == 1 && (stacks[0] == 0 || !returning[0]))
                    throw new InvalidOperationException("hardware event creation is outside the selected KernelBase attach window");
                if (slot == 0 && argument != 1)
                    throw new InvalidOperationException("hardware KernelBase observation is not PROCESS_ATTACH");
                ulong target = ReturnAddress(stack);
                if (target == entries[slot] || (enabled[1 - slot] && target == addresses[1 - slot]))
                    throw new InvalidOperationException("hardware return breakpoint aliases an active entry/return slot");
                stacks[slot] = stack; returns[slot] = target; arguments[slot] = argument;
                addresses[slot] = target; returning[slot] = true;
                if (slot == 0) ArmEventWindow(entries, addresses, enabled);
                Apply(before, false);
                emit("phase=hardware-entry routine=" + Routine(slot) + (slot == 0 ? " reason=PROCESS_ATTACH" :
                    " desired_access=0x" + argument.ToString("X8")) + " outermost_only=True control_integer_unchanged=True");
            }
            else {
                if (!Pair(stack, stacks[slot], U64(before, 248), returns[slot]))
                    throw new InvalidOperationException("hardware outermost return stack/address pairing is inconclusive");
                uint result = unchecked((uint)U64(before, 120));
                // Observe one KernelBase PROCESS_ATTACH pair, never re-arm for PROCESS_DETACH.
                addresses[slot] = slot == 0 ? 0 : entries[slot]; returning[slot] = false;
                if (slot == 0) {
                    addresses[1] = 0; enabled[0] = enabled[1] = false;
                }
                Apply(before, false);
                emit("phase=hardware-return routine=" + Routine(slot) + (slot == 0 ? " attach_succeeded=" + (result != 0) :
                    " native_status=0x" + result.ToString("X8")) + " pair_verified=True control_integer_unchanged=True");
                if (slot == 0) Restore(); // The selected window ends with the first PROCESS_ATTACH pair.
            }
            return true;
        }
        static void ArmEventWindow(ulong[] routineEntries, ulong[] activeAddresses, bool[] activeSlots)
        {
            if (routineEntries[1] == 0 || routineEntries[1] == activeAddresses[0] || activeSlots[1])
                throw new InvalidOperationException("hardware attach window lacks a distinct inactive event entry");
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
            emit("phase=hardware-cleanup state_destroyed=True restored_claimed=False");
        }
        public static void CheckValidation()
        {
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
            foreach (ulong collision in new ulong[] { 0x2000, 0x10000, 0xC0000000 }) {
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
            ArmEventWindow(entries, active, slots);
            if (!slots[1] || active[1] != 200) throw new InvalidOperationException("event slot did not arm inside attach window");
            bool rejected = false;
            try { ArmEventWindow(entries, active, slots); } catch (InvalidOperationException) { rejected = true; }
            if (!rejected) throw new InvalidOperationException("event slot duplicate window activation was accepted");
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
