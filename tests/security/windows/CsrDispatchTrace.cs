using System;
using System.Runtime.InteropServices;

namespace ScientificSecurity
{
    public sealed partial class ActivationBoundaryTrace
    {
        readonly bool csrDispatch, csrModuleDispatch;
        KernelImage dispatchNtdll;
        uint dispatchIat;
        bool dispatchRead, dispatchArmed;
        internal sealed partial class ResourceThreads
        {
            CsrDispatchPair dispatchPair;
            Action dispatchTarget;
            string dispatchCallTrap;
            internal string DispatchTraps { get { return (dispatchCallTrap == null ? "" : " call_" + dispatchCallTrap.Replace(" ", " call_")) +
                (Trap == null ? "" : " return_" + Trap.Replace(" ", " return_")); } }
            void RequireDispatchTransition(Generation value, byte[] context)
            {
                ResourceCheck(value.dispatchState != null && value.dispatchState.Length == 6, "dispatch-transition-baseline");
                for (int index = 0; index < 4; index++)
                    ResourceCheck(U64(context, 72 + index * 8) == value.dispatchState[index], "dispatch-transition-address");
                ulong control = value.dispatchState[5];
                bool exact = U64(context, 104) == value.dispatchState[4] && U64(context, 112) == control;
                bool ownedTrap = false;
                if (kind == 1 && eventThread == value.id) {
                    for (int slot = 0; slot < 2; slot++)
                        ownedTrap |= value.dispatchState[slot] != 0 && U64(context, 248) == value.dispatchState[slot] &&
                            DebugContext.OwnedTrapStatus(U64(context, 104), U64(context, 112), control, slot);
                }
                ResourceCheck(exact || ownedTrap, "dispatch-transition-control");
            }
            internal void ArmDispatch(ulong call, ulong post, Action qualifyTarget)
            {
                ResourceCheck(epoch && !cleanup && !processDead && !Captured && site == 0 && qualifyTarget != null, "dispatch-arm-state");
                dispatchPair = new CsrDispatchPair(call, post); dispatchTarget = qualifyTarget; site = call;
                foreach (var value in generations) if (!value.dead && !value.retired) Apply(value, false);
            }
            internal bool CaptureDispatch(uint id, bool first, IntPtr exception)
            {
                ResourceCheck(epoch && !cleanup && !failed && !Captured && dispatchPair != null && !processDead, "dispatch-capture-state");
                deadline(); Generation value = Live(id); byte[] context = read(value.handle);
                try {
                    int generation = generations.IndexOf(value);
                    ulong[] sites = dispatchPair.Sites(generation);
                    ulong cause = U64(context, 104) & 0xE00F;
                    int slot = cause == 1 ? 0 : cause == 2 ? 1 : -1;
                    ResourceCheck(slot >= 0 && first && value.changed && sites[slot] != 0 &&
                        unchecked((ulong)exception.ToInt64()) == sites[slot] && U64(context, 248) == sites[slot], "dispatch-trap-site");
                    DispatchOwnership(value, context, sites, slot);
                    if (!dispatchPair.Started) {
                        ResourceCheck(slot == 0, "dispatch-call-first");
                        dispatchPair.Begin(generation, context);
                        dispatchCallTrap = DebugContext.TrapQualifiers(U64(context, 104));
                        dispatchTarget(); BaseEqual = true;
                        foreach (var live in generations) if (!live.dead && !live.retired) Apply(live, false);
                    } else {
                        ResourceCheck(slot == 1, "dispatch-return-slot"); dispatchPair.End(generation, context);
                        Captured = true; CreatorCapture = id == creator; RawEax = dispatchPair.Result;
                        Trap = DebugContext.TrapQualifiers(U64(context, 104));
                        RestoreAll(); captureRestored = true;
                    }
                    return true;
                } catch { failed = true; throw; }
                finally { Array.Clear(context, 0, context.Length); }
            }
            void DispatchOwnership(Generation value, byte[] context, ulong[] sites, int slot)
            {
                for (int index = 0; index < 4; index++)
                    ResourceCheck(U64(context, 72 + index * 8) == (index < 2 ? sites[index] : U64(value.baseline, 72 + index * 8)), "dispatch-address-ownership");
                ulong control = U64(value.baseline, 112) | (sites[0] != 0 ? 1UL : 0UL) | (sites[1] != 0 ? 4UL : 0UL);
                ResourceCheck(DebugContext.OwnedTrapStatus(U64(context, 104), U64(context, 112), control, slot), "dispatch-control-ownership");
            }
            internal bool DispatchSoftware(uint id, bool first)
            {
                ResourceCheck(epoch && !cleanup && !failed && id == creator && first && !initial && !processDead, "dispatch-software-state");
                Generation value = Live(id); byte[] context = read(value.handle);
                try {
                    ulong[] sites = dispatchPair == null ? new ulong[2] : dispatchPair.Sites(generations.IndexOf(value));
                    for (int index = 0; index < 4; index++)
                        ResourceCheck(U64(context, 72 + index * 8) == (index < 2 ? sites[index] : U64(value.baseline, 72 + index * 8)), "dispatch-software-address");
                    ulong control = U64(value.baseline, 112) | (sites[0] != 0 ? 1UL : 0UL) | (sites[1] != 0 ? 4UL : 0UL);
                    ResourceCheck(dispatchPair == null ? DebugContext.RawDebugEqual(value.baseline, context) :
                        SoftwareStatus(U64(context, 104), U64(context, 112), control) ||
                        Captured && captureRestored && !failed && DebugContext.RawDebugEqual(value.baseline, context), "dispatch-software-control");
                    initial = true; return true;
                } finally { Array.Clear(context, 0, context.Length); }
            }
        }
        void LoadDispatch(IntPtr file, IntPtr imageBase)
        {
            KernelImage ntdll = KernelImage.FromCsrDispatchNtdll(file, imageBase);
            if (ntdll != null) {
                ResourceCheck(dispatchNtdll == null && !resourceThreads.Captured, "dispatch-ntdll-load");
                ulong target = ntdll.CsrDispatchExport();
                RequireExecutable(ntdll, checked((uint)(target - ntdll.Base)), 1); dispatchNtdll = ntdll;
            } else {
                KernelImage candidate = KernelImage.FromActivationSystemLoad(file, imageBase);
                if (candidate == null) return;
                ResourceCheck(kernel == null, "dispatch-kernel-load"); kernel = candidate;
                uint[] sites = kernel.CsrDispatchSites(); dispatchIat = sites[2];
                RequireExecutable(kernel, sites[0], 7); RequireExecutable(kernel, sites[1], 5);
            }
            if (!dispatchArmed && kernel != null && dispatchNtdll != null) {
                dispatchArmed = true;
                uint[] sites = kernel.CsrDispatchSites();
                resourceThreads.ArmDispatch(kernel.Address(sites[0]), kernel.Address(sites[1]), RequireDispatchTarget);
            }
        }
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr process,
            IntPtr address, byte[] bytes, UIntPtr count, out UIntPtr read);
        delegate bool DispatchRead(byte[] bytes, out UIntPtr transferred);
        static void ReadDispatchTarget(ref bool consumed, Func<bool> region, DispatchRead read, ulong expected)
        {
            ResourceCheck(!consumed && expected != 0, "dispatch-read-budget"); consumed = true;
            byte[] bytes = new byte[8];
            try {
                ResourceCheck(region(), "dispatch-iat-region"); UIntPtr transferred;
                ResourceCheck(read(bytes, out transferred) && transferred.ToUInt64() == 8 &&
                    BitConverter.ToUInt64(bytes, 0) == expected, "dispatch-iat-target");
            } finally { Array.Clear(bytes, 0, bytes.Length); }
        }
        void RequireDispatchTarget()
        {
            ResourceCheck(kernel != null && dispatchNtdll != null, "dispatch-images");
            ulong address = kernel.CsrDispatchIatAddress(dispatchIat);
            ReadDispatchTarget(ref dispatchRead, () => {
                MemoryInfo info;
                return VirtualQueryEx(process, new IntPtr((long)address), out info, new UIntPtr(48)).ToUInt64() == 48 &&
                    DispatchReadable(info, address, kernel.Base);
            }, (byte[] bytes, out UIntPtr transferred) =>
                ReadProcessMemory(process, new IntPtr((long)address), bytes, new UIntPtr(8), out transferred), dispatchNtdll.CsrDispatchExport());
        }
        static bool DispatchReadable(MemoryInfo info, ulong address, ulong allocation)
        {
            ulong start = unchecked((ulong)info.address.ToInt64()), size = info.size.ToUInt64();
            uint access = info.protect & 0xFF;
            return address >= start && address - start <= size && 8UL <= size - (address - start) &&
                info.state == 0x1000 && info.type == 0x1000000 && unchecked((ulong)info.allocation.ToInt64()) == allocation &&
                (info.protect & 0x100) == 0 && (access == 2 || access == 4 || access == 8 || access == 0x20 || access == 0x40 || access == 0x80);
        }
        internal string DispatchMetadata()
        {
            ResourceCheck(csrDispatch && resourceDestroyed, "dispatch-metadata-destruction");
            return (csrModuleDispatch ? "WINDOWS_MODULE_CSR_DISPATCH invocation_module_verified=False python_equivalence_claimed=False paired=" : "WINDOWS_CSR_DISPATCH paired=") + resourceThreads.Captured + " target_equal=" + resourceThreads.BaseEqual +
                (resourceThreads.Captured ? " request=0x1001001E length=0x000001F8 raw_return=0x" + resourceThreads.RawEax.ToString("X8") : "") +
                " live_restored=" + resourceThreads.CaptureRestored + " natural_exit=" + resourceNaturalExit +
                " state_destroyed=True observation_qualified=" + ResourceComplete() + resourceThreads.DispatchTraps +
                " server_operation_verified=False cause_claimed=False target_admitted=False production_grant=False undebugged_equivalence_claimed=False";
        }
    }
}
