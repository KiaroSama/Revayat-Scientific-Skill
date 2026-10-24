using System;

namespace ScientificSecurity
{
    internal sealed partial class LoaderTrace
    {
        sealed class EventCleanupLedger
        {
            readonly System.Collections.Generic.HashSet<IntPtr> unresolved = new System.Collections.Generic.HashSet<IntPtr>();
            bool failed;
            internal bool Overflowed { get; private set; }
            internal int Count { get { return unresolved.Count; } }
            internal void Close(ref IntPtr handle, Action<IntPtr> close)
            {
                IntPtr value = handle;
                if (value == IntPtr.Zero || value == Native.InvalidHandle) { handle = IntPtr.Zero; return; }
                if (unresolved.Contains(value)) {
                    failed = true; handle = IntPtr.Zero;
                    throw new InvalidOperationException("uncertain event handle cannot be closed twice");
                }
                // At most 128 observation + 128 cleanup events and two original aliases.
                if (unresolved.Count >= 260) {
                    failed = Overflowed = true; // Keep the caller's handle and refuse a new event that could overwrite it.
                    throw new InvalidOperationException("callback event cleanup ownership exceeded its bound");
                }
                unresolved.Add(value); handle = IntPtr.Zero;
                try { close(value); }
                catch { failed = true; throw; }
                unresolved.Remove(value);
            }
            internal void RequireClean()
            {
                if (failed || Overflowed || unresolved.Count != 0)
                    throw new InvalidOperationException("callback event handle cleanup remains unqualified");
            }
        }
        readonly string entryPython;
        bool EntryMode { get { return entryPython != null; } }
        bool StrictEventOwnership { get { return moduleCallback || EntryMode || ResourceMode; } }
        internal string EntryMetadata()
        {
            ThreadCheck();
            if (!EntryMode || activation == null) throw new InvalidOperationException("fixed entry observer is unavailable");
            return activation.EntryMetadata();
        }
        static bool EntryMetadataEvent(uint kind)
        { return kind == 2 || kind == 4 || kind == 6 || kind == 7 || kind == 8; }
        void ObserveEntryEvent()
        {
            events++;
            FinalizeEntryEvent(activation, current.code, current.data.unloadDll.imageBase, false, () => {
                uint code = current.data.exception.record.code;
                bool first = current.data.exception.firstChance != 0;
                activation.Event(current.tid, code, first);
                if (!activation.SingleStep(current.tid, code, first, current.data.exception.record.address) &&
                    !activation.AcceptSoftware(current.tid, code, first))
                    throw new InvalidOperationException("fixed entry observation encountered an unexpected exception");
            }, () => exited = true, new Action[] { CloseCurrentFile }, ContinuePending);
        }
        internal static void FinalizeEntryEvent(ActivationBoundaryTrace observer, uint kind, IntPtr unloaded, bool cleanup,
            Action exception, Action exit, Action[] releases, Action<uint> continuation)
        {
            uint status = kind == 1 ? NotHandled : Continue;
            try { ActivationEvent(() => {
                if (cleanup) { observer.Invalidate(); if (kind == 5) exit(); return; }
                switch (kind) {
                    case 1: exception(); status = Continue; break;
                    case 5: observer.EntryExit(); exit(); break;
                    case 7: observer.Unload(unloaded); break;
                    default:
                        if (!EntryMetadataEvent(kind)) throw new InvalidOperationException("fixed entry observation received an unsupported event");
                        break;
                }
            }, () => { observer.Invalidate(); observer.Restore(); }, releases, () => continuation(status)); }
            catch { observer.Invalidate(); throw; }
        }
        internal static void CheckEntryEventValidation()
        {
            foreach (uint kind in new uint[] { 2, 4, 6, 7, 8 })
                if (!EntryMetadataEvent(kind)) throw new InvalidOperationException("fixed entry transport metadata refused");
            foreach (uint kind in new uint[] { 0, 1, 3, 5, 9, UInt32.MaxValue })
                if (EntryMetadataEvent(kind)) throw new InvalidOperationException("fixed entry transport accepted an unqualified event");
            var ledger = new EventCleanupLedger(); IntPtr handle = new IntPtr(11); int attempts = 0;
            try { ledger.Close(ref handle, _ => { attempts++; throw new InvalidOperationException("fixed close"); }); }
            catch (InvalidOperationException) { }
            bool refused = false;
            try { ledger.RequireClean(); } catch (InvalidOperationException) { refused = true; }
            if (!refused || handle != IntPtr.Zero || attempts != 1) throw new InvalidOperationException("fixed entry event close uncertainty was lost");
        }
    }
}
