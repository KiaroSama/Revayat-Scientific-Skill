using System;
using System.Collections.Generic;

namespace ScientificSecurity
{
    public sealed partial class KernelImage
    {
        internal const uint CheckpointRva = 0x39A7E8;
        public static void CheckCheckpointValidation()
        {
            var section = new Section { rva = 0x394000, size = 0xA338, raw = 0x394000, rawSize = 0x2000, flags = 0xC0000040 };
            Need(CheckpointSpan(new[] { section }, 0x3ED000, 0x180000000UL) == 0x18039A7E8UL);
            foreach (Action<Section[]> change in new Action<Section[]>[] {
                s => s[0].rva++, s => s[0].raw++, s => s[0].rawSize++, s => s[0].size++,
                s => s[0].rawSize = 0x67E9, s => s[0].size = 0x67E9,
                s => s[0].flags = 0xE0000040, s => s[0].flags = 0x40000040, s => s[0].flags = 0x80000040,
                s => s[0].flags = 0xC0000080, s => s[0].rva = UInt32.MaxValue,
                s => s[0] = new Section { rva = 0x395000, size = 0xA368, raw = 0x395000, rawSize = 0x2000, flags = 0xC0000040 }
            }) {
                var bad = new[] { section }; change(bad); bool refused = false;
                try { CheckpointSpan(bad, 0x3ED000, 0x180000000UL); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            foreach (IList<Section> bad in new IList<Section>[] { new Section[0], new[] { section, section } }) {
                bool refused = false;
                try { CheckpointSpan(bad, 0x3ED000, 0x180000000UL); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            foreach (ulong imageBase in new[] { 0UL, 0x7FFFFFFFFFFFFFFFUL, UInt64.MaxValue }) {
                bool refused = false;
                try { CheckpointSpan(new[] { section }, 0x3ED000, imageBase); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            bool clipped = false, fakeIdentity = false;
            try { CheckpointSpan(new[] { section }, 0x39A7E9, 0x180000000UL); } catch (InvalidOperationException) { clipped = true; }
            try { FromStatic(ObservationFixture()).RequireCheckpointAddress(); } catch (InvalidOperationException) { fakeIdentity = true; }
            Need(clipped && fakeIdentity);
        }
        internal ulong RequireCheckpointAddress()
        {
            RequireObservationProfile();
            return CheckpointSpan(sections, imageSize, Base);
        }
        static ulong CheckpointSpan(IList<Section> scope, uint size, ulong imageBase)
        {
            const uint bytes = 2;
            Need(scope != null && imageBase != 0 && imageBase <= 0x7FFFFFFFFFFFFFFFUL - size && (ulong)CheckpointRva + bytes <= size);
            int matches = 0;
            foreach (Section section in scope) {
                if (CheckpointRva < section.rva || (ulong)CheckpointRva + bytes > (ulong)section.rva + section.size) continue;
                Need(section.rva == 0x394000 && section.size == 0xA338 && section.raw == 0x394000 &&
                    section.rawSize == 0x2000 && section.flags == 0xC0000040);
                // The fixed WORD is in the virtual zero-filled suffix, not a raw file mapping.
                Need(CheckpointRva - section.rva >= section.rawSize && (ulong)section.rva + section.size <= size);
                matches++;
            }
            Need(matches == 1); return imageBase + CheckpointRva;
        }
    }
}
