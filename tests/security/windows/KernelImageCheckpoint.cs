using System;
using System.Collections.Generic;

namespace ScientificSecurity
{
    public sealed partial class KernelImage
    {
        public static void CheckCheckpointValidation()
        {
            foreach (var profile in new[] { originalObservation, servicedObservation }) {
                Section section = profile.DataSection;
                ulong expected = profile == originalObservation ? 0x18039B8F8UL : 0x18039A7E8UL;
                Need(CheckpointSpan(new[] { section }, profile.ImageSize, 0x180000000UL, profile) == expected);
                var other = profile == originalObservation ? servicedObservation : originalObservation;
                foreach (Action<Section[]> change in new Action<Section[]>[] {
                    s => s[0].rva++, s => s[0].raw++, s => s[0].rawSize++, s => s[0].size++,
                    s => s[0].rawSize = profile.Checkpoint - section.rva + 1, s => s[0].size = profile.Checkpoint - section.rva + 1,
                    s => s[0].flags = 0xE0000040, s => s[0].flags = 0x40000040, s => s[0].flags = 0x80000040,
                    s => s[0].flags = 0xC0000080, s => s[0].rva = UInt32.MaxValue, s => s[0] = other.DataSection
                }) {
                    var bad = new[] { section }; change(bad); bool refused = false;
                    try { CheckpointSpan(bad, profile.ImageSize, 0x180000000UL, profile); } catch (InvalidOperationException) { refused = true; }
                    Need(refused);
                }
                foreach (IList<Section> bad in new IList<Section>[] { new Section[0], new[] { section, section } }) {
                    bool refused = false;
                    try { CheckpointSpan(bad, profile.ImageSize, 0x180000000UL, profile); } catch (InvalidOperationException) { refused = true; }
                    Need(refused);
                }
                foreach (ulong imageBase in new[] { 0UL, 0x7FFFFFFFFFFFFFFFUL, UInt64.MaxValue }) {
                    bool refused = false;
                    try { CheckpointSpan(new[] { section }, profile.ImageSize, imageBase, profile); } catch (InvalidOperationException) { refused = true; }
                    Need(refused);
                }
                bool clipped = false, fakeIdentity = false;
                try { CheckpointSpan(new[] { section }, profile.Checkpoint + 1, 0x180000000UL, profile); } catch (InvalidOperationException) { clipped = true; }
                try { FromStatic(ObservationFixture(profile)).RequireCheckpointAddress(); } catch (InvalidOperationException) { fakeIdentity = true; }
                Need(clipped && fakeIdentity);
            }
        }
        internal ulong RequireCheckpointAddress()
        {
            var profile = SelectObservation(KernelBaseIdentity());
            ObservationBytes(profile);
            return CheckpointSpan(sections, imageSize, Base, profile);
        }
        static ulong CheckpointSpan(IList<Section> scope, uint size, ulong imageBase, ObservationProfile profile)
        {
            const uint bytes = 2; uint rva = profile.Checkpoint; Section expected = profile.DataSection;
            Need(scope != null && imageBase != 0 && imageBase <= 0x7FFFFFFFFFFFFFFFUL - size && (ulong)rva + bytes <= size);
            int matches = 0;
            foreach (Section section in scope) {
                if (rva < section.rva || (ulong)rva + bytes > (ulong)section.rva + section.size) continue;
                Need(section.rva == expected.rva && section.size == expected.size && section.raw == expected.raw &&
                    section.rawSize == expected.rawSize && section.flags == expected.flags);
                // Each exact profile owns its WORD in the virtual zero-filled suffix, not a raw file mapping.
                Need(rva - section.rva >= section.rawSize && (ulong)section.rva + section.size <= size);
                matches++;
            }
            Need(matches == 1); return imageBase + rva;
        }
    }
}
