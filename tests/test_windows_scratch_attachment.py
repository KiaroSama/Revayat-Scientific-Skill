"""Keep attachment-policy diagnostics read-only and separate from admission."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WINDOWS = ROOT / 'tests/security/windows'


class ScratchAttachmentTest(unittest.TestCase):
    def test_owned_lifetime_and_host_only_descriptor_model(self):
        controller = (WINDOWS / 'Run-WindowsSecurity.ps1').read_text(encoding='utf-8')
        attachment = (WINDOWS / 'ScratchAttachment.cs').read_text(encoding='utf-8')
        observer = (WINDOWS / 'ScratchAccess.cs').read_text(encoding='utf-8')
        self.assertEqual(controller.count("(Join-Path $PSScriptRoot 'ScratchAttachment.cs')"), 1)
        self.assertEqual(controller.count('[ScientificSecurity.ScratchAttachment]::CheckValidation()'), 1)
        anchors = (
            'New-VHD -Path $vhd',
            '[ScientificSecurity.ScratchAttachment]::Capture($runId, $state)',
            'Mount-VHD -Path $vhd',
            '$scratchAttachment.Bind($mountPath, [uint32]$ownedDisk.DiskNumber, [uint32]$partition.PartitionNumber)',
            '$scratchAttachment.Dispose()',
            'if ($mounted -and $traceStopped -and $attachmentClosed) { Dismount-VHD',
        )
        positions = [controller.index(anchor) for anchor in anchors]
        self.assertEqual(positions, sorted(positions))
        self.assertLess(observer.index('ScratchAttachment.Observe('), observer.index('ImpersonateLoggedOnUser(duplicate)'))
        self.assertLess(observer.index('Revert();'), observer.index('foreach (string line in observations)'))
        self.assertIn('new SecurityIdentifier(package), () => Deadline(clock)', observer)
        self.assertIn('Native.DeviceIoControl(handle, 0x2D1080, IntPtr.Zero, 0, memory, 12', attachment)
        self.assertIn('Need(returned == 12)', attachment)
        self.assertIn('Number(bytes, disk, partition)', attachment)
        self.assertIn('0x20000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero', attachment)
        self.assertIn('0x20080, 3, IntPtr.Zero, 3, 0x200000, IntPtr.Zero', attachment)
        for forbidden in ('AttachVirtualDisk(', 'SetSecurityInfo', 'NtSetSecurityObject',
                          'AdjustTokenPrivileges', 'SetTokenInformation', 'NtOpenFile(', 'ReadFile(', 'WriteFile('):
            self.assertNotIn(forbidden, attachment)
        self.assertIn('attachment_input_verified=False checked_device_verified=False cause_claimed=False', attachment)
        self.assertIn('known=False equal=False', attachment)


class ScratchVolumePolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = (WINDOWS / 'ScratchVolumePolicy.cs').read_text(encoding='utf-8')
        cls.controller = (WINDOWS / 'Run-WindowsSecurity.ps1').read_text(encoding='utf-8')
        cls.sandbox = (WINDOWS / 'Sandbox.cs').read_text(encoding='utf-8')
        cls.observer = (WINDOWS / 'ScratchAccess.cs').read_text(encoding='utf-8')

    def test_suspended_lifetime_and_managed_discovery(self):
        self.assertEqual(self.controller.count("(Join-Path $PSScriptRoot 'ScratchVolumePolicy.cs')"), 2)
        self.assertEqual(self.controller.count('[ScientificSecurity.ScratchVolumePolicy]::CheckValidation()'), 1)
        anchors = ('ScratchVolumePolicy.EnterRun();', 'ScratchVolumePolicy.SelectSuspended(job, process)',
                   'PrepareContained(process', 'ScratchVolumePolicy.RequireNoLease();',
                   'Native.ResumeThread(process.thread)', 'FinishRun(ref process',
                   'ScratchVolumePolicy.EndRun(cleanupQualified)')
        positions = [self.sandbox.index(anchor) for anchor in anchors]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('accounting.activeProcesses == 1 && accounting.totalProcesses == 1', self.policy)
        self.assertIn('Native.WaitForSingleObject(selectedProcess, 0) == 0x102', self.policy)
        self.assertIn('uncertain |= !clean || active != null', self.policy)
        self.assertNotIn('ResumeThread', self.policy)

    def test_receipt_precedes_possible_mutation_and_recovery_precedes_detach(self):
        install = self.policy.split('internal void Install()', 1)[1].split('static void Restore(', 1)[0]
        anchors = ('RequireHost();', 'RequireSuspended();', 'Bind();', 'Persist();',
                   'Need(Same(Read(volume), before))', 'possible = true;',
                   'Write(volume, after)', 'Need(Same(Read(volume), after))')
        positions = [install.index(anchor) for anchor in anchors]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('NtSetSecurityObject(handle, 4, bytes)', self.policy)
        self.assertIn('new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x100020, sid, false, null)', self.policy)
        self.assertIn('Need(Same(actual, after)); write(before); Need(Same(read(), before))', self.policy)
        self.assertIn('D:P(D;;0x000C0000;;;OW)(D;;FA;;;', self.policy)
        self.assertIn('cleanupQualified = clean;', self.policy)
        self.assertIn('return outerReaped || clean && activeRuns == 0 && !chosen;', self.policy)
        self.assertIn('RecoveryAvailable(outerOwnerReaped, cleanupQualified, runs, selected)', self.policy)
        self.assertIn('Need(!RecoveryAvailable(false, false, 0, false))', self.policy)
        self.assertIn('file.Flush(true)', self.policy)
        self.assertIn('Need(Equal(ReadReceipt(file), receiptBytes))', self.policy)
        outer = self.controller.split('if ($CleanupOnly) {', 1)[1].split('$null = New-Item', 1)[0]
        self.assertLess(outer.index('[ScientificSecurity.ScratchVolumePolicy]::Recover('),
                        outer.index('Dismount-VHD -Path $ownedVhd'))
        final = self.controller.split('$attachmentClosed = $true', 1)[1]
        self.assertLess(final.index('[ScientificSecurity.ScratchVolumePolicy]::Recover('),
                        final.index('$scratchAttachment.Dispose()'))
        self.assertLess(final.index('$scratchAttachment.Dispose()'), final.index('Dismount-VHD -Path $vhd'))
        self.assertIn('$traceStopped -and $attachmentClosed', final)
        for forbidden in ('AttachVirtualDisk(', 'AdjustTokenPrivileges', 'SetTokenInformation',
                          'ReadFile(', 'WriteFile(', 'Process.Start', 'CreateProcess'):
            self.assertNotIn(forbidden, self.policy)

    def test_phase_handles_close_and_frames_follow_restore(self):
        probe = self.observer.split('static int[] PolicyProbe(', 1)[1].split('static void Deadline(', 1)[0]
        self.assertEqual(probe.count('new NativeRequest'), 2)
        self.assertIn('path = nativeRoot, role = "lpac", name = "device"', probe)
        self.assertIn('path = nativeRoot + "temp"', probe)
        self.assertEqual(probe.count('expected.Same(Privileges(effective))'), 2)
        self.assertLess(probe.index('Revert();'), probe.index('request.Release('))
        self.assertLess(probe.index('request.Release('), probe.index('return ScratchVolumeAccess.Combine('))
        compare = self.policy.split('internal List<string> Compare(', 1)[1].split('void Close()', 1)[0]
        self.assertLess(compare.index('Finish(primary, Dispose)'), compare.index('WINDOWS_SCRATCH_POLICY'))
        self.assertIn('descriptor_restored=True handles_closed=True cause_claimed=False admission=False', compare)
        self.assertIn('finally { Attempt(failures, restore); }', self.policy)
        self.assertIn('results[2].SequenceEqual(results[0])', self.policy)
        fixtures = self.policy.split('public static void CheckValidation()', 1)[1]
        for seam in ('Trial(original, sid)', 'Trial(trial, sid)', 'Restore(original, trial',
                     'Differential(() =>', 'decoded.Decode(', 'receipt + "extra"',
                     'Object.ReferenceEquals(error.InnerExceptions[0], operation)'):
            self.assertIn(seam, fixtures)


class ScratchVolumeAccessTest(unittest.TestCase):
    def test_fixed_handle_only_differential_and_discovery(self):
        source = (WINDOWS / 'ScratchVolumeAccess.cs').read_text(encoding='utf-8')
        observer = (WINDOWS / 'ScratchAccess.cs').read_text(encoding='utf-8')
        policy = (WINDOWS / 'ScratchVolumePolicy.cs').read_text(encoding='utf-8')
        controller = (WINDOWS / 'Run-WindowsSecurity.ps1').read_text(encoding='utf-8')
        self.assertEqual(controller.count("(Join-Path $PSScriptRoot 'ScratchVolumeAccess.cs')"), 1)
        self.assertEqual(controller.count('[ScientificSecurity.ScratchVolumeAccess]::CheckValidation()'), 1)
        self.assertIn('0, 0x20, 0x100000, 0x100020, 1, 2, 0x20000, 0x40000, 0x80000', source)
        self.assertIn('requested = mask, options = 0x200000', source)
        self.assertIn('ScratchVolumeAccess.Host(', observer)
        self.assertIn('ScratchVolumeAccess.Open(', observer)
        self.assertIn('ScratchVolumeAccess.Qualify(', observer)
        self.assertIn('ScratchVolumeAccess.Frames', observer)
        self.assertIn('frames.AddRange(extra(phases[i], results[i]))', policy)
        self.assertIn('NtQueryObject(', source)
        self.assertIn('kind, memory, 1024, out returned', source)
        self.assertIn('authority_qualified=False admission=False', source)
        for forbidden in ('DeviceIoControl(', 'ReadFile(', 'WriteFile(', 'NtSetSecurityObject',
                          'AdjustTokenPrivileges', 'CreateProcess', 'ResumeThread'):
            self.assertNotIn(forbidden, source)


if __name__ == '__main__':
    unittest.main()
