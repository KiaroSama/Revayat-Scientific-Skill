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
        self.assertLess(observer.index('RevertToSelf();'), observer.index('foreach (string line in observations)'))
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


if __name__ == '__main__':
    unittest.main()
