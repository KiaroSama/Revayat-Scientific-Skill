//! Inert storage readback validation; these numbers never create native ownership.
use anyhow::{Result, ensure};

#[derive(Clone, Copy)]
pub(in crate::windows_security) struct Disk {
    pub number: u32,
    pub bytes: u64,
    /// MSFT_Disk: Unknown/PowerShell RAW=0, MBR=1, GPT=2.
    pub style: u16,
    pub partitions: u32,
}
#[derive(Clone, Copy)]
pub(in crate::windows_security) struct Layout {
    /// Win32 PARTITION_STYLE: MBR=0, GPT=1, RAW=2 (a different enum).
    pub style: u32,
    pub count: u32,
    pub entries: usize,
}
pub(in crate::windows_security) fn require(
    disk: Disk,
    expected: u32,
    capacity: u64,
    layout: Layout,
) -> Result<()> {
    ensure!(
        disk.number == expected
            && disk.bytes == capacity
            && disk.style == 0
            && disk.partitions == 0
            && matches!(layout.style, 0 | 2)
            && layout.count == 0
            && layout.entries == 0,
        "scratch provider RAW identity or empty physical layout differs"
    );
    Ok(())
}
/// WMI uint64 BSTRs use unsigned decimal or hexadecimal, not localized text.
pub(in crate::windows_security) fn unsigned(units: &[u16]) -> Result<u64> {
    let (digits, radix, bound) = if units.starts_with(&[u16::from(b'0'), u16::from(b'x')])
        || units.starts_with(&[u16::from(b'0'), u16::from(b'X')])
    {
        (&units[2..], 16u64, 16)
    } else {
        (units, 10u64, 20)
    };
    ensure!(
        !digits.is_empty()
            && digits.len() <= bound
            && (radix == 16 || digits.len() == 1 || digits[0] != u16::from(b'0')),
        "scratch provider capacity representation differs"
    );
    digits.iter().try_fold(0u64, |value, unit| {
        let digit = match *unit {
            48..=57 => u64::from(*unit - 48),
            65..=70 if radix == 16 => u64::from(*unit - 65 + 10),
            97..=102 if radix == 16 => u64::from(*unit - 97 + 10),
            _ => anyhow::bail!("scratch provider capacity is not an unsigned integer"),
        };
        value
            .checked_mul(radix)
            .and_then(|value| value.checked_add(digit))
            .ok_or_else(|| anyhow::anyhow!("scratch provider capacity exceeds integer bound"))
    })
}
