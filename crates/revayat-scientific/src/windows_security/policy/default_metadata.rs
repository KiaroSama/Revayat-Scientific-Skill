//! Bounded default-token diagnostics, separate from the strict grant/admission ACL parser.
use super::{dword, sid_length, valid_sid, within, word};
use anyhow::{Result, ensure};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct DefaultAclSummary {
    pub is_null: bool,
    pub ace_count: usize,
    pub canonical: bool,
    pub recognized_all: bool,
    pub inherit_only: usize,
    pub user_allow: u32,
    pub user_deny: u32,
    pub package_allow: u32,
    pub package_deny: u32,
    pub other: usize,
    pub unknown: usize,
}
impl DefaultAclSummary {
    /// Structural metadata only. No SID, pointer, ACE payload or effective-access claim.
    pub fn record(&self, acl_bytes: usize) -> String {
        if self.is_null {
            return "WINDOWS_DEFAULT_DACL status=summary default_dacl_null=True effective_access_proved=False".into();
        }
        let boolean = |value| if value { "True" } else { "False" };
        format!(
            "WINDOWS_DEFAULT_DACL status=summary default_dacl_null=False acl_bytes={acl_bytes} ace_count={} canonical_order={} recognized_all={} unknown_ace_count={} other_ace_count={} inherit_only_count={} user_allow_mask=0x{:08X} user_deny_mask=0x{:08X} package_allow_mask=0x{:08X} package_deny_mask=0x{:08X} effective_access_proved=False",
            self.ace_count,
            boolean(self.canonical),
            boolean(self.recognized_all),
            self.unknown,
            self.other,
            self.inherit_only,
            self.user_allow,
            self.user_deny,
            self.package_allow,
            self.package_deny
        )
    }
}
fn ace_layout(bytes: &[u8]) -> Result<()> {
    // RawAcl/CommonAce permits opaque tails even for noncallback allow/deny diagnostics.
    // These bytes must never pass through the strict policy::Acl grant parser.
    let (sid_offset, opaque_limit) = match bytes[0] {
        0..=3 | 9 | 10 | 13 | 14 => (8, 65535 - 8 - 68),
        4 => (12, 0),
        5..=8 | 11 | 12 | 15 | 16 => {
            let flags = dword(bytes, 8)?;
            (
                12 + usize::from(flags & 1 != 0) * 16 + usize::from(flags & 2 != 0) * 16,
                65535 - 12 - 32 - 68,
            )
        }
        _ => return Ok(()), // .NET Framework CustomAce: opaque data, not a SID or grant.
    };
    let tail = bytes
        .get(sid_offset..)
        .ok_or_else(|| anyhow::anyhow!("short diagnostic ACE layout"))?;
    let sid_bytes = sid_length(tail)?;
    ensure!(
        tail.len() - sid_bytes <= opaque_limit,
        "diagnostic ACE opaque data exceeds bound"
    );
    Ok(())
}
fn entries(bytes: &[u8]) -> Result<Vec<&[u8]>> {
    ensure!(
        (8..=65535).contains(&bytes.len())
            && bytes.len() % 4 == 0
            && matches!(bytes[0], 2 | 4)
            && bytes[1] == 0
            && usize::from(word(bytes, 2)?) == bytes.len()
            && word(bytes, 6)? == 0,
        "invalid diagnostic ACL header"
    );
    let count = usize::from(word(bytes, 4)?);
    ensure!(count <= 64, "default ACL ACE budget exceeded");
    let mut result = Vec::with_capacity(count);
    let mut offset = 8;
    for _ in 0..count {
        ensure!(offset <= bytes.len() - 4, "short diagnostic ACE header");
        let length = usize::from(word(bytes, offset + 2)?);
        ensure!(
            length >= 4 && length % 4 == 0 && length <= bytes.len() - offset,
            "invalid diagnostic ACE span"
        );
        let ace = &bytes[offset..offset + length];
        // Original native/byte prechecks validate only plain allow/deny SID spans.
        // Remaining supported layouts belong to RawAcl-equivalent semantic decoding below.
        if matches!(ace[0], 0 | 1) {
            sid_length(
                ace.get(8..)
                    .ok_or_else(|| anyhow::anyhow!("short plain diagnostic ACE"))?,
            )?;
        }
        result.push(ace);
        offset += length;
    }
    Ok(result) // Legitimate unused final ACL padding does not change its entries.
}
/// Decode only the actual returned x64 TOKEN_DEFAULT_DACL span, never spare capacity.
pub fn token_default_acl(
    bytes: &[u8],
    start: u64,
) -> std::result::Result<Option<&[u8]>, &'static str> {
    if !(8..=65536).contains(&bytes.len()) {
        return Err("default-length");
    }
    let pointer = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    if pointer == 0 {
        return Ok(None);
    }
    if !within(start, bytes.len() as u64, pointer, 8, 4) {
        return Err("default-pointer");
    }
    let offset = (pointer - start) as usize;
    let length = u16::from_le_bytes(bytes[offset + 2..offset + 4].try_into().unwrap()) as usize;
    if length < 8
        || length % 4 != 0
        || !within(start, bytes.len() as u64, pointer, length as u64, 4)
    {
        return Err("acl-length");
    }
    let acl = &bytes[offset..offset + length];
    entries(acl).map_err(|_| "ace-spans")?;
    Ok(Some(acl))
}
/// TOKEN_USER and TOKEN_APPCONTAINER_INFORMATION point inside their own returned buffer.
pub fn token_metadata_sid(
    bytes: &[u8],
    start: u64,
    user: bool,
) -> std::result::Result<&[u8], &'static str> {
    if !((if user { 16 } else { 8 })..=65536).contains(&bytes.len()) {
        return Err("identity-query");
    }
    let pointer = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    if !within(start, bytes.len() as u64, pointer, 8, 4) {
        return Err("identity-query");
    }
    let offset = (pointer - start) as usize;
    let tail = &bytes[offset..];
    let length = sid_length(tail).map_err(|_| "identity-query")?;
    Ok(&tail[..length])
}
pub fn default_acl_summary(
    bytes: Option<&[u8]>,
    user: &[u8],
    package: &[u8],
) -> Result<DefaultAclSummary> {
    valid_sid(user)?;
    valid_sid(package)?;
    let Some(bytes) = bytes else {
        return Ok(DefaultAclSummary {
            is_null: true,
            ..Default::default()
        });
    };
    let aces = entries(bytes)?;
    let mut result = DefaultAclSummary {
        ace_count: aces.len(),
        canonical: true,
        recognized_all: true,
        ..Default::default()
    };
    let mut stage = 0;
    for ace in aces {
        ace_layout(ace)?;
        if !matches!(ace[0], 0 | 1) {
            result.recognized_all = false;
            result.canonical = false;
            result.unknown += 1;
            continue;
        }
        let current = if ace[1] & 16 != 0 {
            2
        } else if ace[0] == 1 {
            0
        } else {
            1
        };
        if current < stage {
            result.canonical = false;
        }
        stage = stage.max(current);
        if ace[1] & 8 != 0 {
            result.inherit_only += 1;
            continue;
        }
        let mask = dword(ace, 4)?;
        let sid = &ace[8..8 + sid_length(&ace[8..])?];
        match (sid, ace[0]) {
            (sid, 0) if sid == user => result.user_allow |= mask,
            (sid, 1) if sid == user => result.user_deny |= mask,
            (sid, 0) if sid == package => result.package_allow |= mask,
            (sid, 1) if sid == package => result.package_deny |= mask,
            _ => result.other += 1,
        }
    }
    Ok(result)
}
