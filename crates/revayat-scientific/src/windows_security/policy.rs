//! Bounded binary policy contracts. These parsers do not prove effective kernel access.
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

#[path = "policy/default_control.rs"]
pub mod default_control;

pub const REGISTRY_READ: u32 = 0x20019;
pub const REGISTRY_DENY: u32 = 2 | 4 | 0x10000 | 0x40000 | 0x80000;
pub const SCRATCH_MASKS: [u32; 9] = [0, 0x20, 0x100000, 0x100020, 1, 2, 0x20000, 0x40000, 0x80000];

fn word(bytes: &[u8], offset: usize) -> Result<u16> {
    ensure!(
        offset <= bytes.len() && 2 <= bytes.len() - offset,
        "short policy word"
    );
    Ok(u16::from_le_bytes(bytes[offset..offset + 2].try_into()?))
}
fn dword(bytes: &[u8], offset: usize) -> Result<u32> {
    ensure!(
        offset <= bytes.len() && 4 <= bytes.len() - offset,
        "short policy DWORD"
    );
    Ok(u32::from_le_bytes(bytes[offset..offset + 4].try_into()?))
}
pub fn within(start: u64, length: u64, address: u64, bytes: u64, alignment: u64) -> bool {
    alignment != 0
        && address.is_multiple_of(alignment)
        && address >= start
        && address - start <= length
        && bytes <= length - (address - start)
}
fn sid_length(bytes: &[u8]) -> Result<usize> {
    ensure!(
        bytes.len() >= 8 && bytes[0] == 1 && bytes[1] <= 15,
        "invalid bounded SID"
    );
    let length = 8 + usize::from(bytes[1]) * 4;
    ensure!(length <= bytes.len(), "truncated bounded SID");
    Ok(length)
}
fn valid_sid(bytes: &[u8]) -> Result<()> {
    ensure!(sid_length(bytes)? == bytes.len(), "noncanonical SID length");
    Ok(())
}
fn package_text(bytes: &[u8]) -> Result<String> {
    valid_sid(bytes)?;
    ensure!(
        bytes.len() == 40
            && bytes[1] == 8
            && bytes[2..8] == [0, 0, 0, 0, 0, 15]
            && dword(bytes, 8)? == 2,
        "expected one concrete package SID"
    );
    let mut value = String::from("S-1-15-2");
    for offset in (12..40).step_by(4) {
        use std::fmt::Write;
        write!(&mut value, "-{}", dword(bytes, offset)?)?;
    }
    super::package_sid(&value)?;
    Ok(value)
}

#[derive(Debug)]
pub struct Ace<'a> {
    pub bytes: &'a [u8],
    pub kind: u8,
    pub flags: u8,
}
impl Ace<'_> {
    pub fn mask(&self) -> Result<u32> {
        dword(self.bytes, 4)
    }
    pub fn sid(&self) -> Result<&[u8]> {
        ensure!(matches!(self.kind, 0 | 1 | 17), "ACE is not unconditional");
        let bytes = self
            .bytes
            .get(8..)
            .ok_or_else(|| anyhow::anyhow!("short ACE SID"))?;
        valid_sid(bytes)?;
        Ok(bytes)
    }
}
#[derive(Debug)]
pub struct Acl<'a> {
    pub revision: u8,
    pub aces: Vec<Ace<'a>>,
}
impl<'a> Acl<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        ensure!(
            (8..=65535).contains(&bytes.len())
                && bytes.len().is_multiple_of(4)
                && matches!(bytes[0], 2 | 4)
                && bytes[1] == 0
                && usize::from(word(bytes, 2)?) == bytes.len()
                && word(bytes, 6)? == 0,
            "invalid ACL header"
        );
        let count = usize::from(word(bytes, 4)?);
        ensure!(count <= 256, "ACL ACE budget exceeded");
        let mut aces = Vec::with_capacity(count);
        let mut offset = 8;
        for _ in 0..count {
            ensure!(
                offset <= bytes.len().saturating_sub(4),
                "truncated ACE header"
            );
            let length = usize::from(word(bytes, offset + 2)?);
            ensure!(
                length >= 4 && length % 4 == 0 && length <= bytes.len() - offset,
                "invalid ACE span"
            );
            let ace = Ace {
                bytes: &bytes[offset..offset + length],
                kind: bytes[offset],
                flags: bytes[offset + 1],
            };
            if matches!(ace.kind, 0 | 1 | 17) {
                ensure!(length >= 16, "short unconditional ACE");
                ace.sid()?;
            }
            aces.push(ace);
            offset += length;
        }
        Ok(Self {
            revision: bytes[0],
            aces,
        }) // AclSize may include unused final padding.
    }
    fn canonical(&self) -> bool {
        let mut stage = 0;
        for ace in &self.aces {
            if !matches!(ace.kind, 0 | 1) {
                return false;
            }
            let next = if ace.flags & 16 != 0 {
                2
            } else if ace.kind == 1 {
                0
            } else {
                1
            };
            if next < stage {
                return false;
            }
            stage = next;
        }
        true
    }
}

#[path = "policy/default_metadata.rs"]
mod default_metadata;
pub use default_metadata::{
    DefaultAclSummary, default_acl_summary, token_default_acl, token_metadata_sid,
};
fn plain_child(bytes: &[u8]) -> Result<Acl<'_>> {
    let acl = Acl::parse(bytes)?;
    ensure!(
        acl.aces.len() <= 64 && acl.canonical(),
        "child ACL is not bounded and canonical"
    );
    for ace in &acl.aces {
        ensure!(
            matches!(ace.kind, 0 | 1) && ace.flags == 0 && ace.mask()? & !0xb01f0003 == 0,
            "unsupported child ACL ACE header or mask"
        );
    }
    Ok(acl)
}
fn encode_acl(revision: u8, entries: &[Vec<u8>]) -> Result<Vec<u8>> {
    let size = 8 + entries.iter().map(Vec::len).sum::<usize>();
    ensure!(
        size <= 65532 && entries.len() <= 256,
        "encoded ACL exceeds bound"
    );
    let mut result = vec![revision, 0];
    result.extend((size as u16).to_le_bytes());
    result.extend((entries.len() as u16).to_le_bytes());
    result.extend([0, 0]);
    for entry in entries {
        result.extend(entry);
    }
    Ok(result)
}
fn allow_ace(sid: &[u8], mask: u32) -> Result<Vec<u8>> {
    valid_sid(sid)?;
    let mut ace = vec![0, 0];
    ace.extend(((8 + sid.len()) as u16).to_le_bytes());
    ace.extend(mask.to_le_bytes());
    ace.extend(sid);
    Ok(ace)
}
pub fn child_with_user(bytes: &[u8], user: &[u8]) -> Result<Vec<u8>> {
    let acl = plain_child(bytes)?;
    ensure!(acl.aces.len() < 64, "child ACL insertion exceeds bound");
    let mut entries = Vec::new();
    let position = acl.aces.iter().take_while(|ace| ace.kind == 1).count();
    for (index, ace) in acl.aces.iter().enumerate() {
        ensure!(ace.sid()? != user, "child ACL user already present");
        if index == position {
            entries.push(allow_ace(user, 0x10000000)?);
        }
        entries.push(ace.bytes.to_vec());
    }
    if position == acl.aces.len() {
        entries.push(allow_ace(user, 0x10000000)?);
    }
    encode_acl(acl.revision, &entries)
}
pub fn child_event_policy(bytes: &[u8]) -> Result<Vec<u8>> {
    let acl = plain_child(bytes)?;
    let entries = acl
        .aces
        .iter()
        .map(|ace| {
            let original = ace.mask()?;
            let mut mask = original & !0xb0000000;
            for (generic, concrete) in [
                (0x10000000, 0x1f0003),
                (0x80000000, 0x20001),
                (0x20000000, 0x120000),
            ] {
                if original & generic != 0 {
                    mask |= concrete;
                }
            }
            let mut value = ace.bytes.to_vec();
            value[4..8].copy_from_slice(&mask.to_le_bytes());
            Ok(value)
        })
        .collect::<Result<Vec<_>>>()?;
    encode_acl(acl.revision, &entries)
}
pub fn child_acl_equal(first: &[u8], second: &[u8]) -> Result<bool> {
    let (first, second) = (plain_child(first)?, plain_child(second)?);
    Ok(first.revision == second.revision
        && first.aces.len() == second.aces.len()
        && first
            .aces
            .iter()
            .zip(&second.aces)
            .all(|(a, b)| a.bytes == b.bytes))
}

pub struct Descriptor<'a> {
    pub control: u16,
    pub rm_control: u8,
    pub owner: Option<&'a [u8]>,
    pub group: Option<&'a [u8]>,
    pub sacl: Option<&'a [u8]>,
    pub dacl: Option<&'a [u8]>,
}
impl<'a> Descriptor<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        ensure!(
            (20..=65536).contains(&bytes.len()) && bytes[0] == 1,
            "invalid relative descriptor header"
        );
        let control = word(bytes, 2)?;
        ensure!(control & 0x8000 != 0, "descriptor is not self-relative");
        let mut ranges = Vec::new();
        let mut component = |field: usize, acl: bool| -> Result<Option<&'a [u8]>> {
            let offset = dword(bytes, field)? as usize;
            if offset == 0 {
                return Ok(None);
            }
            ensure!(
                offset >= 20 && offset.is_multiple_of(4) && offset < bytes.len(),
                "invalid descriptor component offset"
            );
            let tail = &bytes[offset..];
            let length = if acl {
                usize::from(word(tail, 2)?)
            } else {
                sid_length(tail)?
            };
            ensure!(length <= tail.len(), "descriptor component exceeds input");
            let value = &tail[..length];
            if acl {
                Acl::parse(value)?;
            }
            for (start, end) in &ranges {
                ensure!(
                    offset >= *end
                        || offset + length <= *start
                        || (offset == *start && offset + length == *end),
                    "descriptor components overlap"
                );
            }
            ranges.push((offset, offset + length));
            Ok(Some(value))
        };
        let owner = component(4, false)?;
        let group = component(8, false)?;
        let sacl = component(12, true)?;
        let dacl = component(16, true)?;
        Ok(Self {
            control,
            rm_control: bytes[1],
            owner,
            group,
            sacl,
            dacl,
        })
    }
    fn lease(&self) -> Result<()> {
        ensure!(
            self.control & 4 != 0
                && self.owner.is_some()
                && self.group.is_some()
                && self.dacl.is_some(),
            "lease descriptor identity or DACL missing"
        );
        let dacl = Acl::parse(self.dacl.unwrap())?;
        ensure!(
            dacl.aces.len() < 256
                && dacl.canonical()
                && dacl.aces.iter().all(|ace| matches!(ace.kind, 0 | 1)),
            "lease DACL is unsupported"
        );
        if let Some(sacl) = self.sacl {
            let acl = Acl::parse(sacl)?;
            ensure!(
                acl.aces.len() <= 16 && acl.aces.iter().all(|ace| ace.kind == 17 && ace.flags == 0),
                "lease integrity labels are unsupported"
            );
        }
        Ok(())
    }
}
pub fn access_matches(first: &[u8], second: &[u8]) -> Result<bool> {
    let (a, b) = (Descriptor::parse(first)?, Descriptor::parse(second)?);
    Ok(a.control & !0x400 == b.control & !0x400
        && a.control & 0x1000 != 0
        && b.control & 0x1000 != 0
        && a.dacl.is_some()
        && a.dacl == b.dacl)
}
/// DACL persistence must leave owner, group, MIC/SACL and non-DACL control untouched.
/// This is RegistrySeal.RequirePreserved, not Profile's access-only comparison.
pub fn require_registry_preserved(before: &[u8], after: &[u8]) -> Result<()> {
    let (before, after) = (Descriptor::parse(before)?, Descriptor::parse(after)?);
    ensure!(
        before.owner.is_some()
            && before.group.is_some()
            && after.owner.is_some()
            && after.group.is_some()
            && before.owner == after.owner
            && before.group == after.group
            && before.control & !0x150c == after.control & !0x150c
            && before.sacl == after.sacl,
        "registry DACL persistence changed owner/group/integrity or unrelated control"
    );
    Ok(())
}
pub fn descriptor_equal(first: &[u8], second: &[u8]) -> Result<bool> {
    let (a, b) = (Descriptor::parse(first)?, Descriptor::parse(second)?);
    a.lease()?;
    b.lease()?;
    Ok(a.control == b.control
        && a.rm_control == b.rm_control
        && a.owner == b.owner
        && a.group == b.group
        && a.sacl == b.sacl
        && a.dacl == b.dacl)
}
pub fn validate_registry_seal(bytes: &[u8]) -> Result<()> {
    let sd = Descriptor::parse(bytes)?;
    ensure!(
        sd.control & 0x9004 == 0x9004
            && sd.control & 0x10 == 0
            && sd.owner.is_none()
            && sd.group.is_none()
            && sd.sacl.is_none(),
        "registry seal must be protected access-only"
    );
    let acl = Acl::parse(
        sd.dacl
            .ok_or_else(|| anyhow::anyhow!("registry seal DACL missing"))?,
    )?;
    ensure!(
        acl.aces.len() == 6 && acl.canonical(),
        "registry seal requires six ordered ACEs"
    );
    for ace in acl.aces {
        ensure!(
            matches!(ace.kind, 0 | 1) && ace.flags == 2 && ace.mask()? != 0,
            "unsupported registry seal ACE"
        );
    }
    Ok(())
}
pub fn descriptor_trial(bytes: &[u8], package: &[u8], mask: u32) -> Result<Vec<u8>> {
    package_text(package)?;
    ensure!(
        matches!(mask, REGISTRY_READ | 0x1301bf),
        "unsupported fixed trial mask"
    );
    let sd = Descriptor::parse(bytes)?;
    sd.lease()?;
    let acl = Acl::parse(sd.dacl.unwrap())?;
    let mut entries = Vec::new();
    let mut inserted = false;
    for ace in &acl.aces {
        ensure!(
            ace.sid()? != package,
            "package already present in trial policy"
        );
        if !inserted && ace.flags & 16 != 0 {
            entries.push(allow_ace(package, mask)?);
            inserted = true;
        }
        entries.push(ace.bytes.to_vec());
    }
    if !inserted {
        entries.push(allow_ace(package, mask)?);
    }
    let dacl = encode_acl(acl.revision, &entries)?;
    let mut result = vec![1, sd.rm_control];
    result.extend(sd.control.to_le_bytes());
    result.resize(20, 0);
    for (field, component) in [
        (4, sd.owner),
        (8, sd.group),
        (12, sd.sacl),
        (16, Some(dacl.as_slice())),
    ] {
        if let Some(value) = component {
            let offset = result.len() as u32;
            result[field..field + 4].copy_from_slice(&offset.to_le_bytes());
            result.extend(value);
        }
    }
    Descriptor::parse(&result)?.lease()?;
    Ok(result)
}
#[derive(Debug, PartialEq, Eq)]
pub enum RestoreDecision {
    AlreadyOriginal,
    RestoreOriginal,
}
pub fn restore_decision(
    before: &[u8],
    after: &[u8],
    current: &[u8],
    cleanup: bool,
) -> Result<RestoreDecision> {
    if descriptor_equal(before, current)? {
        return Ok(RestoreDecision::AlreadyOriginal);
    }
    ensure!(
        cleanup && descriptor_equal(after, current)?,
        "foreign policy or unqualified cleanup forbids restore"
    );
    Ok(RestoreDecision::RestoreOriginal)
}
fn identifier(text: &str) -> bool {
    text.len() == 32
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn hash(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}
pub fn encode_registry_receipt(
    run: &str,
    package: &[u8],
    nonce: &str,
    before: &[u8],
    after: &[u8],
) -> Result<String> {
    ensure!(
        identifier(run) && identifier(nonce),
        "invalid lease identity"
    );
    ensure!(
        descriptor_equal(&descriptor_trial(before, package, REGISTRY_READ)?, after)?,
        "trial policy differs"
    );
    let body = format!(
        "registry-policy-v1\n{run}\n{}\n{nonce}\nsxs-policy\n{}\n{}\n",
        package_text(package)?,
        STANDARD.encode(before),
        STANDARD.encode(after)
    );
    let text = format!("{body}{}\n", hash(&body));
    ensure!(text.len() <= 196608, "lease receipt exceeds bound");
    Ok(text)
}
pub fn decode_registry_receipt(
    text: &str,
    run: &str,
    package: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    ensure!(text.len() <= 196608, "lease receipt exceeds bound");
    let fields = text.split('\n').collect::<Vec<_>>();
    ensure!(
        fields.len() == 9
            && fields[0] == "registry-policy-v1"
            && fields[1] == run
            && fields[2] == package_text(package)?
            && identifier(run)
            && identifier(fields[3])
            && fields[4] == "sxs-policy"
            && fields[8].is_empty(),
        "lease receipt binding differs"
    );
    let body = format!("{}\n", fields[..7].join("\n"));
    ensure!(fields[7] == hash(&body), "lease receipt digest differs");
    let before = STANDARD.decode(fields[5])?;
    let after = STANDARD.decode(fields[6])?;
    ensure!(
        STANDARD.encode(&before) == fields[5]
            && STANDARD.encode(&after) == fields[6]
            && descriptor_equal(&descriptor_trial(&before, package, REGISTRY_READ)?, &after)?,
        "noncanonical lease policy"
    );
    Ok((before, after))
}
pub fn require_supported_results(result: &[i32]) -> Result<()> {
    let count = SCRATCH_MASKS.len();
    ensure!(
        result.len() == 2 + count * 5 && result[..2] == [0, 0],
        "unsupported scratch result shape"
    );
    for (index, mask) in SCRATCH_MASKS.iter().enumerate() {
        let readable = matches!(*mask, 0x100000 | 0x20000);
        ensure!(
            result[2 + index] == (if readable { 0 } else { 0xc0000022u32 as i32 })
                && result[2 + count + index] == (if readable { *mask as i32 } else { 0 }),
            "scratch volume authority differs"
        );
    }
    Ok(())
}
pub fn supported_privileges(entries: &[(u64, u32)]) -> Result<()> {
    ensure!(
        entries.len() == 1 && entries[0].0 == 23 && matches!(entries[0].1, 2 | 3),
        "unsupported scratch privileges"
    );
    Ok(())
}
pub fn can_restore(supported: bool, running: bool, deferred: bool, clean: bool) -> bool {
    !deferred && (!supported || !running && clean)
}
pub fn recovery_available(
    outer_reaped: bool,
    clean: bool,
    active_runs: usize,
    chosen: bool,
) -> bool {
    outer_reaped || clean && active_runs == 0 && !chosen
}
pub fn require_quota(expected: &[u8], actual: &[u8], threshold: i64, limit: i64) -> Result<()> {
    valid_sid(expected)?;
    valid_sid(actual)?;
    ensure!(
        expected == actual && threshold == 16777216 && limit == 16777216,
        "quota identity or bounds differ"
    );
    Ok(())
}
