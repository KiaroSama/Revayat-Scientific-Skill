//! Shared returned-buffer and identity contracts for the exact registry token context.
use super::super::within;
use anyhow::{Result, ensure};

pub const LPAC_NAME: &str = "WIN://NOALLAPPPKG";

fn u16_at(bytes: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes
            .get(at..at + 2)
            .ok_or_else(|| anyhow::anyhow!("short LPAC field"))?
            .try_into()?,
    ))
}
fn u32_at(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at + 4)
            .ok_or_else(|| anyhow::anyhow!("short LPAC field"))?
            .try_into()?,
    ))
}
fn u64_at(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(at..at + 8)
            .ok_or_else(|| anyhow::anyhow!("short LPAC field"))?
            .try_into()?,
    ))
}

/// Decode the original Windows x64 named-attribute ABI inside its actual returned span.
/// The caller retains the allocation and supplies its original address, not a copied address.
pub fn require_lpac(bytes: &[u8], start: u64) -> Result<()> {
    ensure!(
        (16..=512).contains(&bytes.len()) && within(start, bytes.len() as u64, start, 16, 8),
        "LPAC attribute returned length or alignment violates fixed bounds"
    );
    ensure!(
        u16_at(bytes, 0)? == 1 && u16_at(bytes, 2)? == 0 && u32_at(bytes, 4)? == 1,
        "LPAC attribute header is not exact version-one/single-attribute"
    );
    let entry = u64_at(bytes, 8)?;
    ensure!(
        within(start, bytes.len() as u64, entry, 40, 8),
        "LPAC attribute entry violates returned-buffer bounds"
    );
    let at = (entry - start) as usize;
    let length = usize::from(u16_at(bytes, at)?);
    let maximum = usize::from(u16_at(bytes, at + 2)?);
    let name = LPAC_NAME.encode_utf16().collect::<Vec<_>>();
    ensure!(
        length == name.len() * 2 && maximum >= length && maximum.is_multiple_of(2),
        "LPAC attribute name length does not match the fixed query"
    );
    ensure!(
        u16_at(bytes, at + 16)? == 2
            && u16_at(bytes, at + 18)? == 0
            && u32_at(bytes, at + 20)? & 0x10 == 0
            && u32_at(bytes, at + 24)? == 1,
        "LPAC attribute is not an active single UInt64 value"
    );
    let text = u64_at(bytes, at + 8)?;
    let value = u64_at(bytes, at + 32)?;
    ensure!(
        within(start, bytes.len() as u64, text, maximum as u64, 2)
            && within(start, bytes.len() as u64, value, 8, 8),
        "LPAC attribute name/value violates returned-buffer bounds"
    );
    let text = (text - start) as usize;
    ensure!(
        bytes[text..text + length]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|part| u16::from_le_bytes([part[0], part[1]]))
            .eq(name),
        "LPAC attribute name differs from the fixed query"
    );
    ensure!(
        u64_at(bytes, (value - start) as usize)? == 1,
        "LPAC attribute value is not exactly enabled"
    );
    Ok(())
}

/// Restricted groups are sorted multisets: duplicate SID/attribute entries retain multiplicity.
pub struct Identity<'a> {
    pub user: &'a [u8],
    pub package: &'a [u8],
    pub restricted: &'a [(Vec<u8>, u32)],
}
pub fn require_equal(expected: Identity<'_>, actual: Identity<'_>) -> Result<()> {
    let user = expected.user == actual.user;
    let package = expected.package == actual.package;
    let restricted = expected.restricted == actual.restricted;
    ensure!(
        user && package && restricted,
        "registry control token identity changed user_equal={user} package_equal={package} restricted_multiset_equal={restricted}"
    );
    Ok(())
}

fn validation_identity(restricted: &[(Vec<u8>, u32)]) -> Identity<'_> {
    Identity {
        user: b"user",
        package: b"package",
        restricted,
    }
}

fn fixture(start: u64) -> Vec<u8> {
    let mut bytes = vec![0; 128];
    bytes[..2].copy_from_slice(&1u16.to_le_bytes());
    bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
    bytes[8..16].copy_from_slice(&(start + 16).to_le_bytes());
    let name = LPAC_NAME
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    bytes[16..18].copy_from_slice(&(name.len() as u16).to_le_bytes());
    bytes[18..20].copy_from_slice(&(name.len() as u16).to_le_bytes());
    bytes[24..32].copy_from_slice(&(start + 64).to_le_bytes());
    bytes[32..34].copy_from_slice(&2u16.to_le_bytes());
    bytes[40..44].copy_from_slice(&1u32.to_le_bytes());
    bytes[48..56].copy_from_slice(&(start + 112).to_le_bytes());
    bytes[64..64 + name.len()].copy_from_slice(&name);
    bytes[112..120].copy_from_slice(&1u64.to_le_bytes());
    bytes
}

/// LpacQuery.CheckValidation's complete 21 mutation and three returned-length cases.
pub fn check_lpac_validation() -> Result<()> {
    ensure!(
        std::mem::size_of::<usize>() == 8,
        "LPAC named-attribute validation requires the verified x64 pointer width"
    );
    let start = 0x1000;
    let valid = fixture(start);
    require_lpac(&valid, start)?;
    let mutations: [(usize, Vec<u8>); 21] = [
        (112, 0u64.to_le_bytes().to_vec()),
        (112, 2u64.to_le_bytes().to_vec()),
        (0, 2u16.to_le_bytes().to_vec()),
        (2, 1u16.to_le_bytes().to_vec()),
        (4, 0u32.to_le_bytes().to_vec()),
        (4, 2u32.to_le_bytes().to_vec()),
        (8, (start + 17).to_le_bytes().to_vec()),
        (8, (start + 496).to_le_bytes().to_vec()),
        (32, 3u16.to_le_bytes().to_vec()),
        (34, 1u16.to_le_bytes().to_vec()),
        (36, 0x10u32.to_le_bytes().to_vec()),
        (40, 0u32.to_le_bytes().to_vec()),
        (40, 2u32.to_le_bytes().to_vec()),
        (16, 1u16.to_le_bytes().to_vec()),
        (18, 1u16.to_le_bytes().to_vec()),
        (24, (start + 65).to_le_bytes().to_vec()),
        (24, (start + 120).to_le_bytes().to_vec()),
        (64, u16::from(b'X').to_le_bytes().to_vec()),
        (48, (start + 113).to_le_bytes().to_vec()),
        (48, (start + 128).to_le_bytes().to_vec()),
        (48, (start - 8).to_le_bytes().to_vec()),
    ];
    for (index, (at, value)) in mutations.iter().enumerate() {
        let mut changed = valid.clone();
        changed[*at..*at + value.len()].copy_from_slice(value);
        ensure!(
            require_lpac(&changed, start).is_err(),
            "malformed LPAC attribute accepted fixture={index}"
        );
    }
    for length in [15, 513, 119] {
        let mut changed = valid.clone();
        changed.resize(length, 0);
        ensure!(
            require_lpac(&changed, start).is_err(),
            "LPAC returned-length fixture accepted"
        );
    }
    Ok(())
}

/// RegistryContext.CheckValidation, including its reachable LpacQuery matrix.
pub fn check_validation() -> Result<()> {
    check_lpac_validation()?;
    ensure!(
        within(100, 16, 100, 16, 1)
            && within(100, 16, 108, 8, 1)
            && !within(100, 16, 99, 1, 1)
            && !within(100, 16, 108, 9, 1)
            && !within(u64::MAX - 8, 8, 1, 1, 1),
        "registry context buffer range self-check failed"
    );
    let expected = vec![(b"a".to_vec(), 1), (b"a".to_vec(), 1), (b"b".to_vec(), 2)];
    let changed = vec![(b"a".to_vec(), 1), (b"b".to_vec(), 2), (b"b".to_vec(), 2)];
    require_equal(
        validation_identity(&expected),
        validation_identity(&expected),
    )?;
    ensure!(
        require_equal(
            validation_identity(&expected),
            validation_identity(&changed)
        )
        .is_err(),
        "registry context multiset multiplicity self-check failed"
    );
    Ok(())
}
