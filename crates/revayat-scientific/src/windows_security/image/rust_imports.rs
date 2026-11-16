//! Separate Rust quota-image imports. SDK and raw-dylib case spellings may form disjoint groups.
//! Historical direct_imports and its duplicate-name refusals remain unchanged.
use super::*;
use std::collections::BTreeMap;

const ALLOWED: [&str; 8] = [
    "kernel32.dll",
    "ntdll.dll",
    "advapi32.dll",
    "bcrypt.dll",
    "userenv.dll",
    "ws2_32.dll",
    "api-ms-win-core-synch-l1-2-0.dll",
    "bcryptprimitives.dll",
];

fn need(condition: bool, stage: &'static str) -> Result<()> {
    ensure!(condition, "fixed Rust quota import refused stage={stage}");
    Ok(())
}
struct Bounds<'a, 'b> {
    image: &'a PeImage<'b>,
    claimed: Vec<(u32, u32)>,
}
impl Bounds<'_, '_> {
    fn map(&self, rva: u32, length: u32) -> Result<usize> {
        self.image
            .map(rva, length)
            .map_err(|error| error.context("fixed Rust quota import refused stage=backing-span"))
    }
    fn claim(&mut self, rva: u32, length: u32) -> Result<()> {
        self.map(rva, length)?;
        need(
            length > 0
                && self.claimed.iter().all(|(start, size)| {
                    !overlaps(rva.into(), length.into(), (*start).into(), (*size).into())
                }),
            "overlapping-or-aliased-span",
        )?;
        self.claimed.push((rva, length));
        Ok(())
    }
    fn text(&self, rva: u32, library: bool) -> Result<(String, u32)> {
        let mut text = String::new();
        for index in 0..if library { 128 } else { 1024 } {
            let at = rva
                .checked_add(index)
                .ok_or_else(|| anyhow::anyhow!("fixed Rust quota import refused stage=text-rva"))?;
            let byte = self.image.bytes[self.map(at, 1)?];
            if byte == 0 {
                need(!text.is_empty(), "empty-name")?;
                return Ok((text, index + 1));
            }
            need(
                if library {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                } else {
                    (0x21..=0x7e).contains(&byte) && !matches!(byte, b'/' | b'\\' | b':')
                },
                "text-character",
            )?;
            text.push(byte as char);
        }
        anyhow::bail!("fixed Rust quota import refused stage=text-terminator")
    }
    fn thunks(
        &mut self,
        lookup: u32,
        address: u32,
        symbols: &mut BTreeSet<String>,
        total: &mut usize,
    ) -> Result<()> {
        need(
            lookup != 0 && address != 0 && lookup.is_multiple_of(8) && address.is_multiple_of(8),
            "thunk-alignment",
        )?;
        for index in 0..=4096u32 {
            let lookup_rva = lookup.checked_add(index * 8);
            let address_rva = address.checked_add(index * 8);
            need(lookup_rva.is_some() && address_rva.is_some(), "thunk-rva")?;
            let value = u64_at(self.image.bytes, self.map(lookup_rva.unwrap(), 8)?)?;
            let slot = u64_at(self.image.bytes, self.map(address_rva.unwrap(), 8)?)?;
            // This fixed held file must retain unbound on-disk IATs, never loaded addresses.
            need(value == slot, "bound-or-mismatched-iat")?;
            if value == 0 {
                need(index > 0, "empty-thunks")?;
                let length = (index + 1) * 8;
                self.claim(lookup, length)?;
                return self.claim(address, length);
            }
            need(*total < 4096, "symbol-count")?;
            *total += 1;
            let symbol = if value & (1 << 63) != 0 {
                need(value & 0x7fff_ffff_ffff_0000 == 0, "ordinal-reserved-bits")?;
                format!("ordinal:{:04X}", value as u16)
            } else {
                need(
                    value <= u32::MAX.into() && value.is_multiple_of(2),
                    "hint-rva",
                )?;
                let hint = value as u32;
                self.map(hint, 2)?;
                let name_rva = hint.checked_add(2).ok_or_else(|| {
                    anyhow::anyhow!("fixed Rust quota import refused stage=hint-rva")
                })?;
                let (name, length) = self.text(name_rva, false)?;
                self.claim(hint, length + 2)?;
                format!("name:{name}")
            };
            // Case variants may contribute disjoint imports only, never duplicate symbol authority.
            need(symbols.insert(symbol), "duplicate-symbol")?;
        }
        anyhow::bail!("fixed Rust quota import refused stage=thunk-terminator")
    }
}

impl PeImage<'_> {
    /// Validate the separate fixed Rust quota subject, including all descriptor and thunk owners.
    pub fn qualify_rust_quota(&self) -> Result<()> {
        need(
            self.entry != 0
                && u16_at(self.bytes, self.pe + 22)? & 0x2002 == 2
                && u16_at(self.bytes, self.optional + 68)? == 3
                && self.directory(14)? == (0, 0)
                && self.directory(13)? == (0, 0),
            "image-role",
        )?;
        let (rva, size) = self.directory(1)?;
        need(
            rva != 0 && (40..=2580).contains(&size) && size.is_multiple_of(20),
            "directory-shape",
        )?;
        let mut bounds = Bounds {
            image: self,
            claimed: Vec::new(),
        };
        let table = bounds.map(rva, size)?;
        bounds.claim(rva, size)?;
        let mut raw_names = BTreeSet::new();
        let mut groups: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut total = 0;
        for index in (0..size as usize).step_by(20) {
            let row = span(self.bytes, table + index, 20)?;
            if row.iter().all(|byte| *byte == 0) {
                need(
                    !raw_names.is_empty()
                        && span(self.bytes, table + index, size as usize - index)?
                            .iter()
                            .all(|byte| *byte == 0),
                    "directory-tail",
                )?;
                return need(
                    groups.keys().all(|name| ALLOWED.contains(&name.as_str())),
                    "library-profile",
                );
            }
            need(
                u32_at(row, 4)? == 0 && u32_at(row, 8)? == 0 && raw_names.len() < 128,
                "descriptor",
            )?;
            let name_rva = u32_at(row, 12)?;
            let (name, length) = bounds.text(name_rva, true)?;
            need(
                name.len() > 4
                    && name.to_ascii_lowercase().ends_with(".dll")
                    && raw_names.insert(name.clone()),
                "name-shape-or-exact-duplicate",
            )?;
            bounds.claim(name_rva, length)?;
            let symbols = groups.entry(name.to_ascii_lowercase()).or_default();
            bounds.thunks(u32_at(row, 0)?, u32_at(row, 16)?, symbols, &mut total)?;
        }
        anyhow::bail!("fixed Rust quota import refused stage=directory-terminator")
    }
}
