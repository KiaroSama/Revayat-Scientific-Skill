//! One bounded direct-import parser, with source-fixed diagnostics for the
//! fixed registry fixture. No imported path, symbol or private payload is reported.
use super::*;
fn check(condition: bool, stage: &str, authority: bool) -> Result<()> {
    if authority {
        ensure!(
            condition,
            "fixed Rust registry authority import refused stage={stage}"
        );
    } else {
        ensure!(condition, "bounded PE import refused stage={stage}");
    }
    Ok(())
}
pub fn qualify_registry_authority(bytes: &[u8]) -> Result<()> {
    let image = PeImage::parse(bytes, 1).map_err(|error| {
        error
            .context("fixed Rust registry authority header refused stage=pe-header")
            .context("fixed Rust registry authority PE refused stage=headers")
    })?;
    image.registry_authority_checked()
}
impl PeImage<'_> {
    pub(super) fn read_imports(&self, authority: bool) -> Result<Vec<String>> {
        check(self.directory(13)? == (0, 0), "delay-import", authority)?;
        let (rva, size) = self.directory(1)?;
        check(
            rva != 0 && (40..=2580).contains(&size) && size % 20 == 0,
            "directory-shape",
            authority,
        )?;
        let table = self.import_map(rva, size, "directory-map", authority)?;
        let mut names = BTreeSet::new();
        for offset in (0..size as usize).step_by(20) {
            let row = span(self.bytes, table + offset, 20)?;
            if row.iter().all(|byte| *byte == 0) {
                check(!names.is_empty(), "empty-directory", authority)?;
                check(
                    self.bytes[table + offset + 20..table + size as usize]
                        .iter()
                        .all(|byte| *byte == 0),
                    "directory-tail",
                    authority,
                )?;
                return Ok(names.into_iter().collect());
            }
            let rva = u32_at(row, 12)?;
            check(
                rva != 0 && u32_at(row, 16)? != 0 && names.len() < 128,
                "descriptor",
                authority,
            )?;
            let mut name = String::new();
            let mut terminated = false;
            for index in 0..128 {
                let at = rva.checked_add(index);
                check(at.is_some(), "name-rva", authority)?;
                let value = self.bytes[self.import_map(at.unwrap(), 1, "name-map", authority)?];
                if value == 0 {
                    terminated = true;
                    break;
                }
                check(
                    value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_' | b'.'),
                    "name-character",
                    authority,
                )?;
                name.push((value as char).to_ascii_lowercase());
            }
            check(
                terminated && name.len() > 4 && name.ends_with(".dll") && names.insert(name),
                "name-shape-or-duplicate",
                authority,
            )?;
        }
        check(false, "terminator", authority)?;
        unreachable!()
    }
    fn import_map(&self, rva: u32, size: u32, stage: &str, authority: bool) -> Result<usize> {
        self.map(rva, size).map_err(|error| {
            if authority {
                error.context(format!(
                    "fixed Rust registry authority import refused stage={stage}"
                ))
            } else {
                error.context(format!("bounded PE import refused stage={stage}"))
            }
        })
    }
    pub(super) fn registry_authority_checked(&self) -> Result<()> {
        ensure!(
            self.entry != 0
                && u16_at(self.bytes, self.pe + 22)? & 0x2002 == 2
                && u16_at(self.bytes, self.optional + 68)? == 3,
            "fixed Rust registry authority PE refused stage=executable"
        );
        ensure!(
            self.directory(14)? == (0, 0),
            "fixed Rust registry authority PE refused stage=clr"
        );
        let names = self.read_imports(true).map_err(|error| {
            error.context("fixed Rust registry authority PE refused stage=imports")
        })?;
        let allowed = [
            "kernel32.dll",
            "ntdll.dll",
            "advapi32.dll",
            "bcrypt.dll",
            "userenv.dll",
            "ws2_32.dll",
            "api-ms-win-core-synch-l1-2-0.dll",
            "bcryptprimitives.dll",
        ];
        ensure!(
            !names.is_empty() && names.iter().all(|name| allowed.contains(&name.as_str())),
            "fixed Rust registry authority PE refused stage=import-profile"
        );
        Ok(())
    }
}
