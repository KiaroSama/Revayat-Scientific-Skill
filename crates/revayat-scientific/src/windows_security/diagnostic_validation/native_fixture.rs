//! Original no-CRT NativeFixture.Pe contract, separate from the broader OS-image parser.
use super::*;
#[derive(Clone, Copy)]
struct Section {
    address: u32,
    virtual_size: u32,
    raw: u32,
    raw_size: u32,
    flags: u32,
}
pub struct FixedNativeImage<'a> {
    bytes: &'a [u8],
    sections: Vec<Section>,
    headers: u32,
    optional: usize,
}
impl<'a> FixedNativeImage<'a> {
    fn span(&self, at: usize, length: usize) -> Result<&'a [u8]> {
        self.bytes
            .get(
                at..at
                    .checked_add(length)
                    .ok_or_else(|| anyhow::anyhow!("native fixture span overflow"))?,
            )
            .ok_or_else(|| anyhow::anyhow!("native fixture span exceeds image"))
    }
    fn u16(&self, at: usize) -> Result<u16> {
        Ok(u16::from_le_bytes(self.span(at, 2)?.try_into()?))
    }
    fn u32(&self, at: usize) -> Result<u32> {
        Ok(u32::from_le_bytes(self.span(at, 4)?.try_into()?))
    }
    fn u64(&self, at: usize) -> Result<u64> {
        Ok(u64::from_le_bytes(self.span(at, 8)?.try_into()?))
    }
    fn map(&self, rva: u32, length: u32) -> Result<usize> {
        let end = u64::from(rva) + u64::from(length);
        let mut found = None;
        if end <= u64::from(self.headers) {
            self.span(rva as usize, length as usize)?;
            found = Some(rva as usize);
        }
        for section in &self.sections {
            if rva >= section.address
                && end <= u64::from(section.address) + u64::from(section.raw_size)
            {
                let at = u64::from(section.raw) + u64::from(rva - section.address);
                self.span(at as usize, length as usize)?;
                ensure!(found.is_none(), "native fixture RVA mapping is ambiguous");
                found = Some(at as usize);
            }
        }
        found.ok_or_else(|| anyhow::anyhow!("native fixture RVA is unavailable"))
    }
    fn text(&self, rva: u32) -> Result<String> {
        let mut out = String::new();
        for index in 0..128 {
            let at = rva
                .checked_add(index)
                .ok_or_else(|| anyhow::anyhow!("native fixture text RVA overflow"))?;
            let byte = self.bytes[self.map(at, 1)?];
            if byte == 0 {
                return Ok(out);
            }
            ensure!(
                (32..=126).contains(&byte),
                "native fixture text is not bounded ASCII"
            );
            out.push(byte as char);
        }
        anyhow::bail!("native fixture text exceeds bound")
    }
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        ensure!(
            (256..=1048576).contains(&bytes.len()),
            "native fixture image size exceeds bound"
        );
        let mut image = Self {
            bytes,
            sections: Vec::new(),
            headers: 0,
            optional: 0,
        };
        ensure!(
            image.u16(0)? == 0x5a4d,
            "native fixture DOS signature differs"
        );
        let pe = image.u32(0x3c)? as usize;
        ensure!(
            pe >= 64 && image.u32(pe)? == 0x4550 && image.u16(pe + 4)? == 0x8664,
            "native fixture NT signature/machine differs"
        );
        let count = image.u16(pe + 6)? as usize;
        let optional_size = image.u16(pe + 20)? as usize;
        ensure!(
            (1..=16).contains(&count) && optional_size >= 240 && image.u16(pe + 22)? & 0x2002 == 2,
            "native fixture header contract differs"
        );
        image.optional = pe + 24;
        let optional = image.optional;
        image.span(optional, optional_size)?;
        ensure!(
            image.u16(optional)? == 0x20b
                && image.u16(optional + 68)? == 3
                && image.u32(optional + 108)? == 16,
            "native fixture optional header differs"
        );
        image.headers = image.u32(optional + 60)?;
        let table = optional + optional_size;
        image.span(table, count * 40)?;
        ensure!(
            image.headers > 0
                && image.headers as usize <= bytes.len()
                && table + count * 40 <= image.headers as usize,
            "native fixture section table exceeds headers"
        );
        for index in 0..count {
            let row = table + index * 40;
            let section = Section {
                virtual_size: image.u32(row + 8)?,
                address: image.u32(row + 12)?,
                raw_size: image.u32(row + 16)?,
                raw: image.u32(row + 20)?,
                flags: image.u32(row + 36)?,
            };
            ensure!(
                section.raw_size > 0
                    && section.raw >= image.headers
                    && section.address >= image.headers,
                "native fixture section overlaps headers"
            );
            image.span(section.raw as usize, section.raw_size as usize)?;
            ensure!(
                u64::from(section.address) + u64::from(section.virtual_size.max(section.raw_size))
                    <= u64::from(u32::MAX) + 1,
                "native fixture virtual section overflow"
            );
            for prior in &image.sections {
                ensure!(
                    (u64::from(section.raw) >= u64::from(prior.raw) + u64::from(prior.raw_size)
                        || u64::from(prior.raw)
                            >= u64::from(section.raw) + u64::from(section.raw_size))
                        && (u64::from(section.address)
                            >= u64::from(prior.address)
                                + u64::from(prior.virtual_size.max(prior.raw_size))
                            || u64::from(prior.address)
                                >= u64::from(section.address)
                                    + u64::from(section.virtual_size.max(section.raw_size))),
                    "native fixture sections overlap"
                );
            }
            image.sections.push(section);
        }
        let entry = image.u32(optional + 16)?;
        ensure!(entry != 0, "native fixture entry absent");
        image.map(entry, 1)?;
        ensure!(
            image
                .sections
                .iter()
                .filter(|section| entry >= section.address
                    && u64::from(entry) < u64::from(section.address) + u64::from(section.raw_size)
                    && section.flags & 0x20000000 != 0)
                .count()
                == 1,
            "native fixture entry is not uniquely executable"
        );
        for directory in [2, 9, 13, 14] {
            ensure!(
                image.u64(optional + 112 + directory * 8)? == 0,
                "native fixture forbidden resource/TLS/import/CLR directory"
            );
        }
        let import = image.u32(optional + 120)?;
        let length = image.u32(optional + 124)?;
        ensure!(
            import != 0 && length >= 40,
            "native fixture import directory absent"
        );
        let descriptor = image.map(import, length)?;
        let thunk = image.u32(descriptor)?;
        let name = image.u32(descriptor + 12)?;
        let iat = image.u32(descriptor + 16)?;
        ensure!(
            thunk != 0
                && name != 0
                && iat != 0
                && image.u32(descriptor + 4)? == 0
                && image.u32(descriptor + 8)? == 0
                && image.text(name)?.eq_ignore_ascii_case("KERNEL32.dll"),
            "native fixture import descriptor differs"
        );
        for offset in (20..40).step_by(4) {
            ensure!(
                image.u32(descriptor + offset)? == 0,
                "native fixture import descriptor repeated"
            );
        }
        let lookup = image.map(thunk, 16)?;
        let symbol = image.u64(lookup)?;
        ensure!(
            symbol > 0 && symbol <= u64::from(u32::MAX) && image.u64(lookup + 8)? == 0,
            "native fixture lookup shape differs"
        );
        let symbol = symbol as u32;
        let name = symbol
            .checked_add(2)
            .ok_or_else(|| anyhow::anyhow!("native fixture import name overflow"))?;
        ensure!(
            image.text(name)? == "ExitProcess",
            "native fixture import name differs"
        );
        image.map(symbol, 2)?;
        let address = image.map(iat, 16)?;
        ensure!(
            image.u64(address)? == u64::from(symbol) && image.u64(address + 8)? == 0,
            "native fixture IAT differs from lookup"
        );
        Ok(image)
    }
    pub fn debug_control_site(&self) -> Result<u32> {
        let export = self.u32(self.optional + 112)?;
        let length = self.u32(self.optional + 116)?;
        ensure!(
            export != 0
                && length >= 40
                && u64::from(export) + u64::from(length) <= u64::from(u32::MAX),
            "debug-control export range differs"
        );
        let table = self.map(export, length)?;
        ensure!(
            self.u32(table + 20)? == 1 && self.u32(table + 24)? == 1,
            "debug-control export count differs"
        );
        let function = self.u32(self.map(self.u32(table + 28)?, 4)?)?;
        let name = self.u32(self.map(self.u32(table + 32)?, 4)?)?;
        ensure!(
            self.u16(self.map(self.u32(table + 36)?, 2)?)? == 0
                && self.text(name)? == "DebugControlSite",
            "debug-control export name/ordinal differs"
        );
        ensure!(
            function < export || u64::from(function) >= u64::from(export) + u64::from(length),
            "debug-control export is forwarded"
        );
        ensure!(
            self.sections
                .iter()
                .any(|section| section.flags & 0x20000000 != 0
                    && function >= section.address
                    && u64::from(function) + 6
                        <= u64::from(section.address) + u64::from(section.raw_size)),
            "debug-control site is not executable"
        );
        ensure!(
            self.span(self.map(function, 6)?, 6)? == [0xb8, 0x31, 0x43, 0x44, 0x53, 0xc3],
            "debug-control site bytes differ"
        );
        Ok(function)
    }
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn fixture() -> Vec<u8> {
    let mut b = vec![0; 1024];
    for (at, n) in [
        (0, 0x5a4d),
        (0x84, 0x8664),
        (0x86, 1),
        (0x94, 240),
        (0x96, 2),
        (0x98, 0x20b),
        (0x98 + 68, 3),
    ] {
        put16(&mut b, at, n);
    }
    for (at, n) in [
        (0x3c, 0x80),
        (0x80, 0x4550),
        (0x98 + 16, 0x1000),
        (0x98 + 60, 0x200),
        (0x98 + 108, 16),
        (0x98 + 112, 0x1100),
        (0x98 + 116, 0x100),
        (0x98 + 120, 0x1040),
        (0x98 + 124, 40),
        (0x188 + 8, 0x200),
        (0x188 + 12, 0x1000),
        (0x188 + 16, 0x200),
        (0x188 + 20, 0x200),
        (0x188 + 36, 0x60000020),
        (0x240, 0x1080),
        (0x24c, 0x10a0),
        (0x250, 0x1090),
        (0x300 + 20, 1),
        (0x300 + 24, 1),
        (0x300 + 28, 0x1140),
        (0x300 + 32, 0x114c),
        (0x300 + 36, 0x1150),
        (0x340, 0x1010),
        (0x34c, 0x1160),
    ] {
        put32(&mut b, at, n);
    }
    b[0x280..0x288].copy_from_slice(&0x10c0u64.to_le_bytes());
    b[0x290..0x298].copy_from_slice(&0x10c0u64.to_le_bytes());
    b[0x2a0..0x2ad].copy_from_slice(b"KERNEL32.dll\0");
    b[0x2c2..0x2ce].copy_from_slice(b"ExitProcess\0");
    b[0x360..0x371].copy_from_slice(b"DebugControlSite\0");
    b[0x210..0x216].copy_from_slice(&[0xb8, 0x31, 0x43, 0x44, 0x53, 0xc3]);
    b
}
pub fn check_native_debug_control_validation() -> Result<()> {
    let bytes = fixture();
    ensure!(
        FixedNativeImage::parse(&bytes)?.debug_control_site()? == 0x1010,
        "debug-control positive site differs"
    );
    for (at, value, width) in [
        (0x210, 0x90, 1),
        (0x215, 0x90, 1),
        (0x300 + 20, 2, 4),
        (0x340, 0x1100, 4),
        (0x34c, u32::MAX, 4),
        (0x188 + 36, 0x40000040, 4),
    ] {
        let mut bad = bytes.clone();
        if width == 1 {
            bad[at] = value as u8;
        } else {
            put32(&mut bad, at, value);
        }
        ensure!(
            FixedNativeImage::parse(&bad)
                .and_then(|image| image.debug_control_site())
                .is_err(),
            "malformed debug-control PE was accepted"
        );
    }
    Ok(())
}
