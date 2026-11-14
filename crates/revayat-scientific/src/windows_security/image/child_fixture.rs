//! Original fixed no-CRT child PE role and literal parser assertions. No execution.
use super::*;

pub(super) const CHILD_IMPORTS: &[&str] = &[
    "CreateActCtxW",
    "ExitProcess",
    "GetLastError",
    "GetStdHandle",
    "ReleaseActCtx",
    "WriteFile",
];

impl PeImage<'_> {
    pub fn qualify_child_activation(&self) -> Result<()> {
        self.child_activation_imports(CHILD_IMPORTS, false)
    }

    pub(in crate::windows_security::image) fn child_activation_imports(
        &self,
        expected: &[&str],
        manifest: bool,
    ) -> Result<()> {
        self.activation_role(false, manifest)?;
        let (rva, size) = self.directory(1)?;
        ensure!(
            rva != 0 && (40..=128).contains(&size),
            "fixed child import directory differs"
        );
        let table = self.map(rva, size)?;
        let owner = self.activation_descriptor(table, expected)?;
        ensure!(
            owner.eq_ignore_ascii_case("KERNEL32.dll")
                && self.bytes[table + 20..table + size as usize]
                    .iter()
                    .all(|byte| *byte == 0),
            "fixed child import owner or descriptor tail differs"
        );
        Ok(())
    }
}

/// Exact original synthetic parser fixture; this is never a native child image.
pub fn child_activation_validation_fixture() -> Vec<u8> {
    let mut bytes = base();
    bytes.resize(2048, 0);
    short(&mut bytes, 0x96, 2);
    short(&mut bytes, 0xdc, 3);
    for (at, value) in [
        (0x190, 0x600),
        (0x198, 0x600),
        (0x110, 0x1000),
        (0x114, 40),
        (0x200, 0x1040),
        (0x20c, 0x10c0),
        (0x210, 0x1080),
    ] {
        put(&mut bytes, at, value);
    }
    text(&mut bytes, 0x2c0, "KERNEL32.dll\0");
    let mut at = 0x300;
    for (index, name) in CHILD_IMPORTS.iter().enumerate() {
        let symbol = (at + 0xe00) as u64;
        long(&mut bytes, 0x240 + index * 8, symbol);
        long(&mut bytes, 0x280 + index * 8, symbol);
        text(&mut bytes, at + 2, name);
        at += name.len() + 3;
    }
    bytes
}

pub fn check_child_activation_validation() -> Result<()> {
    let bytes = child_activation_validation_fixture();
    let check = |bytes: &[u8]| PeImage::parse(bytes, 1)?.qualify_child_activation();
    check(&bytes)?;
    refuse(
        &bytes,
        &[
            Short(0x96, 0x2002),
            Short(0xdc, 2),
            Word(0xa8, 0),
            Word(0x118, 0x1000),
            Word(0x11c, 8),
            Word(0x108, 0x1000),
            Word(0x150, 0x1000),
            Word(0x170, 0x1000),
            Word(0x178, 0x1000),
            Word(0x114, 39),
            Word(0x114, 129),
            Word(0x214, 1),
            Byte(0x2c0, b'X'),
            Byte(0x302, b'X'),
            Xor(0x280),
            Zero(0x240, 8),
            Group(vec![Copy(0x240, 0x248, 8), Copy(0x280, 0x288, 8)]),
            Group(vec![Byte(0x247, 0x80), Byte(0x287, 0x80)]),
            Group(vec![Word(0x240, u32::MAX), Word(0x280, u32::MAX)]),
        ],
        check,
    )
}
