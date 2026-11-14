//! Separate no-entry CPython C-API module role. PE shape alone never attests compilation/execution.
use super::*;
pub fn qualify_python_authority(bytes: &[u8]) -> Result<()> {
    let image = PeImage::parse(bytes, 1)?;
    ensure!(
        u16_at(bytes, image.pe + 22)? & 0x2002 == 0x2002 && image.entry == 0,
        "Python authority module DLL/entry differs"
    );
    for directory in [2, 9, 13, 14] {
        ensure!(
            image.directory(directory)? == (0, 0),
            "Python authority module has an unsupported directory"
        );
    }
    ensure!(
        image.direct_imports()? == ["python311.dll"],
        "Python authority module imports differ"
    );
    let (rva, size) = image.directory(0)?;
    ensure!(
        rva != 0 && (40..=4096).contains(&size),
        "Python authority module export span differs"
    );
    let table = image.map(rva, size)?;
    ensure!(
        image.text(u32_at(bytes, table + 12)?, 64, false)? == "_registry_authority.pyd"
            && u32_at(bytes, table + 20)? == 1
            && u32_at(bytes, table + 24)? == 1,
        "Python authority module export identity/count differs"
    );
    let function = u32_at(bytes, image.map(u32_at(bytes, table + 28)?, 4)?)?;
    let name = u32_at(bytes, image.map(u32_at(bytes, table + 32)?, 4)?)?;
    ensure!(
        u16_at(bytes, image.map(u32_at(bytes, table + 36)?, 2)?)? == 0
            && image.text(name, 64, false)? == "PyInit__registry_authority"
            && image.executable(function, 1)
            && (function < rva || u64::from(function) >= u64::from(rva) + u64::from(size)),
        "Python authority module export target differs"
    );
    Ok(())
}
/// Synthetic parser assertions only, extending existing carriers when this role is integrated.
pub fn check_python_authority_validation() -> Result<()> {
    let mut bytes = imports(&["python311.dll"]);
    bytes.resize(4096, 0);
    short(&mut bytes, 0x96, 0x2002);
    put(&mut bytes, 0x98 + 16, 0);
    for (at, value) in [
        (0x98 + 56, 0x3000),
        (0x188 + 8, 0xe00),
        (0x188 + 16, 0xe00),
        (0x98 + 112, 0x1800),
        (0x98 + 116, 0x100),
        (0xa0c, 0x184c),
        (0xa14, 1),
        (0xa18, 1),
        (0xa1c, 0x1840),
        (0xa20, 0x1844),
        (0xa24, 0x1848),
        (0xa40, 0x1010),
        (0xa44, 0x1880),
    ] {
        put(&mut bytes, at, value);
    }
    text(&mut bytes, 0xa4c, "_registry_authority.pyd\0");
    text(&mut bytes, 0xa80, "PyInit__registry_authority\0");
    qualify_python_authority(&bytes)?;
    refuse(
        &bytes,
        &[
            Short(0x84, 0x14c),
            Short(0x96, 2),
            Word(0x98 + 16, 0x1010),
            Word(0x98 + 112 + 2 * 8, 0x1000),
            Word(0x98 + 112 + 9 * 8, 0x1000),
            Word(0x98 + 116 + 9 * 8, 4),
            Word(0x98 + 112 + 13 * 8, 0x1000),
            Word(0x98 + 112 + 14 * 8, 0x1000),
            Xor(0x300),
            Xor(0xa4c),
            Word(0xa14, 2),
            Word(0xa18, 2),
            Word(0xa40, 0x1800),
            Xor(0xa80),
            Short(0xa48, 1),
        ],
        qualify_python_authority,
    )
}
