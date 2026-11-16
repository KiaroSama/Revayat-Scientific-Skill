//! Frozen no-entry registry-loader PE role; these bytes are inspected, never executed here.
use super::*;
pub fn qualify_registry_loader(bytes: &[u8]) -> Result<()> {
    PeImage::parse(bytes, 1)?.qualify_registry_loader()
}
impl PeImage<'_> {
    pub fn qualify_registry_loader(&self) -> Result<()> {
        ensure!(
            u16_at(self.bytes, self.pe + 22)? & 0x2002 == 0x2002 && self.entry == 0,
            "registry loader DLL/entry differs"
        );
        for directory in [2, 9, 13, 14] {
            ensure!(
                self.directory(directory)? == (0, 0),
                "registry loader has an unsupported directory"
            );
        }
        ensure!(
            self.direct_imports()? == ["kernel32.dll", "python311.dll"],
            "registry loader direct imports differ"
        );
        let (rva, size) = self.directory(0)?;
        ensure!(
            rva != 0 && (40..=4096).contains(&size),
            "registry loader export span differs"
        );
        let table = self.map(rva, size)?;
        ensure!(
            self.text(u32_at(self.bytes, table + 12)?, 64, false)? == "_registry_loader.pyd"
                && u32_at(self.bytes, table + 20)? == 1
                && u32_at(self.bytes, table + 24)? == 1,
            "registry loader export identity/count differs"
        );
        let function = u32_at(self.bytes, self.map(u32_at(self.bytes, table + 28)?, 4)?)?;
        let name = u32_at(self.bytes, self.map(u32_at(self.bytes, table + 32)?, 4)?)?;
        ensure!(
            u16_at(self.bytes, self.map(u32_at(self.bytes, table + 36)?, 2)?)? == 0
                && self.text(name, 64, false)? == "PyInit__registry_loader"
                && self.executable(function, 1),
            "registry loader export target differs"
        );
        ensure!(
            function < rva || u64::from(function) >= u64::from(rva) + u64::from(size),
            "registry loader export is forwarded"
        );
        Ok(())
    }
}
/// All thirteen mutations in KernelImageRegistryLoader.CheckRegistryLoaderValidation.
pub fn check_registry_loader_validation() -> Result<()> {
    let mut bytes = imports(&["KERNEL32.dll", "python311.dll"]);
    bytes.resize(4096, 0);
    short(&mut bytes, 0x96, 0x2002);
    put(&mut bytes, 0x98 + 16, 0);
    for (at, value) in [
        (0x98 + 56, 0x3000),
        (0x188 + 8, 0xE00),
        (0x188 + 16, 0xE00),
        (0x98 + 112, 0x1800),
        (0x98 + 116, 0x100),
        (0xA0C, 0x184C),
        (0xA14, 1),
        (0xA18, 1),
        (0xA1C, 0x1840),
        (0xA20, 0x1844),
        (0xA24, 0x1848),
        (0xA40, 0x1010),
        (0xA44, 0x1880),
    ] {
        put(&mut bytes, at, value);
    }
    text(&mut bytes, 0xA4C, "_registry_loader.pyd\0");
    text(&mut bytes, 0xA80, "PyInit__registry_loader\0");
    qualify_registry_loader(&bytes)?;
    refuse(
        &bytes,
        &[
            Short(0x84, 0x14C),
            Short(0x96, 2),
            Word(0x98 + 16, 0x1010),
            Word(0x98 + 112 + 9 * 8, 0x1000),
            Word(0x98 + 116 + 9 * 8, 4),
            Word(0x98 + 112 + 14 * 8, 0x1000),
            Word(0x98 + 112 + 13 * 8, 0x1000),
            Xor(0x310),
            Word(0xA14, 2),
            Word(0xA18, 2),
            Word(0xA40, 0x1800),
            Xor(0xA80),
            Short(0xA48, 1),
        ],
        qualify_registry_loader,
    )
}
