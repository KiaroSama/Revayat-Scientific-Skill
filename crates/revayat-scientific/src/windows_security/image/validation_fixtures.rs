//! Independent literal baseline PE fixtures. These bytes are never executed.
use super::*;
pub(super) fn put(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
pub(super) fn short(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
pub(super) fn long(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
pub(super) fn text(bytes: &mut [u8], offset: usize, value: &str) {
    bytes[offset..offset + value.len()].copy_from_slice(value.as_bytes());
}
pub(super) fn base() -> Vec<u8> {
    let mut b = vec![0; 1024];
    for (at, n) in [
        (0, 0x5a4d),
        (0x84, 0x8664),
        (0x86, 1),
        (0x94, 240),
        (0x98, 0x20b),
    ] {
        short(&mut b, at, n);
    }
    for (at, n) in [
        (0x3c, 0x80),
        (0x80, 0x4550),
        (0xa8, 0x1000),
        (0xd0, 0x2000),
        (0xd4, 0x200),
        (0x104, 16),
        (0x190, 0x200),
        (0x194, 0x1000),
        (0x198, 0x200),
        (0x19c, 0x200),
        (0x1ac, 0x60000020),
    ] {
        put(&mut b, at, n);
    }
    b
}
pub(super) fn identity() -> Vec<u8> {
    let mut b = base();
    b.resize(2048, 0);
    for (at, n) in [
        (0x190, 0x600),
        (0x198, 0x600),
        (0x88, 0x12345678),
        (0x138, 0x1200),
        (0x13c, 28),
        (0x40c, 2),
        (0x410, 39),
        (0x414, 0x1280),
        (0x418, 0x480),
        (0x480, 0x53445352),
        (0x494, 7),
    ] {
        put(&mut b, at, n);
    }
    b[0x484..0x494].copy_from_slice(&[
        0x33, 0x22, 0x11, 0, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ]);
    text(&mut b, 0x498, "kernelbase.pdb\0");
    b
}
pub(super) fn static_image() -> Vec<u8> {
    let mut b = identity();
    long(&mut b, 0xb0, 0x180000000);
    b[0x200..0x20b].copy_from_slice(&[0xb8, 0, 0, 0, 0, 0xc3, 0xe8, 0xf5, 0xff, 0xff, 0xff]);
    b
}
pub(super) fn worker() -> Vec<u8> {
    let mut b = static_image();
    short(&mut b, 0x96, 0x2002);
    put(&mut b, 0x108, 0x1200);
    put(&mut b, 0x10c, 0x200);
    b[0x400..0x600].fill(0);
    for (at, n) in [
        (0x410, 7),
        (0x414, 2),
        (0x418, 1),
        (0x41c, 0x1240),
        (0x420, 0x1250),
        (0x424, 0x1258),
        (0x440, 0x1020),
        (0x450, 0x1280),
    ] {
        put(&mut b, at, n);
    }
    text(&mut b, 0x480, "CreateActCtxWWorker\0");
    b[0x220..0x22a].copy_from_slice(&[0xb8, 1, 0, 0, 0, 0xe9, 0xd6, 0xff, 0xff, 0xff]);
    b
}
pub(super) fn imports(names: &[&str]) -> Vec<u8> {
    let mut b = base();
    put(&mut b, 0x110, 0x1000);
    put(&mut b, 0x114, ((names.len() + 1) * 20) as u32);
    let mut offset = 0x300;
    for (index, name) in names.iter().enumerate() {
        let row = 0x200 + index * 20;
        for (at, n) in [
            (row, 0x11f0),
            (row + 16, 0x11f0),
            (row + 12, (0x1000 + offset - 0x200) as u32),
        ] {
            put(&mut b, at, n);
        }
        text(&mut b, offset, name);
        offset += name.len() + 1;
    }
    b
}
pub(super) fn resource(b: &mut [u8], raw: usize, rva: u32, id: u32) {
    put(b, 0x118, rva);
    put(b, 0x11c, 0x100);
    for at in [raw + 14, raw + 0x2e, raw + 0x4e] {
        short(b, at, 1);
    }
    for (at, n) in [
        (raw + 0x10, 24),
        (raw + 0x14, 0x80000020),
        (raw + 0x30, id),
        (raw + 0x34, 0x80000040),
        (raw + 0x50, 1033),
        (raw + 0x54, 0x60),
        (raw + 0x60, rva + 0x80),
        (raw + 0x64, 4),
    ] {
        put(b, at, n);
    }
    b[raw + 0x80..raw + 0x84].copy_from_slice(&[1, 2, 3, 4]);
}
pub(super) fn manifest() -> Vec<u8> {
    let mut b = base();
    resource(&mut b, 0x200, 0x1000, 1);
    put(&mut b, 0x11c, 0x200);
    b
}
pub(super) fn default_activation() -> Vec<u8> {
    let mut b = base();
    b.resize(2048, 0);
    short(&mut b, 0x96, 2);
    short(&mut b, 0xdc, 3);
    for (at, n) in [
        (0x190, 0x600),
        (0x198, 0x600),
        (0x110, 0x1000),
        (0x114, 40),
        (0x200, 0x1040),
        (0x20c, 0x10c0),
        (0x210, 0x1080),
    ] {
        put(&mut b, at, n);
    }
    text(&mut b, 0x2c0, "KERNEL32.dll\0");
    symbols(
        &mut b,
        &["ExitProcess", "GetStdHandle", "WriteFile"],
        0x300,
        0x240,
        0x280,
    );
    resource(&mut b, 0x500, 0x1300, 1);
    b
}
fn symbols(b: &mut [u8], names: &[&str], mut offset: usize, lookup: usize, address: usize) {
    for (index, name) in names.iter().enumerate() {
        let rva = (offset + 0xe00) as u64;
        long(b, lookup + index * 8, rva);
        long(b, address + index * 8, rva);
        text(b, offset + 2, name);
        offset += name.len() + 3;
    }
}
pub(super) fn module_activation(dll: bool, manifest: bool) -> Vec<u8> {
    let mut b = base();
    b.resize(4096, 0);
    short(&mut b, 0x96, if dll { 0x2002 } else { 2 });
    short(&mut b, 0xdc, 3);
    for (at, n) in [
        (0xd0, 0x3000),
        (0x190, 0xe00),
        (0x198, 0xe00),
        (0x110, 0x1000),
        (0x114, if dll { 40 } else { 60 }),
        (0x200, 0x1080),
        (0x20c, 0x1300),
        (0x210, 0x1100),
    ] {
        put(&mut b, at, n);
    }
    text(&mut b, 0x500, "KERNEL32.dll\0");
    symbols(
        &mut b,
        if dll {
            &[
                "CompareStringOrdinal",
                "GetLastError",
                "GetModuleFileNameW",
                "QueryActCtxW",
            ]
        } else {
            &["ExitProcess", "GetStdHandle", "WriteFile"]
        },
        0x600,
        0x280,
        0x300,
    );
    if dll {
        for (at, n) in [
            (0x108, 0x1800),
            (0x10c, 0x100),
            (0xa0c, 0x184c),
            (0xa14, 1),
            (0xa18, 1),
            (0xa1c, 0x1840),
            (0xa20, 0x1844),
            (0xa24, 0x1848),
            (0xa40, 0x1010),
            (0xa44, 0x1880),
        ] {
            put(&mut b, at, n);
        }
        text(&mut b, 0xa4c, "startup-module.dll\0");
        text(&mut b, 0xa80, "ObserveModuleActivation\0");
    } else {
        for (at, n) in [(0x214, 0x1180), (0x220, 0x1340), (0x224, 0x1200)] {
            put(&mut b, at, n);
        }
        text(&mut b, 0x540, "startup-module.dll\0");
        long(&mut b, 0x380, 0x1580);
        long(&mut b, 0x400, 0x1580);
        text(&mut b, 0x782, "ObserveModuleActivation\0");
    }
    if manifest {
        resource(&mut b, 0xb00, 0x1900, 2);
    }
    b
}
pub(super) enum Change {
    Text(usize, &'static str),
    Group(Vec<Change>),
    Word(usize, u32),
    Short(usize, u16),
    Xor(usize),
    Byte(usize, u8),
    Zero(usize, usize),
    Copy(usize, usize, usize),
    Long(usize, u64),
}
pub(super) fn apply(b: &mut [u8], change: &Change) {
    if let Change::Group(changes) = change {
        for child in changes {
            apply(b, child);
        }
        return;
    }
    match *change {
        Change::Group(_) => unreachable!(),
        Change::Text(at, value) => text(b, at, value),
        Change::Word(at, n) => put(b, at, n),
        Change::Short(at, n) => short(b, at, n),
        Change::Xor(at) => b[at] ^= 1,
        Change::Byte(at, n) => b[at] = n,
        Change::Zero(at, n) => b[at..at + n].fill(0),
        Change::Copy(from, to, n) => b.copy_within(from..from + n, to),
        Change::Long(at, n) => long(b, at, n),
    }
}
pub(super) fn refuse(
    bytes: &[u8],
    changes: &[Change],
    check: impl Fn(&[u8]) -> Result<()>,
) -> Result<()> {
    for (index, change) in changes.iter().enumerate() {
        let mut bad = bytes.to_vec();
        apply(&mut bad, change);
        ensure!(
            check(&bad).is_err(),
            "original image mutation accepted index={index}"
        );
    }
    Ok(())
}
