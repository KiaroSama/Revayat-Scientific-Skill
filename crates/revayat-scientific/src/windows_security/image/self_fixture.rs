//! Fixed self/manual/explicit-ID2 PE roles. Borrowed manifest bytes are never loaded.
use super::*;
use crate::windows_security::activation::self_result::SelfRole;

const SELF_IMPORTS: &[&str] = &[
    "CreateActCtxW",
    "ExitProcess",
    "GetLastError",
    "GetModuleHandleW",
    "GetStdHandle",
    "ReleaseActCtx",
    "WriteFile",
];

impl PeImage<'_> {
    pub fn qualify_self_activation(
        &self,
        role: SelfRole,
        language: u16,
        payload: &[u8],
    ) -> Result<()> {
        self.child_activation_imports(SELF_IMPORTS, true)?;
        ensure!(
            (u16_at(self.bytes, self.optional + 70)? & 0x0200 != 0)
                == (role == SelfRole::ExplicitId2),
            "fixed self activation isolation role differs"
        );
        self.require_manifest(
            if role == SelfRole::Manual { 101 } else { 2 },
            language,
            payload,
        )
    }
}

/// Original synthetic parser bytes with a four-byte payload, not Python or a native fixture.
pub fn self_activation_validation_fixture(role: SelfRole) -> Vec<u8> {
    let mut bytes = base();
    bytes.resize(4096, 0);
    short(&mut bytes, 0x96, 2);
    short(&mut bytes, 0xdc, 3);
    short(
        &mut bytes,
        0xde,
        if role == SelfRole::ExplicitId2 {
            0x200
        } else {
            0
        },
    );
    for (at, value) in [
        (0xd0, 0x3000),
        (0x190, 0xe00),
        (0x198, 0xe00),
        (0x110, 0x1000),
        (0x114, 40),
        (0x200, 0x1080),
        (0x20c, 0x1300),
        (0x210, 0x1100),
    ] {
        put(&mut bytes, at, value);
    }
    text(&mut bytes, 0x500, "KERNEL32.dll\0");
    let mut at = 0x600;
    for (index, name) in SELF_IMPORTS.iter().enumerate() {
        let symbol = (at + 0xe00) as u64;
        long(&mut bytes, 0x280 + index * 8, symbol);
        long(&mut bytes, 0x300 + index * 8, symbol);
        text(&mut bytes, at + 2, name);
        at += name.len() + 3;
    }
    resource(
        &mut bytes,
        0xb00,
        0x1900,
        if role == SelfRole::Manual { 101 } else { 2 },
    );
    bytes
}

pub fn check_self_activation_validation() -> Result<()> {
    const PAYLOAD: &[u8] = &[1, 2, 3, 4];
    let roles = [SelfRole::Original, SelfRole::Manual, SelfRole::ExplicitId2];
    for invalid in [-1, 3, i32::MAX] {
        ensure!(
            SelfRole::try_from(invalid).is_err(),
            "invalid self role accepted"
        );
    }
    for role in roles {
        let bytes = self_activation_validation_fixture(role);
        let check =
            |bytes: &[u8]| PeImage::parse(bytes, 1)?.qualify_self_activation(role, 1033, PAYLOAD);
        check(&bytes)?;
        refuse(
            &bytes,
            &[Short(
                0xde,
                if role == SelfRole::ExplicitId2 {
                    0
                } else {
                    0x200
                },
            )],
            check,
        )?;
        refuse(
            &bytes,
            &[
                Short(0x96, 0x2002),
                Short(0xdc, 2),
                Word(0xa8, 0),
                Xor(0x500),
                Xor(0x602),
                Xor(0x300),
                Group(vec![Copy(0x280, 0x288, 8), Copy(0x300, 0x308, 8)]),
                Group(vec![Zero(0x2b0, 8), Zero(0x330, 8)]),
                Word(0x114, 39),
                Word(0x214, 1),
                Word(0xb30, 1),
                Word(0xb10, 23),
                Xor(0xb80),
                Word(0xb50, 1034),
                Short(0xb4e, 2),
                Word(0xb60, 0x1940),
                Group(vec![
                    Short(0xb2e, 2),
                    Word(0xb30, 1),
                    Word(0xb38, 2),
                    Word(0xb3c, 0x80000040),
                ]),
                Word(0x108, 0x1000),
                Word(0x150, 0x1000),
                Word(0x170, 0x1000),
                Word(0x178, 0x1000),
            ],
            check,
        )?;
        if role == SelfRole::ExplicitId2 {
            refuse(&bytes, &[Short(0xde, 0x1000)], check)?;
            for id in [1, 3, 16, 101, 65535] {
                refuse(&bytes, &[Word(0xb30, id)], check)?;
            }
        }
        if role == SelfRole::Manual {
            for id in [1, 2, 3, 16, 100, 102, 65535] {
                refuse(&bytes, &[Word(0xb30, id)], check)?;
            }
            let image = PeImage::parse(&bytes, 1)?;
            ensure!(
                image
                    .qualify_self_activation(SelfRole::Original, 1033, PAYLOAD)
                    .is_err()
                    && image.module_manifest(true).is_err()
                    && image.manifest(1, true).is_err(),
                "manual manifest crossed a fixed resource role"
            );
            refuse(
                &bytes,
                &[Group(vec![
                    Short(0xb2e, 2),
                    Word(0xb30, 2),
                    Word(0xb38, 101),
                    Word(0xb3c, 0x80000040),
                ])],
                check,
            )?;
        }
    }
    // The caller's root36 validation also runs the original entry-lifetime
    // dependency using these explicit-ID2 bytes; image parsing does not own it.
    Ok(())
}
