//! Callable original bootstrap assertions. Fixtures exercise production parsers;
//! returning successfully is not evidence that an ordered native stage ran.
use super::*;
#[path = "validation_fixtures.rs"]
mod fixtures;
use fixtures::{Change::*, *};
#[path = "static_checks.rs"]
mod static_checks;
pub use static_checks::{check_identity_validation, check_static_validation};
#[path = "import_checks.rs"]
mod import_checks;
pub use import_checks::check_import_validation;
#[path = "registry_loader.rs"]
mod registry_loader;
pub use registry_loader::{check_registry_loader_validation, qualify_registry_loader};
#[path = "observation_checks.rs"]
mod observation_checks;
pub use observation_checks::{check_checkpoint_validation, check_observation_validation};
#[path = "worker_checks.rs"]
mod worker_checks;
pub use worker_checks::check_activation_worker_validation;
#[path = "child_fixture.rs"]
mod child_fixture;
pub use child_fixture::{check_child_activation_validation, child_activation_validation_fixture};
#[path = "self_fixture.rs"]
mod self_fixture;
pub use self_fixture::{check_self_activation_validation, self_activation_validation_fixture};
#[path = "csr_export_checks.rs"]
mod csr_export_checks;
pub(super) use csr_export_checks::check_csr_export_validation;
#[path = "python_dispatch_checks.rs"]
mod python_dispatch_checks;
pub use python_dispatch_checks::{
    check_python_dispatch_identity, python_dispatch_validation_fixtures,
    qualify_python_dispatch_image,
};

/// Original managed stage8 root, including all reachable pure assertion helpers.
pub fn check_validation() -> Result<()> {
    check_identity_validation()?;
    check_static_validation()?;
    check_observation_validation()?;
    let bytes = base();
    let image = KernelImage::with_subject(&bytes, 0x10000000, "ntdll.dll")?;
    ensure!(
        image.pe.entry == 0x1000 && image.contains_executable(0x10001000),
        "hardware image positive parser fixture differs"
    );
    refuse(
        &bytes,
        &[
            Word(0x3c, u32::MAX),
            Short(0x86, 65),
            Word(0xa8, 0x3000),
            Word(0x1ac, 0x40000040),
            Word(0x19c, u32::MAX),
            Word(0x194, u32::MAX),
            Group(vec![Short(0x86, 2), Copy(0x188, 0x1b0, 40)]),
        ],
        |bad| KernelImage::with_subject(bad, 0x10000000, "ntdll.dll").map(|_| ()),
    )
}
pub fn static_validation_fixture() -> Vec<u8> {
    static_image()
}
pub fn activation_worker_validation_fixture() -> Vec<u8> {
    worker()
}
/// Original literal parser fixture; never an executable/native observation.
pub fn module_activation_validation_fixture(dll: bool, manifest: bool) -> Vec<u8> {
    module_activation(dll, manifest)
}

pub fn check_default_activation_validation() -> Result<()> {
    let b = default_activation();
    let check =
        |bytes: &[u8]| PeImage::parse(bytes, 1)?.qualify_default_activation(1033, &[1, 2, 3, 4]);
    check(&b)?;
    refuse(
        &b,
        &[
            Xor(0x580),
            Word(0x550, 0),
            Word(0x530, 2),
            Short(0x50e, 2),
            Short(0x54e, 2),
            Word(0x560, 0x1340),
            Word(0x564, 65537),
            Word(0xa8, 0),
            Short(0x96, 0x2002),
            Word(0x108, 0x1000),
            Word(0x150, 0x1000),
            Word(0x170, 0x1000),
            Word(0x178, 0x1000),
            Xor(0x280),
            Byte(0x302, b'X'),
            Word(0x218, 1),
        ],
        check,
    )
}
pub fn check_module_activation_validation() -> Result<()> {
    for role in 0..3 {
        let dll = role != 0;
        let manifest = role == 2;
        let b = module_activation(dll, manifest);
        let check = |bytes: &[u8]| {
            PeImage::parse(bytes, 1)?.qualify_module_activation(dll, manifest, 1033, &[1, 2, 3, 4])
        };
        check(&b)?;
        refuse(
            &b,
            &[
                Short(0x96, if dll { 2 } else { 0x2002 }),
                Word(0xa8, 0),
                Short(0xdc, 2),
                Xor(0x500),
                Xor(0x602),
                Xor(0x300),
                Word(0x114, 39),
                Word(0x150, 0x1000),
                Word(0x170, 0x1000),
                Word(0x178, 0x1000),
                Word(if dll { 0x214 } else { 0x228 }, 1),
            ],
            check,
        )?;
        if dll {
            refuse(
                &b,
                &[
                    Word(0xa14, 2),
                    Word(0xa18, 2),
                    Word(0xa40, 0x1800),
                    Xor(0xa82),
                    Short(0xa48, 1),
                ],
                check,
            )?;
        }
        if manifest {
            refuse(
                &b,
                &[
                    Word(0xb30, 1),
                    Word(0xb10, 23),
                    Xor(0xb80),
                    Word(0xb50, 1034),
                    Short(0xb4e, 2),
                    Word(0xb60, 0x1940),
                ],
                check,
            )?;
        } else {
            refuse(&b, &[Word(0x11c, 8)], check)?;
        }
    }
    Ok(())
}
pub fn check_manifest_validation() -> Result<()> {
    let b = manifest();
    let image = PeImage::parse(&b, 1)?;
    let value = image.manifest(1, false)?;
    ensure!(
        value.language == 1033 && value.bytes == [1, 2, 3, 4],
        "original manifest positive differs"
    );
    let mut owned = image.manifest(1, true)?.bytes.to_vec();
    owned[0] = 9;
    ensure!(
        owned[0] == 9 && b[0x280] == 1,
        "manifest copy changed its source"
    );
    let mut module = b.clone();
    put(&mut module, 0x230, 2);
    let module_image = PeImage::parse(&module, 1)?;
    let value = module_image.module_manifest(true)?;
    ensure!(
        value.language == 1033
            && value.bytes == [1, 2, 3, 4]
            && module_image.manifest(1, false).is_err()
            && image.module_manifest(false).is_err(),
        "original manifest ID boundary differs"
    );
    for extra_type in [true, false] {
        let mut extra = b.clone();
        if extra_type {
            short(&mut extra, 0x20e, 2);
            put(&mut extra, 0x218, 25);
            put(&mut extra, 0x21c, 0x80000020);
        } else {
            short(&mut extra, 0x22e, 2);
            put(&mut extra, 0x238, 2);
            put(&mut extra, 0x23c, 0x80000040);
        }
        let extra = PeImage::parse(&extra, 1)?;
        ensure!(
            extra.manifest(1, false)?.bytes.len() == 4 && extra.manifest(1, true).is_err(),
            "sole-manifest boundary differs"
        );
    }
    for sole in [false, true] {
        refuse(
            &b,
            &[
                Word(0x118, 0),
                Word(0x11c, 15),
                Short(0x20e, 129),
                Short(0x20c, 1),
                Word(0x210, 23),
                Word(0x214, 0x80000000),
                Word(0x214, 0xfffffff0),
                Word(0x234, 0x80000020),
                Word(0x254, 0x80000060),
                Short(0x24e, 2),
                Word(0x250, 65536),
                Word(0x26c, 1),
                Word(0x260, 0x1040),
                Word(0x264, 65537),
                Word(0x264, 0),
            ],
            |bad| PeImage::parse(bad, 1)?.manifest(1, sole).map(|_| ()),
        )?;
        let mut duplicate = b.clone();
        short(&mut duplicate, 0x20e, 2);
        put(&mut duplicate, 0x218, 24);
        put(&mut duplicate, 0x21c, 0x80000020);
        ensure!(
            PeImage::parse(&duplicate, 1)?.manifest(1, sole).is_err(),
            "duplicate manifest type accepted"
        );
    }
    Ok(())
}
