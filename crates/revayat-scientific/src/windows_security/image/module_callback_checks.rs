//! Original callback/profile assertion roots, separate from CSR qualification.
use super::*;
use csr::{put, raw};
use std::path::Path;

pub fn qualify_module_callback_host(bytes: &[u8], digest: &str) -> Result<()> {
    ensure!(sha256(bytes) == digest, "callback host digest differs");
    let image = PeImage::parse(bytes, 1)?;
    image.qualify_module_activation(false, false, 0, &[])?;
    ensure!(
        image.full_executable(image.entry, 1),
        "callback entry is incomplete"
    );
    Ok(())
}
pub fn qualify_module_callback_path(actual: &Path, expected: &Path) -> Result<()> {
    let actual_text = actual
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("callback event path is not Unicode"))?;
    let expected_text = expected
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("callback expected path is not Unicode"))?;
    ensure!(
        expected.file_name().and_then(|v| v.to_str()) == Some("startup-module.exe")
            && expected
                .parent()
                .and_then(Path::file_name)
                .and_then(|v| v.to_str())
                == Some("module-id2")
            && crate::windows_security::sxs::ordinal_path_equal(actual_text, expected_text)?,
        "callback host path differs"
    );
    Ok(())
}
fn site(p: &Profile, role: usize) -> Result<u32> {
    [
        p.worker,
        p.code[62],
        p.code[13],
        p.callback[39],
        p.callback[63],
    ]
    .get(role)
    .copied()
    .ok_or_else(|| anyhow::anyhow!("invalid activation site role"))
}
/// Exact callable CheckActivationProfiles products, including both identities.
pub fn check_activation_profiles() -> Result<()> {
    for (index, p) in PROFILES.iter().enumerate() {
        ensure!(
            select_nullable(None).is_err(),
            "null profile identity admitted"
        );
        ensure!(
            std::ptr::eq(select(p.identity)?, p),
            "profile selection differs"
        );
        let other = &PROFILES[1 - index];
        let hash = p
            .identity
            .split("sha256=")
            .nth(1)
            .unwrap()
            .split(' ')
            .next()
            .unwrap();
        let alternate_hash = other
            .identity
            .split("sha256=")
            .nth(1)
            .unwrap()
            .split(' ')
            .next()
            .unwrap();
        for bad in [
            String::new(),
            format!("{} ", p.identity),
            p.identity.replace("kernel32.dll", "kernelbase.dll"),
            p.identity.replace("sha256=", "sha256=0"),
            p.identity.replace("pe_timestamp=", "pe_timestamp=0"),
            p.identity.replace("image_size=", "image_size=0"),
            p.identity.replace("file_size=", "file_size=0"),
            p.identity.replace(hash, alternate_hash),
        ] {
            ensure!(select(&bad).is_err(), "profile identity mutation admitted");
        }
        let bytes = profile_fixture(p);
        let image = PeImage::parse(&bytes, 1)?;
        activation_boundary_bytes(&image, p)?;
        callback_bytes(&image, p)?;
        ensure!(
            image.activation_worker_slice()?.rva == p.worker,
            "worker differs"
        );
        let expected = if index == 0 {
            [0x24d20, 0x277a8, 0x25a1a, 0x25c1d, 0x25c81]
        } else {
            [0x240d0, 0x26b58, 0x24dca, 0x24fcd, 0x25031]
        };
        for (role, expected) in expected.into_iter().enumerate() {
            ensure!(site(p, role)? == expected, "profile site differs");
        }
        ensure!(
            site(p, 5).is_err()
                && activation_boundary_bytes(&image, other).is_err()
                && callback_bytes(&image, other).is_err()
                && image.require_module_callback_profile().is_err()
                && image.require_activation_profile().is_err(),
            "profile role/full-hash refusal differs"
        );
        for &rva in p.code.iter().chain(p.callback) {
            let mut bad = bytes.clone();
            bad[image.map(rva, 1)?] ^= 1;
            let result = (|| {
                let changed = PeImage::parse(&bad, 1)?;
                activation_boundary_bytes(&changed, p)?;
                callback_bytes(&changed, p)
            })();
            ensure!(result.is_err(), "profile literal mutation admitted");
        }
        for imports in p.imports {
            for (at, set) in [
                (imports.descriptor, false),
                (imports.lookup + imports.count * 8, true),
                (imports.address, false),
                (imports.symbols[0].record, false),
                (imports.symbols[0].record + 2, false),
            ] {
                let mut bad = bytes.clone();
                let at = image.map(at, 1)?;
                if set {
                    bad[at] = 1
                } else {
                    bad[at] ^= 1
                }
                ensure!(
                    (|| callback_bytes(&PeImage::parse(&bad, 1)?, p))().is_err(),
                    "profile import mutation admitted"
                );
            }
        }
        for (at, value) in [
            (0xa8, p.entry + 1),
            (0x110, other.import_directory),
            (0x1ac, 0x40000040),
            (0x190, p.callback[63] - 0x22000 + 4),
            (0x198, p.callback[63] - 0x22000 + 4),
        ] {
            let mut bad = bytes.clone();
            put(&mut bad, at, value);
            ensure!(
                (|| callback_bytes(&PeImage::parse(&bad, 1)?, p))().is_err(),
                "profile header mutation admitted"
            );
        }
        let mut bad = bytes.clone();
        bad[image.map(p.null_descriptor, 1)?] = 1;
        ensure!(
            callback_bytes(&PeImage::parse(&bad, 1)?, p).is_err(),
            "non-null import terminator admitted"
        );
    }
    let p = &PROFILES[1];
    ensure!(
        p.worker == 0x240d0
            && p.code[62] == 0x26b58
            && p.code[13] == 0x24dca
            && p.callback[39] == 0x24fcd
            && p.callback[63] == 0x25031
            && p.edges[4] == 0xead0
            && p.bytes[14] == "E8FF9CFEFF"
            && p.callback_bytes[38] == "48FF15A3600600"
            && p.callback_bytes[62] == "48FF15CF580600",
        "serviced literals differ"
    );
    Ok(())
}
fn callback_fixture() -> Vec<u8> {
    let p = &PROFILES[0];
    let mut b = vec![0; 0xc9000];
    let boundary = super::boundary_checks::fixture();
    b[..boundary.len()].copy_from_slice(&boundary);
    csr::short(&mut b, 0x86, 2);
    for (at, value) in [
        (0xa8, 0x2e1d0),
        (0xd0, 0xca000),
        (0x190, 0xd000),
        (0x198, 0xd000),
        (0x1b8, 0x49000),
        (0x1bc, 0x80000),
        (0x1c0, 0x49000),
        (0x1c4, 0x80000),
        (0x1d4, 0x40000040),
    ] {
        put(&mut b, at, value);
    }
    code(&mut b, p.callback, p.callback_bytes);
    put(&mut b, 0x110, 0xb34bc);
    put(&mut b, 0x114, 0x834);
    fixture_imports(&mut b, p, 0xc0100);
    b
}
fn code(bytes: &mut [u8], rvas: &[u32], encodings: &[&str]) {
    for (&rva, encoding) in rvas.iter().zip(encodings) {
        let literal = decode(encoding).unwrap();
        let at = raw(rva);
        bytes[at..at + literal.len()].copy_from_slice(&literal);
    }
}
fn text(bytes: &mut [u8], at: usize, text: &str) {
    bytes[at..at + text.len()].copy_from_slice(text.as_bytes());
    bytes[at + text.len()] = 0;
}
fn fixture_imports(bytes: &mut [u8], p: &Profile, mut owner: u32) {
    for imports in p.imports {
        let at = raw(imports.descriptor);
        put(bytes, at, imports.lookup);
        put(bytes, at + 12, owner);
        put(bytes, at + 16, imports.address);
        text(bytes, owner as usize, imports.owner);
        owner += 128;
        for index in 0..=imports.count {
            let record = if index == imports.count {
                0u64
            } else {
                0xc0000
            };
            for table in [imports.lookup, imports.address] {
                let at = raw(table + index * 8);
                bytes[at..at + 8].copy_from_slice(&record.to_le_bytes());
            }
        }
        for symbol in imports.symbols {
            for table in [imports.lookup, imports.address] {
                let at = raw(table + symbol.index * 8);
                bytes[at..at + 8].copy_from_slice(&u64::from(symbol.record).to_le_bytes());
            }
            csr::short(bytes, raw(symbol.record), symbol.hint);
            text(bytes, raw(symbol.record + 2), symbol.name);
        }
    }
}
fn profile_fixture(p: &Profile) -> Vec<u8> {
    let mut b = callback_fixture();
    b[0x200..0xd200].fill(0);
    put(&mut b, 0xa8, p.entry);
    code(&mut b, p.code, p.bytes);
    code(&mut b, p.callback, p.callback_bytes);
    put(&mut b, 0x110, p.import_directory);
    put(&mut b, 0x114, 0x834);
    let at = raw(p.import_directory);
    b[at..at + 0x834].fill(0);
    fixture_imports(&mut b, p, 0xc1000);
    put(&mut b, 0x108, 0xc2000);
    put(&mut b, 0x10c, 0x200);
    b[0xc2000..0xc2200].fill(0);
    for (at, value) in [
        (0xc2010, 1),
        (0xc2014, 1),
        (0xc2018, 1),
        (0xc201c, 0xc2040),
        (0xc2020, 0xc2050),
        (0xc2024, 0xc2058),
        (0xc2040, p.worker),
        (0xc2050, 0xc2080),
    ] {
        put(&mut b, at, value);
    }
    text(&mut b, 0xc2080, "CreateActCtxWWorker");
    b
}
pub fn check_module_callback_profile_validation() -> Result<()> {
    check_activation_profiles()?;
    let b = callback_fixture();
    let p = &PROFILES[0];
    let image = PeImage::parse(&b, 1)?;
    activation_boundary_bytes(&image, p)?;
    callback_bytes(&image, p)?;
    ensure!(
        image.entry == 0x2e1d0 && image.full_executable(0x25c81, 5),
        "callback entry/span differs"
    );
    for &rva in p.callback {
        let mut bad = b.clone();
        bad[image.map(rva, 1)?] ^= 1;
        ensure!(
            (|| callback_bytes(&PeImage::parse(&bad, 1)?, p))().is_err(),
            "callback literal mutation admitted"
        );
    }
    for (at, value) in [
        (0xa8, 0x2e1d1),
        (0x114, 0x820),
        (0xb3cdc, 1),
        (0xb34e4, 0xb5c90),
        (0xb3b70, 0x8a890),
        (0x190, 0x3c84),
        (0x1ac, 0x40000040),
    ] {
        let mut bad = b.clone();
        put(&mut bad, at, value);
        ensure!(
            (|| callback_bytes(&PeImage::parse(&bad, 1)?, p))().is_err(),
            "callback header/import mutation admitted"
        );
    }
    for at in [0xc0100, 0xb6a68, 0xbc2fa, 0xb6748, 0x8a8d0] {
        let mut bad = b.clone();
        bad[at] ^= 1;
        ensure!(
            callback_bytes(&PeImage::parse(&bad, 1)?, p).is_err(),
            "callback record mutation admitted"
        );
    }
    let mut bad = b.clone();
    bad[0xb56b8..0xb56c0].copy_from_slice(&1u64.to_le_bytes());
    ensure!(
        callback_bytes(&PeImage::parse(&bad, 1)?, p).is_err()
            && image.require_module_callback_profile().is_err(),
        "callback thunk/full-hash refusal differs"
    );
    let host = super::super::validation::module_activation_validation_fixture(false, false);
    qualify_module_callback_host(&host, &sha256(&host))?;
    ensure!(
        qualify_module_callback_host(&host, "different").is_err(),
        "wrong host digest admitted"
    );
    let dll = super::super::validation::module_activation_validation_fixture(true, true);
    ensure!(
        qualify_module_callback_host(&dll, &sha256(&host)).is_err(),
        "DLL admitted as host"
    );
    let expected = Path::new("fixed")
        .join("module-id2")
        .join("startup-module.exe");
    qualify_module_callback_path(&expected, &expected)?;
    for wrong in [
        Path::new("fixed")
            .join("module-plain")
            .join("startup-module.exe"),
        Path::new("fixed")
            .join("module-id2")
            .join("startup-explicit-id2.exe"),
    ] {
        ensure!(
            qualify_module_callback_path(&wrong, &wrong).is_err(),
            "wrong callback role path admitted"
        );
    }
    ensure!(
        qualify_module_callback_path(Path::new("other"), &expected).is_err(),
        "foreign callback path admitted"
    );
    Ok(())
}
