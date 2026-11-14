//! CheckImportValidation's original fixture products and diagnostic categories.
use super::*;
pub fn check_import_validation() -> Result<()> {
    let mut b = base();
    for (at, n) in [
        (0x110, 0x1000),
        (0x114, 40),
        (0x200, 0x1080),
        (0x20c, 0x1060),
        (0x210, 0x1080),
    ] {
        put(&mut b, at, n);
    }
    text(&mut b, 0x260, "KERNEL32.dll\0");
    ensure!(
        PeImage::parse(&b, 1)?.direct_imports()? == ["kernel32.dll"],
        "original direct-import positive differs"
    );
    refuse(
        &b,
        &[
            Word(0x114, 39),
            Word(0x114, 2600),
            Word(0x20c, u32::MAX),
            Byte(0x260, b'\\'),
            Word(0x224, 1),
            Word(0x170, 0x1000),
            Word(0x210, 0),
            Zero(0x200, 20),
        ],
        |bad| PeImage::parse(bad, 1)?.direct_imports().map(|_| ()),
    )?;
    ensure!(
        PeImage::parse(&b, 1)?
            .qualify_python_imports("python-exe")
            .is_err(),
        "Python import drift accepted"
    );
    let python = imports(&[
        "KERNEL32.dll",
        "python311.dll",
        "VCRUNTIME140.dll",
        "api-ms-win-crt-runtime-l1-1-0.dll",
    ]);
    ensure!(
        PeImage::parse(&python, 1)?.qualify_python_imports("python-exe")? == 1,
        "Python API-set count differs"
    );
    let mut authority = imports(&["KERNEL32.dll", "ntdll.dll", "advapi32.dll"]);
    short(&mut authority, 0x96, 2);
    short(&mut authority, 0xdc, 3);
    qualify_registry_authority(&authority)?;
    let mut sync = imports(&[
        "KERNEL32.dll",
        "ntdll.dll",
        "advapi32.dll",
        "api-ms-win-core-synch-l1-2-0.dll",
    ]);
    short(&mut sync, 0x96, 2);
    short(&mut sync, 0xdc, 3);
    qualify_registry_authority(&sync)?;
    let cases = [
        (Short(0x84, 0x14c), "header refused stage=pe-header"),
        (Short(0x96, 0x2002), "PE refused stage=executable"),
        (Short(0xdc, 2), "PE refused stage=executable"),
        (Word(0xa8, 0), "PE refused stage=executable"),
        (Word(0x178, 0x1000), "PE refused stage=clr"),
        (
            Text(0x300, "libffi-8.dll\0"),
            "PE refused stage=import-profile",
        ),
        (
            Group(vec![Word(0x20c, 0x1180), Text(0x380, "vcruntime140.dll\0")]),
            "PE refused stage=import-profile",
        ),
        (Word(0x114, 39), "import refused stage=directory-shape"),
        (Word(0x110, u32::MAX), "import refused stage=directory-map"),
        (Word(0x170, 0x1000), "import refused stage=delay-import"),
        (Byte(0x300, b'\\'), "import refused stage=name-character"),
        (Word(0x210, 0), "import refused stage=descriptor"),
        (
            Group(vec![Word(0x114, 100), Byte(0x25f, 1)]),
            "import refused stage=directory-tail",
        ),
        (
            Group(vec![Word(0x114, 60), Copy(0x200, 0x214, 20)]),
            "import refused stage=name-shape-or-duplicate",
        ),
        (
            Group(vec![
                Word(0x20c, 0x1180),
                Text(0x380, "synchronization.dll\0"),
            ]),
            "PE refused stage=import-profile",
        ),
    ];
    for (change, predicate) in cases {
        let mut bad = authority.clone();
        apply(&mut bad, &change);
        let error = qualify_registry_authority(&bad)
            .err()
            .ok_or_else(|| anyhow::anyhow!("original authority import mutation accepted"))?;
        let expected = format!("fixed Rust registry authority {predicate}");
        let mut observed = false;
        for cause in error.chain() {
            let message = cause.to_string();
            observed |= message == expected;
            ensure!(
                !["libffi", "vcruntime", "api-ms-win", "private"]
                    .iter()
                    .any(|text| message.contains(text)),
                "private import diagnostic escaped"
            );
        }
        ensure!(observed, "original authority diagnostic category differs");
    }
    for name in [
        "api-ms-win-core-synch-l1-2-1.dll",
        "api-ms-win-core-synch-l1-2-0-extra.dll",
        "unexpected.dll",
    ] {
        let mut bad = imports(&["KERNEL32.dll", "ntdll.dll", "advapi32.dll", name]);
        short(&mut bad, 0x96, 2);
        short(&mut bad, 0xdc, 3);
        ensure!(
            qualify_registry_authority(&bad)
                .err()
                .is_some_and(|error| error.to_string()
                    == "fixed Rust registry authority PE refused stage=import-profile"),
            "authority import alias accepted"
        );
    }
    ensure!(
        PeImage::parse(&imports(&["KERNEL32.dll"]), 1)?.qualify_python_imports("vcruntime140")?
            == 0,
        "runtime import count differs"
    );
    ensure!(
        PeImage::parse(
            &imports(&[
                "ADVAPI32.dll",
                "bcrypt.dll",
                "KERNEL32.dll",
                "VCRUNTIME140.dll",
                "VERSION.dll",
                "WS2_32.dll"
            ]),
            1
        )?
        .qualify_python_imports("python311")?
            == 0,
        "Python DLL imports differ"
    );
    let long = "a".repeat(128) + ".dll";
    for names in [
        vec!["KERNEL32.dll", "kernel32.dll"],
        vec!["C:\\private\\secret.dll"],
        vec!["kernel32.dll", "unexpected.dll"],
        vec![long.as_str()],
    ] {
        ensure!(
            PeImage::parse(&imports(&names), 1)?
                .qualify_python_imports("vcruntime140")
                .is_err(),
            "invalid Python import profile accepted"
        );
    }
    Ok(())
}
