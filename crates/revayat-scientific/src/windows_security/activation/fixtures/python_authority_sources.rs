//! Exact separately reviewed authority sources; the one Python glue path is never an extension allowlist.
use super::*;
struct Source {
    name: &'static str,
    text: &'static str,
    digest: &'static str,
}
macro_rules! pinned {
    ($name:literal, $digest:literal) => {
        Source {
            name: $name,
            text: include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/security/windows/python-authority/",
                $name
            )),
            digest: $digest,
        }
    };
}
pub const GLUE_SHA256: &str = "f62db5611e8bf8d43b914b6925f3b2fd2ae6965ad415bb30a6ce173716781d79";
const SOURCES: &[Source] = &[
    pinned!(
        "import_dispatch.py",
        "f62db5611e8bf8d43b914b6925f3b2fd2ae6965ad415bb30a6ce173716781d79"
    ),
    pinned!(
        "src/ascii.rs",
        "f4e988b8633bd527f71f5fb2e05c95eefe06ddc596eb1514a126b89bd51f9b88"
    ),
    pinned!(
        "src/body.rs",
        "a900595d156d7147f955094887e3bdbd30fc03a818ccf21ebcecd06745b40215"
    ),
    pinned!(
        "src/bootstrap.rs",
        "a5698e1da8e2817abfad43806bf0d72c65d1228203645d1c873126afac0a0d20"
    ),
    pinned!(
        "src/child_wire.rs",
        "7eb58a31e526836ac494cfac292b5d0c5ffd69e316f52e57775b30b7f8b5c17b"
    ),
    pinned!(
        "src/classify.rs",
        "3d4d86ac99851453464eea287368df20f7a97f0fb0eab5999e93a52d9aa8ed09"
    ),
    pinned!(
        "src/ctypes.rs",
        "dd6a7866ceb460582d5db2a3819b8baaad000269edf19df54075aa30451b8b72"
    ),
    pinned!(
        "src/descendant.rs",
        "520895a44567e7924e92fb66affc1f7341d471b57b1472d43403fa788ba23f27"
    ),
    pinned!(
        "src/descendant_api.rs",
        "ca1eb995cc8a35617e1afdb1fc905393af2692e3474d95f69c8c068f0ad48c0e"
    ),
    pinned!(
        "src/entry.rs",
        "d56c4b6230d8bece5e786aa783a91c7037cf9fe2518b15b9c4678354bdb83ac5"
    ),
    pinned!(
        "src/failure.rs",
        "c7e9a419f2e8fe8434f76b83ae17589d4e6be459ba240195cf596691b70936d7"
    ),
    pinned!(
        "src/ffi.rs",
        "d891b3f62e5f7646d120fdb135a5a2111881a0a719ee7585f1d3468b9cf42568"
    ),
    pinned!(
        "src/lib.rs",
        "bbfa1892f7b733baf946bba03cb49bdcc7941db66dafa3f3f010e2c7b87452c3"
    ),
    pinned!(
        "src/object.rs",
        "8d1ac255b49ce0063af5734e413de1625acb5fb82082387f1f912ecd2b9d2f6d"
    ),
    pinned!(
        "src/registry.rs",
        "ea07eb7f246397a6bec8fd271553733f32af244186893ae936272c5fb924b317"
    ),
    pinned!(
        "src/small.rs",
        "f2e7c11e8ee6f092b92deb14020dc90f86a107ff2f6e8db46f556e0663187ec6"
    ),
    pinned!(
        "src/token.rs",
        "9a5aed36864a2ee8ecffefa57ff374933706c73603df495ee80e12e177f27b3f"
    ),
    pinned!(
        "src/wide.rs",
        "40bb082e01667ddfb9e0cb4b4be650d219da5a6941c281ebe39c00ed17e7bb8b"
    ),
    pinned!(
        "src/wire.rs",
        "63786acb0c5adf2411f180c66274e62ca8a0b661af3f34cf3562c2f3d6ca9f27"
    ),
];
fn directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/security/windows/python-authority")
}
fn selected(name: &str) -> Result<&'static Source> {
    SOURCES
        .iter()
        .find(|source| source.name == name)
        .ok_or_else(|| anyhow::anyhow!("unsupported fixed authority source"))
}
fn copy(inputs: &mut Inputs, source: &Source, output: &Path) -> Result<()> {
    let path = directory().join(source.name);
    inputs.open(&path, 65536)?;
    let bytes = Bytes(inputs.bytes(&path)?);
    let actual = std::str::from_utf8(&bytes.0)?.replace("\r\n", "\n");
    let expected = source.text.replace("\r\n", "\n");
    ensure!(
        actual == expected
            && !actual.contains('\r')
            && io::digest(actual.as_bytes()) == source.digest,
        "fixed Python authority source differs from reviewed pin"
    );
    inputs.create(output, actual.as_bytes(), 65536)
}
pub(super) fn body(inputs: &mut Inputs, folder: &Path) -> Result<()> {
    for source in SOURCES
        .iter()
        .filter(|source| source.name.starts_with("src/"))
    {
        let name = source.name.strip_prefix("src/").unwrap();
        copy(
            inputs,
            source,
            &folder.join(if name == "lib.rs" { "main.rs" } else { name }),
        )?;
    }
    Ok(())
}
pub(super) fn glue(inputs: &mut Inputs, output: &Path) -> Result<()> {
    copy(inputs, selected("import_dispatch.py")?, output)
}
/// Source identity only. Does not attest compilation, module load or Python observations.
pub fn check_source_validation() -> Result<()> {
    ensure!(
        SOURCES.len() == 19 && selected("import_dispatch.py")?.digest == GLUE_SHA256,
        "fixed authority source set differs"
    );
    for source in SOURCES {
        let normalized = source.text.replace("\r\n", "\n");
        ensure!(
            !normalized.contains('\r') && io::digest(normalized.as_bytes()) == source.digest,
            "embedded authority source pin differs"
        );
    }
    // Canonical shared helpers remain explicitly checked by this carrier after
    // extraction; removing the duplicate probe must not remove its assertion.
    for name in ["builtins.rs", "stack_probe.rs"] {
        let (text, digest) = crate::windows_security::activation::fixtures::source::pinned(name)?;
        let normalized = text.replace("\r\n", "\n");
        ensure!(
            !normalized.contains('\r') && io::digest(normalized.as_bytes()) == digest,
            "embedded authority shared source pin differs"
        );
    }
    Ok(())
}
