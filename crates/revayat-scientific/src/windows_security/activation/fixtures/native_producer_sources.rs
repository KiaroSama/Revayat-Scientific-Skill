//! Separate tracked source pins for independent native controls and CPython loader glue.
use super::*;
fn directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/security/windows/native-fixtures")
}
fn source(name: &str) -> Result<(&'static str, &'static str)> {
    Ok(match name {
        "startup_native.rs" => (
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/security/windows/native-fixtures/startup_native.rs"
            )),
            "6db6fe0919c4780e4107fa360a28777cfc63fafc96e59745a428e72e13e07f0f",
        ),
        "debug_control.rs" => (
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/security/windows/native-fixtures/debug_control.rs"
            )),
            "94449a5f7f40590de5d8ab37e6ad357e559a304d97f38950397a5752288ff424",
        ),
        "python_abi.rs" => (
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/security/windows/native-fixtures/python_abi.rs"
            )),
            "e45b0eb874e77b8690836ec3f3abfea40af7995c89e4c1c3a790abb87926319a",
        ),
        "registry_loader.rs" => (
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/security/windows/native-fixtures/registry_loader.rs"
            )),
            "02352310c4d54ceffa780eae30b58b080223a0703a547bc12e75ec70f9f0c9d4",
        ),
        _ => anyhow::bail!("unsupported independent native source"),
    })
}
pub(super) fn copy(
    inputs: &mut Inputs,
    output: &Path,
    name: &str,
    destination: &str,
) -> Result<()> {
    let (expected, digest) = source(name)?;
    let path = directory().join(name);
    inputs.open(&path, 65536)?;
    let bytes = Bytes(inputs.bytes(&path)?);
    let normalized = std::str::from_utf8(&bytes.0)?.replace("\r\n", "\n");
    ensure!(
        normalized == expected
            && !normalized.contains('\r')
            && io::digest(normalized.as_bytes()) == digest,
        "independent native source differs from reviewed Rust pin"
    );
    inputs.create(&output.join(destination), normalized.as_bytes(), 65536)
}
