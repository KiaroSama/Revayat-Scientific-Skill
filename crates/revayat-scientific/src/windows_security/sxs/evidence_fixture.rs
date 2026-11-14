//! Shared fixed source-validation fixtures. These functions never produce native evidence.
use super::super::PrivateFailure;
use anyhow::{Result, ensure};
pub(super) const BEGIN: &str = "Begin Activation Context Generation.";
pub(super) const END: &str = "End Activation Context Generation.";
pub(super) fn need(value: bool) -> Result<()> {
    ensure!(value, "fixed SxS source validation failed");
    Ok(())
}
pub(super) fn utf8(text: &str) -> Vec<u8> {
    [&[239, 187, 191][..], text.as_bytes()].concat()
}
pub(super) fn utf16(text: &str) -> Vec<u8> {
    let mut bytes = vec![255, 254];
    for unit in text.encode_utf16() {
        bytes.extend(unit.to_le_bytes());
    }
    bytes
}
pub(super) fn block(manifest: &str, body: &str) -> String {
    format!("{BEGIN}\nManifestPath = {manifest}\n{body}\n{END}\n")
}
pub(super) fn private(error: &anyhow::Error) -> Result<&PrivateFailure> {
    error
        .downcast_ref::<PrivateFailure>()
        .ok_or_else(|| anyhow::anyhow!("expected fixed private SxS failure"))
}
pub(super) fn stage(error: &anyhow::Error) -> Result<&str> {
    Ok(private(error)?.stage())
}
pub(super) fn withheld(error: &anyhow::Error) -> Result<()> {
    need(
        !format!("{error:?}").contains("sentinel")
            && std::error::Error::source(private(error)?).is_none(),
    )
}
