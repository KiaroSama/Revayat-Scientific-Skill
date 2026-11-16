//! Automatic executable-ID1 fixture contracts; no claim of Python equivalence.
use super::{io, lease};
use anyhow::{Result, ensure};
use std::path::{Path, PathBuf};
#[path = "default_checks.rs"]
mod checks;
pub use checks::check_default_validation;
pub const ENTRY: &str = "WINDOWS_DEFAULT_ACTIVATION_ENTRY reached=True\n";
pub fn require_role(preflight: bool, others: &[bool]) -> Result<()> {
    ensure!(
        preflight && others.len() == 7 && !others.contains(&true),
        "default activation is a separate fixed undebugged trusted diagnostic"
    );
    Ok(())
}
pub fn resource_script(language: u16) -> String {
    format!(
        "LANGUAGE {},{}\n1 24 \"default-activation-payload.bin\"\n",
        language & 1023,
        language >> 10
    )
}
pub fn resource_compiler(library: &Path) -> Result<PathBuf> {
    let x64 = library
        .parent()
        .ok_or_else(|| anyhow::anyhow!("fixed resource SDK path differs"))?;
    let um = x64
        .parent()
        .ok_or_else(|| anyhow::anyhow!("fixed resource SDK path differs"))?;
    let version = um
        .parent()
        .ok_or_else(|| anyhow::anyhow!("fixed resource SDK path differs"))?;
    let lib = version
        .parent()
        .ok_or_else(|| anyhow::anyhow!("fixed resource SDK path differs"))?;
    let sdk = lib
        .parent()
        .ok_or_else(|| anyhow::anyhow!("fixed resource SDK path differs"))?;
    let text = version.file_name().and_then(|v| v.to_str()).unwrap_or("");
    let numbers = text.split('.').collect::<Vec<_>>();
    ensure!(
        library.is_absolute()
            && library.file_name().and_then(|v| v.to_str()) == Some("kernel32.lib")
            && x64.file_name().and_then(|v| v.to_str()) == Some("x64")
            && um.file_name().and_then(|v| v.to_str()) == Some("um")
            && lib.file_name().and_then(|v| v.to_str()) == Some("Lib")
            && (2..=4).contains(&numbers.len())
            && numbers.iter().all(|v| !v.is_empty()
                && v.bytes().all(|v| v.is_ascii_digit())
                && v.parse::<i32>().is_ok()),
        "fixed resource SDK path differs"
    );
    Ok(sdk.join("bin").join(text).join("x64").join("rc.exe"))
}
pub fn result(exit: u32, text: Option<&str>, errors: Option<&str>) -> Result<String> {
    ensure!(
        text.is_some() && errors == Some(""),
        "fixed default activation contract failed"
    );
    if exit == 0 {
        ensure!(
            text == Some(ENTRY),
            "fixed default activation contract failed"
        );
        return Ok("entry_observed=True exit=0x00000000".into());
    }
    ensure!(
        exit & 0x80000000 != 0 && text == Some(""),
        "fixed default activation contract failed"
    );
    Ok(format!("entry_observed=False exit=0x{exit:08X}"))
}
pub fn condition(condition: &str, value: Option<&str>) -> Result<String> {
    ensure!(
        matches!(condition, "original" | "modified" | "restored"),
        "fixed default activation contract failed"
    );
    let value = value.ok_or_else(|| anyhow::anyhow!("fixed default activation contract failed"))?;
    let absent = value
        .strip_prefix("entry_observed=False exit=0x")
        .filter(|v| v.len() == 8)
        .and_then(|v| u32::from_str_radix(v, 16).ok())
        .filter(|v| v & 0x80000000 != 0);
    ensure!(
        value == "entry_observed=True exit=0x00000000"
            || absent.is_some_and(
                |exit| result(exit, Some(""), Some("")).is_ok_and(|parsed| parsed == value)
            ),
        "fixed default activation contract failed"
    );
    Ok(format!(
        "WINDOWS_DEFAULT_ACTIVATION condition={condition} {value} cause_claimed=False python_equivalence_claimed=False"
    ))
}
pub fn finish<'a>(
    primary: Option<anyhow::Error>,
    actions: Vec<Box<dyn FnMut() -> Result<()> + 'a>>,
) -> Result<()> {
    lease::finish(primary, actions)
}
pub fn require_identity(bytes: &[u8], length: u64, digest: &str) -> Result<()> {
    io::require_identity(bytes, length, digest)
}
