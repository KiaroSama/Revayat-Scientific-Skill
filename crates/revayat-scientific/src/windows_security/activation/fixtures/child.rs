//! Fixed external executable activation request, distinct from Python execution.
use super::io;
use anyhow::{Result, ensure};
use std::path::{Component, Path};
#[path = "child_checks.rs"]
mod checks;
pub use checks::check_child_validation;
pub const SUCCESS: &str = "WINDOWS_CHILD_ACTIVATION created=True win32_error=0x00000000 cause_claimed=False child_equivalence_claimed=False\n";
pub const DENIED: &str = "WINDOWS_CHILD_ACTIVATION created=False win32_error=0x00000005 cause_claimed=False child_equivalence_claimed=False\n";
pub fn require_role(preflight: bool, others: &[bool]) -> Result<()> {
    ensure!(
        preflight && others.len() == 4 && !others.contains(&true),
        "child activation is a separate fixed trusted preflight diagnostic"
    );
    Ok(())
}
pub fn require_diagnostic_role(
    preflight: bool,
    others: &[bool; 4],
    probe: bool,
    trace: bool,
) -> Result<()> {
    ensure!(
        !probe || !trace,
        "activation diagnostic roles cannot overlap"
    );
    if probe || trace {
        require_role(preflight, others)?;
    }
    Ok(())
}
pub fn numeric(units: &[u16]) -> Result<String> {
    ensure!(
        !units.is_empty()
            && units.len() <= 1024
            && !units.contains(&0)
            && String::from_utf16(units).is_ok(),
        "activation build input exceeds fixed UTF-16 text contract"
    );
    Ok(units
        .iter()
        .map(u16::to_string)
        .chain(["0".into()])
        .collect::<Vec<_>>()
        .join(","))
}
pub fn canonical_input(path: &Path, filename: &str) -> Result<()> {
    let normalized = path.components().collect::<std::path::PathBuf>();
    ensure!(
        path.is_absolute()
            && path.as_os_str() == normalized.as_os_str()
            && !path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
            && path.file_name().and_then(|v| v.to_str()) == Some(filename),
        "activation build requires canonical prepared input"
    );
    Ok(())
}
pub fn path_units(path: &Path) -> Result<Vec<u16>> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        Ok(path.as_os_str().encode_wide().collect())
    }
    #[cfg(not(windows))]
    {
        Ok(path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("activation path is not Unicode"))?
            .encode_utf16()
            .collect())
    }
}
pub fn header(path: &Path, language: u16, dll: bool) -> Result<String> {
    canonical_input(path, if dll { "python311.dll" } else { "python.exe" })?;
    let target = numeric(&path_units(path)?)?;
    let directory = numeric(&path_units(path.parent().unwrap())?)?;
    Ok(format!(
        "pub static FIXED_PYTHON: &[u16] = &[{target}];\npub static FIXED_DIRECTORY: &[u16] = &[{directory}];\npub const FIXED_LANGUAGE: u16 = {language};\n"
    ))
}
pub fn require_result(text: Option<&str>) -> Result<String> {
    let text = text
        .filter(|text| text.encode_utf16().count() <= 256)
        .ok_or_else(|| anyhow::anyhow!("child activation result exceeds bound"))?;
    let body = text
        .strip_prefix("WINDOWS_CHILD_ACTIVATION created=")
        .and_then(|text| {
            text.strip_suffix(" cause_claimed=False child_equivalence_claimed=False\n")
        })
        .ok_or_else(|| anyhow::anyhow!("child activation result is missing or malformed"))?;
    let (created, error) = body
        .split_once(" win32_error=0x")
        .ok_or_else(|| anyhow::anyhow!("child activation result is missing or malformed"))?;
    ensure!(
        matches!(created, "True" | "False")
            && error.len() == 8
            && error
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'A'..=b'F').contains(&v)),
        "child activation result is missing or malformed"
    );
    ensure!(
        (created == "True") == (u32::from_str_radix(error, 16)? == 0),
        "child activation result/error is inconsistent"
    );
    Ok(text.trim_end_matches('\n').into())
}
pub fn require_transport(exit: u32, text: Option<&str>, errors: Option<&str>) -> Result<String> {
    ensure!(
        exit == 0 && errors == Some(""),
        "fixed child activation transport failed"
    );
    require_result(text)
}
pub fn compare_trace_result(ordinary: Option<&str>, traced: Option<&str>) -> Result<String> {
    ensure!(
        require_result(ordinary)? == require_result(traced)?,
        "fixed activation returned results differ"
    );
    Ok("WINDOWS_ACTIVATION_COMPARISON returned_result_equal=True debug_equivalence_claimed=False cause_claimed=False".into())
}
pub fn require_prepared(bytes: &[u8], length: u64, expected: &str) -> Result<()> {
    io::require_identity(bytes, length, expected)
}
