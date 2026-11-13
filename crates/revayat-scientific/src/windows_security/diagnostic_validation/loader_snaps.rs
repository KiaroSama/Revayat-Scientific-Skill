//! LoaderSnaps bounded ownership and redacted debug-string contracts. No registry
//! configuration or remote read is inferred from a successful portable check.
use crate::windows_security::activation::loader;
use anyhow::{Result, ensure};
use std::path::Path;
#[path = "loader_snaps_checks.rs"]
mod checks;
#[path = "loader_phrases.rs"]
mod phrases;
pub use checks::check_loader_snaps_validation;
pub use phrases::phrase_presence;

const ROUTINES: [&str; 5] = [
    "LdrpCallInitRoutine",
    "LdrpInitializeProcess",
    "LdrpInitializeNode",
    "LdrInitializeThunk",
    "BaseDllInitialize",
];
const MODULES: [&str; 18] = [
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "startup-native.exe",
    "python.exe",
    "python311.dll",
    "ucrtbase.dll",
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    "version.dll",
    "ws2_32.dll",
    "pathcch.dll",
    "bcrypt.dll",
    "comctl32.dll",
    "advapi32.dll",
    "shell32.dll",
    "ole32.dll",
    "oleaut32.dll",
];
fn token_character(value: char) -> bool {
    value.is_alphanumeric() || matches!(value, '_' | '.')
}
fn has_token(text: &str, value: &str) -> bool {
    text.char_indices().any(|(at, _)| {
        text.get(at..at + value.len())
            .is_some_and(|tail| tail.eq_ignore_ascii_case(value))
            && text[..at]
                .chars()
                .next_back()
                .is_none_or(|c| !token_character(c))
            && text
                .get(at + value.len()..)
                .is_some_and(|tail| tail.chars().next().is_none_or(|c| !token_character(c)))
    })
}
fn decode(bytes: &[u8], unicode: u16) -> Option<String> {
    if bytes.is_empty() || bytes.len() > 4096 || unicode > 1 {
        return None;
    }
    let text = if unicode == 1 {
        if bytes.len() < 2 || !bytes.len().is_multiple_of(2) || !bytes.ends_with(&[0, 0]) {
            return None;
        }
        let mut units = bytes[..bytes.len() - 2]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|v| u16::from_le_bytes(*v))
            .collect::<Vec<_>>();
        let text = String::from_utf16(&units).ok();
        units.fill(0);
        text?
    } else {
        if bytes.last() != Some(&0) || !bytes.is_ascii() {
            return None;
        }
        String::from_utf8(bytes[..bytes.len() - 1].to_vec()).ok()?
    };
    if text.contains('\0') {
        None
    } else {
        Some(text)
    }
}
pub fn classify_loader_string(bytes: &[u8], unicode: u16, python: bool) -> String {
    if !python {
        return loader::classify(bytes, unicode)
            .unwrap_or_else(|_| "phase=unknown format_valid=False".into());
    }
    let Some(text) = decode(bytes, unicode) else {
        return "phase=unknown format_valid=False".into();
    };
    let routine = ROUTINES.iter().find(|routine| has_token(&text, routine));
    let phase = if has_token(&text, "error") || has_token(&text, "failed") {
        "failure"
    } else if routine.is_some() {
        "initializer"
    } else {
        "unknown"
    };
    format!(
        "phase={phase} format_valid=True{}{}",
        routine.map_or_else(String::new, |routine| format!(" routine={routine}")),
        python_evidence(&text)
    )
}
pub fn python_evidence(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let ordered = |first: &str, second: &str| {
        lower
            .find(&first.to_ascii_lowercase())
            .is_some_and(|at| lower[at + first.len()..].contains(&second.to_ascii_lowercase()))
    };
    let mut kinds = Vec::new();
    if ordered(
        "LdrpProcessWork - ERROR: Unable to load DLL:",
        "Parent Module:",
    ) {
        kinds.push("dll_load_failure");
    }
    if lower.contains("activation context generation failed") {
        kinds.push("activation_context_failure");
    }
    if ordered("Dependent Assembly", "could not be found") {
        kinds.push("assembly_resolution_failure");
    }
    if ordered("LDR: Process initialization failure for", "NTSTATUS") {
        kinds.push("process_initialization_wording_candidate");
    }
    let mentions = MODULES
        .iter()
        .filter(|name| has_token(text, name))
        .copied()
        .collect::<Vec<_>>();
    format!(
        "{}{} access_denied_literal_present={}{}{}",
        if kinds.is_empty() {
            String::new()
        } else {
            format!(" message_kind={}", kinds.join(","))
        },
        if mentions.is_empty() {
            String::new()
        } else {
            format!(" module_mentioned={}", mentions.join(","))
        },
        super::boolean(has_token(text, "C0000022") || has_token(text, "0xC0000022")),
        phrase_presence(text),
        loader::failure_template(text).map_or_else(String::new, |value| format!(" {value}"))
    )
}
fn identifier(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
pub fn image_name(python: bool) -> &'static str {
    if python {
        "startup-python.exe"
    } else {
        "startup-native.exe"
    }
}
pub fn binding(run: &str, nonce: &str, python: bool) -> Result<String> {
    ensure!(
        identifier(run) && identifier(nonce),
        "loader-snaps ownership identifiers are invalid"
    );
    Ok(format!(
        "Scientific.Security.LoaderSnaps:{}{run}:{nonce}",
        if python { "python-pass:" } else { "" }
    ))
}
pub fn receipt(run: &str, nonce: &str, python: bool) -> Result<String> {
    binding(run, nonce, python)?;
    Ok(format!(
        "loader-snaps-v1\n{}\n{run}\n{nonce}\n",
        image_name(python)
    ))
}
pub fn parse_receipt(text: &str, run: &str, python: bool) -> Result<String> {
    ensure!(
        text.len() <= 256,
        "loader-snaps ownership receipt exceeds fixed bound"
    );
    let parts = text.split('\n').collect::<Vec<_>>();
    ensure!(
        parts.len() == 5
            && parts[0] == "loader-snaps-v1"
            && parts[1] == image_name(python)
            && parts[2] == run
            && parts[4].is_empty(),
        "loader-snaps ownership receipt does not name this fixed run/image"
    );
    binding(run, parts[3], python)
}
pub fn require_state(run: &str, state: &Path) -> Result<()> {
    ensure!(
        identifier(run)
            && state.is_absolute()
            && state.file_name().and_then(|v| v.to_str())
                == Some(format!("security-windows-{run}").as_str()),
        "loader-snaps state is not this run's fixed owned directory"
    );
    Ok(())
}
