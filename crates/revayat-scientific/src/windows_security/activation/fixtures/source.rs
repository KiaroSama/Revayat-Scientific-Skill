//! Pinned owned Rust fixture source, replacing immutable C source-format guards.
//! Historical lineage is explicit: no Rust hash or source line is claimed to be C-identical.
use super::{child, io};
use crate::windows_security::activation::self_result::SelfRole;
use anyhow::{Result, ensure};
use std::path::Path;
pub const CHILD: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/security/windows/activation-fixture/src/native/child.rs"
));
pub const SELF_HOST: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/security/windows/activation-fixture/src/native/self_host.rs"
));
pub const ABI: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/security/windows/activation-fixture/src/native/abi.rs"
));
pub const EMIT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/security/windows/activation-fixture/src/native/emit.rs"
));
pub const DEFAULT_HOST: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/security/windows/activation-fixture/src/native/default_host.rs"
));
pub const MODULE_HOST: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/security/windows/activation-fixture/src/native/module_host.rs"
));
pub const MODULE_DLL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/security/windows/activation-fixture/src/native/module_dll.rs"
));
pub const STARTUP_ENTRY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/security/windows/activation-fixture/src/native/startup_entry.rs"
));
pub const MODULE_ENTRY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/security/windows/activation-fixture/src/native/module_entry.rs"
));
pub const BUILTINS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/security/windows/activation-fixture/src/native/builtins.rs"
));
#[path = "source_pins.rs"]
mod pins;
pub use pins::*;
#[path = "source_checks.rs"]
mod checks;
pub use checks::check_self_source_validation;
pub fn owned_directory() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/security/windows/activation-fixture/src/native")
}
pub fn pinned(name: &str) -> Result<(&'static str, &'static str)> {
    Ok(match name {
        "abi.rs" => (ABI, ABI_SHA256),
        "emit.rs" => (EMIT, EMIT_SHA256),
        "builtins.rs" => (BUILTINS, BUILTINS_SHA256),
        "child.rs" => (CHILD, CHILD_SHA256),
        "self_host.rs" => (SELF_HOST, SELF_SHA256),
        "default_host.rs" => (DEFAULT_HOST, DEFAULT_SHA256),
        "module_host.rs" => (MODULE_HOST, MODULE_HOST_SHA256),
        "module_dll.rs" => (MODULE_DLL, MODULE_DLL_SHA256),
        "startup_entry.rs" => (STARTUP_ENTRY, STARTUP_ENTRY_SHA256),
        "module_entry.rs" => (MODULE_ENTRY, MODULE_ENTRY_SHA256),
        _ => anyhow::bail!("unsupported fixed Rust fixture source"),
    })
}
pub fn open_owned(root: &Path, name: &str) -> Result<(io::HeldFile, String)> {
    let (_, expected) = pinned(name)?;
    let mut held = io::HeldFile::open(&root.join(name), 65536)?;
    let mut bytes = held.bytes()?;
    let result = (|| {
        let text = std::str::from_utf8(&bytes)?.replace("\r\n", "\n");
        require_source(&text, expected)?;
        Ok(text)
    })();
    bytes.fill(0);
    match result {
        Ok(text) => Ok((held, text)),
        Err(primary) => match held.close() {
            Ok(()) => Err(primary),
            Err(cleanup) => Err(crate::windows_security::activation::Failures {
                errors: vec![primary, cleanup],
            }
            .into()),
        },
    }
}
pub fn with_owned<T>(
    root: &Path,
    names: &[&str],
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let opens = names
        .iter()
        .map(|name| {
            Box::new(move || open_owned(root, name).map(|(held, _)| held))
                as Box<dyn FnOnce() -> Result<io::HeldFile> + '_>
        })
        .collect();
    let mut lease = super::lease::acquire(opens, super::lease::CloseOrder::Reverse, |_| Ok(()))?;
    let result = operation().and_then(|value| {
        for held in lease.resources() {
            held.verify()?;
        }
        Ok(value)
    });
    match (result, lease.close()) {
        (Err(primary), Err(cleanup)) => Err(crate::windows_security::activation::Failures {
            errors: vec![primary, cleanup],
        }
        .into()),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
}
pub fn directory_link(target: &Path, link: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_dir(target, link)?;
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)?;
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, link);
        anyhow::bail!("fixture link validation requires native platform");
    }
    Ok(())
}
pub fn remove_directory_link(link: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        std::fs::remove_dir(link)?;
    }
    #[cfg(not(windows))]
    {
        std::fs::remove_file(link)?;
    }
    Ok(())
}
pub fn replace_once(text: &str, before: &str, after: &str) -> Result<String> {
    let at = text
        .find(before)
        .ok_or_else(|| anyhow::anyhow!("fixed activation source contract failed"))?;
    ensure!(
        !before.is_empty() && !text[at + before.len()..].contains(before),
        "fixed activation source contract failed"
    );
    Ok(format!(
        "{}{after}{}",
        &text[..at],
        &text[at + before.len()..]
    ))
}
pub fn require_source(text: &str, expected: &str) -> Result<()> {
    ensure!(
        !text.contains('\r') && io::digest(text.as_bytes()) == expected,
        "fixed Rust activation source differs"
    );
    Ok(())
}
pub fn dll_source(text: &str) -> Result<String> {
    require_source(text, CHILD_SHA256)?;
    let text = replace_once(
        text,
        "pub const RESOURCE_ID: u16 = 1;",
        "pub const RESOURCE_ID: u16 = 2;",
    )?;
    replace_once(
        &text,
        "WINDOWS_CHILD_ACTIVATION",
        "WINDOWS_DLL_RESOURCE_ACTIVATION",
    )
}
pub fn self_source(text: &str, role: SelfRole) -> Result<String> {
    require_source(text, SELF_SHA256)?;
    if role == SelfRole::Original {
        return Ok(text.into());
    }
    let text = if role == SelfRole::Manual {
        replace_once(
            text,
            "pub const RESOURCE_ID: u16 = 2;",
            "pub const RESOURCE_ID: u16 = 101;",
        )?
    } else {
        text.into()
    };
    let text = replace_once(&text, "WINDOWS_SELF_ACTIVATION", role.label())?;
    let text = if role == SelfRole::ExplicitId2 {
        replace_once(
            &text,
            "pub const PRE_CALL_RECEIPT: bool = false;",
            "pub const PRE_CALL_RECEIPT: bool = true;",
        )?
    } else {
        text
    };
    require_source(
        &text,
        if role == SelfRole::Manual {
            MANUAL_SHA256
        } else {
            EXPLICIT_SHA256
        },
    )?;
    Ok(text)
}
pub fn resource_bytes(language: u16, id: u16, payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        matches!(id, 1 | 2 | 101) && !payload.is_empty() && payload.len() <= 65536,
        "fixed activation resource contract failed"
    );
    fn header(out: &mut Vec<u8>, length: u32, kind: u16, id: u16, flags: u16, language: u16) {
        out.extend(length.to_le_bytes());
        out.extend(32u32.to_le_bytes());
        for word in [0xffff, kind, 0xffff, id] {
            out.extend(word.to_le_bytes());
        }
        out.extend(0u32.to_le_bytes());
        out.extend(flags.to_le_bytes());
        out.extend(language.to_le_bytes());
        out.extend([0; 8]);
    }
    let mut out = Vec::with_capacity(64 + payload.len() + 3);
    header(&mut out, 0, 0, 0, 0, 0);
    header(&mut out, payload.len() as u32, 24, id, 0x1030, language);
    out.extend(payload);
    out.resize(out.len().next_multiple_of(4), 0);
    Ok(out)
}
pub fn header(path: &Path, language: u16, dll: bool) -> Result<String> {
    child::header(path, language, dll)
}
