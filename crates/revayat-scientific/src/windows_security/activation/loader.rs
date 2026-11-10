//! Finite loader-output decoder. Opaque paths and addresses are never returned.
use anyhow::{Result, ensure};
const ROUTINES: [&str; 5] = [
    "LdrpCallInitRoutine",
    "LdrpInitializeProcess",
    "LdrpInitializeNode",
    "LdrInitializeThunk",
    "BaseDllInitialize",
];
const MODULES: [&str; 4] = [
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "startup-native.exe",
];
const TEMPLATES: [(&str, &str, &str); 8] = [
    (
        "dll_manifest_probe_failed",
        "Probing for the manifest of DLL \"",
        "\" failed with status ",
    ),
    (
        "active_actctx_query_failed",
        "Querying the active activation context failed with status ",
        "",
    ),
    (
        "sxs_registry_key_open_failed",
        "SXS: Unable to open registry key ",
        " Status = ",
    ),
    (
        "sxs_storage_root_subkey_open_failed",
        "SXS: Unable to open storage root subkey ",
        "; Status = ",
    ),
    (
        "sxs_storage_map_resolution_failed",
        "SXS: RtlGetAssemblyStorageRoot() unable to resolve storage map entry.  Status = ",
        "",
    ),
    (
        "current_directory_init_failed",
        "Initializing the current directory to \"",
        "\" failed with status ",
    ),
    (
        "kernel32_functions_init_failed",
        "Calling LdrpInitializeKernel32Functions failed with status ",
        "",
    ),
    (
        "code_authz_init_failed",
        "LdrpCodeAuthzInitialize failed with status ",
        "",
    ),
];
fn token_character(value: char) -> bool {
    value.is_alphanumeric() || value == '_' || value == '.'
}
fn has_token(text: &str, value: &str) -> bool {
    text.char_indices().any(|(at, _)| {
        text.get(at..at + value.len())
            .is_some_and(|s| s.eq_ignore_ascii_case(value))
            && text[..at]
                .chars()
                .next_back()
                .is_none_or(|c| !token_character(c))
            && text[at + value.len()..]
                .chars()
                .next()
                .is_none_or(|c| !token_character(c))
    })
}
pub fn classify(bytes: &[u8], unicode: u16) -> Result<String> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= 4096 && unicode <= 1,
        "loader debug string shape differs"
    );
    let text = if unicode == 1 {
        ensure!(
            bytes.len() >= 2 && bytes.len() % 2 == 0 && bytes.ends_with(&[0, 0]),
            "loader UTF-16 span differs"
        );
        let mut units = bytes[..bytes.len() - 2]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        let text = String::from_utf16(&units)
            .map_err(|_| anyhow::anyhow!("loader UTF-16 encoding differs"));
        units.fill(0);
        text?
    } else {
        ensure!(
            bytes.last() == Some(&0) && bytes.is_ascii(),
            "loader ASCII span differs"
        );
        String::from_utf8(bytes[..bytes.len() - 1].to_vec())?
    };
    ensure!(
        !text.contains('\0'),
        "loader debug string has embedded terminator"
    );
    let routine = ROUTINES.iter().find(|value| has_token(&text, value));
    let module = MODULES.iter().find(|value| has_token(&text, value));
    let mut statuses = Vec::new();
    for (at, _) in text.char_indices() {
        if statuses.len() == 4 {
            break;
        }
        if !text
            .get(at..at + 6)
            .is_some_and(|value| value.eq_ignore_ascii_case("status"))
            || text[..at].chars().next_back().is_some_and(token_character)
        {
            continue;
        }
        let tail = text[at + 6..].trim_start_matches(' ');
        let Some(tail) = tail.strip_prefix('=').or_else(|| tail.strip_prefix(':')) else {
            continue;
        };
        let tail = tail.trim_start_matches(' ');
        let Some(number) = tail.get(..10) else {
            continue;
        };
        if number.as_bytes()[..2].eq_ignore_ascii_case(b"0x")
            && number.as_bytes()[2..].iter().all(u8::is_ascii_hexdigit)
            && tail[10..]
                .chars()
                .next()
                .is_none_or(|c| !token_character(c))
        {
            statuses.push(format!("0x{}", number[2..].to_ascii_uppercase()));
        }
    }
    let phase = if !statuses.is_empty() || has_token(&text, "error") || has_token(&text, "failed") {
        "failure"
    } else if routine.is_some() {
        "initializer"
    } else {
        "unknown"
    };
    let mut output = format!("phase={phase} format_valid=True");
    if let Some(routine) = routine {
        output.push_str(&format!(" routine={routine}"));
    }
    if let Some(module) = module {
        output.push_str(&format!(" module={module}"));
    }
    if !statuses.is_empty() {
        output.push_str(&format!(" status={}", statuses.join(",")));
    }
    Ok(output)
}
fn digits(text: &str, minimum: usize, maximum: usize, hex: bool) -> bool {
    (minimum..=maximum).contains(&text.len())
        && text.bytes().all(|b| {
            if hex {
                b.is_ascii_hexdigit()
            } else {
                b.is_ascii_digit()
            }
        })
}
fn record(text: &str) -> Option<&str> {
    if text.is_empty() || text.len() > 4096 {
        return None;
    }
    let text = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    if text.contains(['\r', '\n', '\0']) {
        return None;
    }
    let Some((wrapper, text)) = text.split_once(" - ERROR: ") else {
        return Some(text);
    };
    let (ids, remainder) = wrapper.split_once(" @ ")?;
    let (clock, routine) = remainder.split_once(" - ")?;
    let (pid, tid) = ids.split_once(':')?;
    if !digits(pid, 4, 8, true)
        || !digits(tid, 4, 8, true)
        || !digits(clock, 8, 10, false)
        || routine.is_empty()
        || routine.len() > 96
        || !routine
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        || text.contains(" - ERROR: ")
    {
        return None;
    }
    Some(text)
}
fn opaque(text: &str, quoted: bool) -> bool {
    !text.is_empty()
        && !text.to_ascii_lowercase().contains("0x")
        && !text
            .chars()
            .any(|c| c.is_control() || c == '\u{2028}' || c == '\u{2029}' || quoted && c == '"')
        && TEMPLATES.iter().all(|(_, first, last)| {
            !text.contains(first) && (last.is_empty() || !text.contains(last))
        })
}
pub fn failure_template(text: &str) -> Option<String> {
    let record = record(text)?;
    let split = record.len().checked_sub(10)?;
    let (Some(body), Some(number)) = (record.get(..split), record.get(split..)) else {
        return None;
    };
    let digits = number.strip_prefix("0x")?;
    if digits.len() != 8 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut selected = None;
    for (id, first, last) in TEMPLATES {
        let matched = if last.is_empty() {
            body == first
        } else {
            body.strip_prefix(first)
                .and_then(|value| value.strip_suffix(last))
                .is_some_and(|value| opaque(value, first.ends_with('"')))
        };
        if matched {
            if selected.is_some() {
                return None;
            }
            selected = Some(id);
        }
    }
    Some(format!(
        "diagnostic_template={} diagnostic_status32=0x{} diagnostic_cause_claimed=False",
        selected?,
        digits.to_ascii_uppercase()
    ))
}
#[derive(Default)]
pub struct DebugStringBudget {
    original_seen: bool,
    requested: usize,
}
impl DebugStringBudget {
    pub fn take(&mut self, fixed_native_or_clone: bool) -> bool {
        if fixed_native_or_clone {
            return true;
        }
        if self.original_seen {
            return false;
        }
        self.original_seen = true;
        true
    }
    pub fn charge(&mut self, length: usize) -> Result<()> {
        ensure!(
            (1..=4096).contains(&length) && self.requested <= 65536 - length,
            "loader requested-byte budget exceeded"
        );
        self.requested += length;
        Ok(())
    }
    pub fn requested(&self) -> usize {
        self.requested
    }
}
pub fn accept_initial(
    thread: u32,
    creator: u32,
    code: u32,
    first: bool,
    seen: bool,
    complete: impl FnOnce() -> Result<()>,
) -> Result<bool> {
    if thread != creator || code != 0x80000003 || !first || seen {
        return Ok(false);
    }
    complete()?;
    Ok(true)
}
