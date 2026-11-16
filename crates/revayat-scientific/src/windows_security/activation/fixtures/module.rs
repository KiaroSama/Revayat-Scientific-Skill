//! Hosted module plain/ID2 pair wire, distinct from active-at-entry attribution.
use super::{io, lease};
use anyhow::{Result, ensure};
use std::path::Path;
#[path = "module_checks.rs"]
mod checks;
pub use checks::check_module_validation;
pub const GOOD: &str = "WINDOWS_MODULE_ACTIVATION attach=1 query_succeeded=1 root_evaluated=1 root_is_module=1 win32_error=0x00000000 returned_bytes=0x00000080 assembly_count=0x00000003\n";
pub const FAILURE: &str = "WINDOWS_MODULE_ACTIVATION attach=1 query_succeeded=0 root_evaluated=0 root_is_module=0 win32_error=0x00000057 returned_bytes=0x00000000 assembly_count=0x00000000\n";
pub fn require_role(preflight: bool, others: &[bool]) -> Result<()> {
    ensure!(
        preflight && others.len() == 8 && !others.contains(&true),
        "module activation is a separate fixed trusted diagnostic"
    );
    Ok(())
}
pub fn script(language: u16) -> String {
    format!(
        "LANGUAGE {},{}\n2 24 \"module-activation-payload.bin\"\n",
        language & 1023,
        language >> 10
    )
}
fn hexadecimal(value: &str) -> Result<u32> {
    ensure!(
        value.len() == 8
            && value
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'A'..=b'F').contains(&v)),
        "fixed module activation contract failed"
    );
    Ok(u32::from_str_radix(value, 16)?)
}
pub fn result(
    manifest: bool,
    exit: u32,
    text: Option<&str>,
    errors: Option<&str>,
) -> Result<String> {
    ensure!(
        text.is_some() && errors == Some(""),
        "fixed module activation contract failed"
    );
    let text = text.unwrap();
    if exit != 0 {
        ensure!(
            manifest && exit & 0x80000000 != 0 && text.is_empty(),
            "fixed module activation contract failed"
        );
        return Ok(format!(
            "entry_observed=False association_proved=False exit=0x{exit:08X}"
        ));
    }
    let words = text
        .strip_suffix('\n')
        .ok_or_else(|| anyhow::anyhow!("fixed module activation contract failed"))?
        .split(' ')
        .collect::<Vec<_>>();
    ensure!(
        words.len() == 8 && words[0] == "WINDOWS_MODULE_ACTIVATION" && words[1] == "attach=1",
        "fixed module activation contract failed"
    );
    let bit = |index: usize, prefix| -> Result<bool> {
        match words[index].strip_prefix(prefix) {
            Some("0") => Ok(false),
            Some("1") => Ok(true),
            _ => anyhow::bail!("fixed module activation contract failed"),
        }
    };
    let query = bit(2, "query_succeeded=")?;
    let evaluated = bit(3, "root_evaluated=")?;
    let own = bit(4, "root_is_module=")?;
    let number = |index: usize, prefix| {
        hexadecimal(
            words[index]
                .strip_prefix(prefix)
                .ok_or_else(|| anyhow::anyhow!("fixed module activation contract failed"))?,
        )
    };
    let error = number(5, "win32_error=0x")?;
    let returned = number(6, "returned_bytes=0x")?;
    let assemblies = number(7, "assembly_count=0x")?;
    ensure!(
        returned <= 65536
            && assemblies <= 16
            && (!own || evaluated)
            && (!evaluated || query && assemblies >= 1)
            && if query {
                error == 0 && returned >= 64
            } else {
                error != 0 && !evaluated && !own && assemblies == 0
            },
        "fixed module activation contract failed"
    );
    ensure!(
        !manifest || query && evaluated && own,
        "fixed module activation contract failed"
    );
    Ok(format!(
        "entry_observed=True association_proved={} exit=0x00000000 {}",
        if own { "True" } else { "False" },
        text.trim_end_matches('\n')
    ))
}
pub fn condition(condition: &str, manifest: bool, value: Option<&str>) -> Result<String> {
    ensure!(
        matches!(condition, "original" | "modified" | "restored"),
        "fixed module activation contract failed"
    );
    let value = value
        .filter(|v| v.encode_utf16().count() <= 512)
        .ok_or_else(|| anyhow::anyhow!("fixed module activation contract failed"))?;
    let mut qualified = false;
    for own in ["True", "False"] {
        if let Some(text) = value.strip_prefix(&format!(
            "entry_observed=True association_proved={own} exit=0x00000000 "
        )) {
            qualified = result(manifest, 0, Some(&format!("{text}\n")), Some(""))? == value;
        }
    }
    if let Some(exit) = value.strip_prefix("entry_observed=False association_proved=False exit=0x")
    {
        qualified = result(manifest, hexadecimal(exit)?, Some(""), Some(""))? == value;
    }
    ensure!(qualified, "fixed module activation contract failed");
    Ok(format!(
        "WINDOWS_MODULE_CONDITION condition={condition} pair={} {value} active_at_entry_claimed=False python_equivalence_claimed=False cause_claimed=False",
        if manifest {
            "module-id2"
        } else {
            "module-plain"
        }
    ))
}
pub fn require_unentered(value: &str) -> Result<u32> {
    condition("modified", true, Some(value))?;
    let code = value
        .strip_prefix("entry_observed=False association_proved=False exit=0x")
        .ok_or_else(|| anyhow::anyhow!("fixed module activation contract failed"))?;
    let code = hexadecimal(code)?;
    ensure!(
        code & 0x80000000 != 0,
        "fixed module activation contract failed"
    );
    Ok(code)
}
pub fn compare_callback(
    expected: u32,
    actual: u32,
    text: Option<&str>,
    errors: Option<&str>,
) -> Result<String> {
    ensure!(
        expected & 0x80000000 != 0 && expected == actual,
        "fixed module activation contract failed"
    );
    require_unentered(&result(true, actual, text, errors)?)?;
    Ok("WINDOWS_MODULE_CALLBACK returned_exit_equal=True observation_only=True cause_claimed=False".into())
}
