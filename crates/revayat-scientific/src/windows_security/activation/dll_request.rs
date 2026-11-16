//! Exact fixed child DLL-file resource request wire; never a Python-equivalence assertion.
use anyhow::{Result, ensure};
pub const LABEL: &str = "WINDOWS_DLL_RESOURCE_ACTIVATION";
pub const SUCCESS: &str = "WINDOWS_DLL_RESOURCE_ACTIVATION created=True win32_error=0x00000000 cause_claimed=False child_equivalence_claimed=False";
pub const DENIAL: &str = "WINDOWS_DLL_RESOURCE_ACTIVATION created=False win32_error=0x00000005 cause_claimed=False child_equivalence_claimed=False";
pub fn result(exit: u32, text: Option<&str>, errors: Option<&str>) -> Result<String> {
    ensure!(
        exit == 0
            && text.is_some_and(|text| text.encode_utf16().count() <= 256)
            && errors == Some(""),
        "fixed DLL resource request contract failed"
    );
    let text = text.unwrap();
    let body = text
        .strip_prefix("WINDOWS_DLL_RESOURCE_ACTIVATION created=")
        .and_then(|body| {
            body.strip_suffix(" cause_claimed=False child_equivalence_claimed=False\n")
        })
        .ok_or_else(|| anyhow::anyhow!("fixed DLL resource request contract failed"))?;
    let (created, error) = body
        .split_once(" win32_error=0x")
        .ok_or_else(|| anyhow::anyhow!("fixed DLL resource request contract failed"))?;
    ensure!(
        matches!(created, "True" | "False")
            && error.len() == 8
            && error
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)),
        "fixed DLL resource request contract failed"
    );
    let error = u32::from_str_radix(error, 16)?;
    ensure!(
        (created == "True") == (error == 0),
        "fixed DLL resource request contract failed"
    );
    Ok(text.trim_end_matches('\n').into())
}
pub fn condition(condition: &str, value: Option<&str>) -> Result<String> {
    ensure!(
        matches!(condition, "original" | "modified" | "restored"),
        "fixed DLL resource request contract failed"
    );
    let value = value
        .filter(|value| value.encode_utf16().count() < 256)
        .ok_or_else(|| anyhow::anyhow!("fixed DLL resource request contract failed"))?;
    ensure!(
        result(0, Some(&format!("{value}\n")), Some(""))? == value,
        "fixed DLL resource request contract failed"
    );
    Ok(format!(
        "{LABEL}_CONDITION condition={condition} {value} python_equivalence_claimed=False cause_claimed=False production_grant=False"
    ))
}
/// The wire assertions used by original CheckDllValidation, independent of legacy C source builds.
pub fn check_wire_validation() -> Result<()> {
    let good = SUCCESS.to_owned() + "\n";
    let denied = DENIAL.to_owned() + "\n";
    ensure!(
        result(0, Some(&good), Some(""))? == SUCCESS
            && result(0, Some(&denied), Some(""))? == DENIAL,
        "DLL request literal result differs"
    );
    for bad in [
        String::new(),
        good.clone() + &good,
        good.trim_end_matches('\n').into(),
        good.replace("00000000", "00000005"),
        denied.replace("00000005", "00000000"),
        denied.replace("00000005", "ffffffff"),
        good.replace("DLL_RESOURCE", "CHILD"),
        good.replace('\n', "\r\n"),
        "private-sentinel".into(),
        "x".repeat(257),
    ] {
        ensure!(
            result(0, Some(&bad), Some("")).is_err(),
            "malformed DLL request wire accepted"
        );
    }
    for exit in [1, 120, 121, 0xc0000022, u32::MAX] {
        ensure!(
            result(exit, Some(&good), Some("")).is_err(),
            "DLL request transport exit accepted"
        );
    }
    ensure!(result(0,Some(&good),Some("private-sentinel")).is_err()
        && result(0,Some("WINDOWS_CHILD_ACTIVATION created=True win32_error=0x00000000 cause_claimed=False child_equivalence_claimed=False\n"),Some("")).is_err()
        && condition("private-sentinel",Some(SUCCESS)).is_err() && condition("original",Some("private-sentinel")).is_err(),
        "DLL request transport or role/condition confusion accepted");
    ensure!(
        condition("original", Some(SUCCESS))?
            == format!(
                "{LABEL}_CONDITION condition=original {SUCCESS} python_equivalence_claimed=False cause_claimed=False production_grant=False"
            ),
        "DLL request condition metadata differs"
    );
    Ok(())
}
