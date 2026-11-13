//! Exact bounded self/manual/explicit-ID2 wire and policy projections, with private refusals.
use super::Failures;
use anyhow::{Result, ensure};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelfRole {
    Original,
    Manual,
    ExplicitId2,
}
impl TryFrom<i32> for SelfRole {
    type Error = anyhow::Error;
    fn try_from(value: i32) -> Result<Self> {
        match value {
            0 => Ok(Self::Original),
            1 => Ok(Self::Manual),
            2 => Ok(Self::ExplicitId2),
            _ => anyhow::bail!("unsupported fixed self activation role"),
        }
    }
}
impl SelfRole {
    pub fn label(self) -> &'static str {
        match self {
            Self::Original => "WINDOWS_SELF_ACTIVATION",
            Self::Manual => "WINDOWS_MANUAL_ACTIVATION",
            Self::ExplicitId2 => "WINDOWS_EXPLICIT_ID2_ACTIVATION",
        }
    }
    pub fn stem(self) -> &'static str {
        match self {
            Self::Original => "self-activation",
            Self::Manual => "manual-activation",
            Self::ExplicitId2 => "explicit-id2",
        }
    }
    pub fn image_name(self) -> String {
        format!("startup-{}.exe", self.stem())
    }
    pub fn success(self) -> String {
        format!(
            "{} entry_reached=True created=True win32_error=0x00000000",
            self.label()
        )
    }
    pub fn denied(self) -> String {
        format!(
            "{} entry_reached=True created=False win32_error=0x00000005",
            self.label()
        )
    }
    pub fn script(self, language: u16) -> String {
        format!(
            "LANGUAGE {},{}\n{} 24 \"{}-payload.bin\"\n",
            language & 1023,
            language >> 10,
            if self == Self::Manual { 101 } else { 2 },
            self.stem()
        )
    }
}
pub const PRE_CALL_RECEIPT: &str = "EXPLICIT_ID2_BEFORE_CALL\n";
pub fn observed_pre_call(text: Option<&str>) -> bool {
    text.is_some_and(|text| text.starts_with(PRE_CALL_RECEIPT))
}
fn completed(text: &str, role: SelfRole) -> Option<(bool, u32)> {
    let text = text
        .strip_prefix(&format!("{} entry_reached=True created=", role.label()))?
        .strip_suffix('\n')?;
    let (created, error) = text.split_once(" win32_error=0x")?;
    let created = match created {
        "True" => true,
        "False" => false,
        _ => return None,
    };
    if error.len() != 8
        || !error
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
    {
        return None;
    }
    Some((created, u32::from_str_radix(error, 16).ok()?))
}
fn refuse(
    stage: &str,
    exit: u32,
    text: Option<&str>,
    errors: Option<&str>,
    role: SelfRole,
    emit: &mut impl FnMut(&str) -> Result<()>,
) -> anyhow::Error {
    let primary = anyhow::anyhow!("fixed self activation contract failed");
    let chars = text
        .map(|text| text.encode_utf16().count() as i64)
        .unwrap_or(-1);
    let mut line = format!(
        "{}_REFUSAL stage={stage} raw_process_exit=0x{exit:08X} stdout_chars={chars} stderr_present={}",
        role.label(),
        if errors.is_some_and(|errors| !errors.is_empty()) {
            "True"
        } else {
            "False"
        }
    );
    if role == SelfRole::ExplicitId2 {
        line.push_str(if observed_pre_call(text) {
            " pre_call_receipt_observed=True"
        } else {
            " pre_call_receipt_observed=False"
        });
    }
    match emit(&line) {
        Ok(()) => primary,
        Err(reporting) => Failures {
            errors: vec![primary, reporting],
        }
        .into(),
    }
}
pub fn result(
    exit: u32,
    text: Option<&str>,
    errors: Option<&str>,
    role: SelfRole,
    mut emit: impl FnMut(&str) -> Result<()>,
) -> Result<String> {
    if exit != 0
        || !text.is_some_and(|text| text.encode_utf16().count() <= 128)
        || errors != Some("")
    {
        return Err(refuse("transport", exit, text, errors, role, &mut emit));
    }
    let wire = text.unwrap();
    let completed_wire = if role == SelfRole::ExplicitId2 {
        if !observed_pre_call(text) {
            return Err(refuse("grammar", exit, text, errors, role, &mut emit));
        }
        &wire[PRE_CALL_RECEIPT.len()..]
    } else {
        wire
    };
    let Some((created, error)) = completed(completed_wire, role) else {
        return Err(refuse("grammar", exit, text, errors, role, &mut emit));
    };
    if created != (error == 0) {
        return Err(refuse("consistency", exit, text, errors, role, &mut emit));
    }
    Ok(completed_wire.trim_end_matches('\n').into())
}
pub fn require_host(result: &str, role: SelfRole) -> Result<()> {
    ensure!(
        result == role.success(),
        "fixed self activation contract failed"
    );
    Ok(())
}
pub fn condition(condition: &str, result: Option<&str>, role: SelfRole) -> Result<String> {
    ensure!(
        matches!(condition, "original" | "modified" | "restored"),
        "fixed self activation contract failed"
    );
    let result = result
        .filter(|result| result.encode_utf16().count() <= 127)
        .ok_or_else(|| anyhow::anyhow!("fixed self activation contract failed"))?;
    let (created, error) = completed(&format!("{result}\n"), role)
        .ok_or_else(|| anyhow::anyhow!("fixed self activation contract failed"))?;
    ensure!(
        created == (error == 0),
        "fixed self activation contract failed"
    );
    Ok(format!(
        "{}_CONDITION condition={condition} {result} python_equivalence_claimed=False cause_claimed=False production_grant=False",
        role.label()
    ))
}
pub fn policy_result(
    exit: u32,
    text: &str,
    errors: &str,
    role: SelfRole,
    readable: bool,
) -> Result<String> {
    ensure!(
        matches!(role, SelfRole::Original | SelfRole::ExplicitId2),
        "fixed self activation contract failed"
    );
    if !readable {
        ensure!(
            exit == 0xc0000022 && text.is_empty() && errors.is_empty(),
            "fixed self activation contract failed"
        );
        return Ok("completed_wire=False exit=0xC0000022".into());
    }
    let value = result(exit, Some(text), Some(errors), role, |line| {
        use std::io::Write;
        let mut output = std::io::stdout().lock();
        writeln!(output, "{line}")?;
        output.flush()?;
        Ok(())
    })?;
    require_host(&value, role)?;
    Ok(value)
}
pub fn complete_host(
    role: SelfRole,
    run: impl FnOnce() -> Result<String>,
    close: impl FnOnce() -> Result<()>,
    accept: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let operation = run().and_then(|value| require_host(&value, role));
    let closing = close();
    match (operation, closing) {
        (Ok(()), Ok(())) => accept(),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(Failures {
            errors: vec![primary, cleanup],
        }
        .into()),
    }
}
/// Original SelfActivationFixture.CheckPolicyResultValidation, running the same production parser.
pub fn check_policy_result_validation() -> Result<()> {
    for role in [SelfRole::Original, SelfRole::ExplicitId2] {
        let success = role.success() + "\n";
        let wire = if role == SelfRole::ExplicitId2 {
            PRE_CALL_RECEIPT.to_owned() + &success
        } else {
            success.clone()
        };
        ensure!(
            policy_result(0xc0000022, "", "", role, false)?
                == "completed_wire=False exit=0xC0000022"
                && policy_result(0, &wire, "", role, true)? == success.trim_end_matches('\n'),
            "self activation policy result differs"
        );
        for code in [0, 1, 0xc0150002, u32::MAX] {
            ensure!(
                policy_result(code, "", "", role, false).is_err(),
                "unreadable policy result accepted a different exit"
            );
        }
        ensure!(
            policy_result(0xc0000022, PRE_CALL_RECEIPT, "", role, false).is_err()
                && policy_result(0xc0000022, "", "private-sentinel", role, false).is_err()
                && policy_result(0xc0000022, "", "", role, true).is_err()
                && policy_result(
                    0,
                    &wire
                        .replace("created=True", "created=False")
                        .replace("00000000", "00000005"),
                    "",
                    role,
                    true
                )
                .is_err(),
            "self activation policy transport/result refusal differs"
        );
    }
    ensure!(
        policy_result(0, "", "", SelfRole::Manual, false).is_err(),
        "manual role entered separate self-policy comparison"
    );
    Ok(())
}
