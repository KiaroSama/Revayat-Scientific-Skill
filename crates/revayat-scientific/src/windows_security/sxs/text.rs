//! Strict standard-tool text decoding and separate failed-consumer/collector-positive contracts.
use anyhow::{Result, ensure};
use regex::Regex;
#[path = "evidence_codec_validation.rs"]
mod codec_validation;
#[path = "evidence.rs"]
mod evidence;
#[path = "evidence_fixture.rs"]
mod fixture;
#[path = "evidence_length_validation.rs"]
mod length_validation;
#[path = "evidence_selection_validation.rs"]
mod selection_validation;
#[path = "evidence_stream_validation.rs"]
mod stream;
#[path = "evidence_validation.rs"]
mod validation;
use evidence::check_stage as check;
pub use evidence::{EvidenceRead, LengthPhase, read_owned, require_length};
pub use validation::{check_evidence_validation, check_reporting_validation};

const BEGIN: &str = "Begin Activation Context Generation.";
const END: &str = "End Activation Context Generation.";
const UNRESOLVED: &str = "ERROR: Cannot resolve reference ";
pub fn decode_lines(bytes: &[u8]) -> Result<Vec<String>> {
    evidence::decode_optional(Some(bytes))
}
pub fn known_dependency(identity: &str) -> bool {
    Regex::new(r#"\A(?:Microsoft\.Windows\.Common-Controls|Microsoft\.VC(?:80|90|100|110|120|140)\.CRT)(?:,[A-Za-z]+="[A-Za-z0-9.*_-]{1,64}"){0,6}\.?\z"#)
        .is_ok_and(|pattern| pattern.is_match(identity))
}
fn boolean(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}
#[derive(Default)]
struct Flags {
    unresolved: bool,
    denied: bool,
    malformed: bool,
    failed: bool,
    common: bool,
    crt: bool,
    unsupported: bool,
}
impl Flags {
    fn observe(&mut self, line: &str) {
        if let Some(identity) = line.strip_prefix(UNRESOLVED) {
            if known_dependency(identity) {
                self.unresolved = true;
                self.common |= identity.starts_with("Microsoft.Windows.Common-Controls");
                self.crt |= identity.starts_with("Microsoft.VC");
            } else {
                self.unsupported = true;
            }
        }
        let denied = line == "ERROR: Access is denied.";
        let malformed = line.starts_with("ERROR: Manifest Parse Error");
        let failed = line == "ERROR: Activation Context generation failed.";
        if line.starts_with("ERROR:")
            && !line.starts_with(UNRESOLVED)
            && !denied
            && !malformed
            && !failed
        {
            self.unsupported = true;
        }
        if let Some(identity) = line.strip_prefix("INFO: Reference: ") {
            self.unsupported |= !known_dependency(identity);
        }
        self.denied |= denied;
        self.malformed |= malformed;
        self.failed |= failed;
    }
    fn output(&self) -> String {
        format!(
            "unresolved_reference={} access_denied={} manifest_parse={} activation_failed={} common_controls={} vc_crt={}",
            boolean(self.unresolved),
            boolean(self.denied),
            boolean(self.malformed),
            boolean(self.failed),
            boolean(self.common),
            boolean(self.crt)
        )
    }
}
pub fn failure_evidence(bytes: &[u8], manifest: &str) -> Result<String> {
    failure_evidence_optional(Some(bytes), manifest)
}
fn failure_evidence_optional(bytes: Option<&[u8]>, manifest: &str) -> Result<String> {
    let lines = evidence::decode_optional(bytes)?;
    let (mut inside, mut selected) = (false, false);
    let (mut blocks, mut matches, mut fields) = (0, 0, 0);
    let mut flags = Flags::default();
    let mut result = None;
    for raw in &lines {
        let line = raw.trim_matches([' ', '\t']);
        if line == BEGIN {
            check(!inside, "evidence-nested")?;
            blocks += 1;
            check(blocks <= 64, "evidence-block-count")?;
            inside = true;
            selected = false;
            fields = 0;
            flags = Flags::default();
            continue;
        }
        if line == END {
            check(inside, "evidence-end")?;
            inside = false;
            if selected {
                matches += 1;
                if let Err(original) = check(matches == 1, "evidence-selected-count") {
                    // The first result and both flag strings contain only fixed boolean projections.
                    let stage = format!(
                        "evidence-selected-count selected_observed=2 total_matches=unknown first_qualified=True first_flags=[{}] second_qualified=False second_flags=[{}] second_unsupported={} further_blocks_examined=False",
                        result.as_deref().unwrap_or(""),
                        flags.output(),
                        boolean(flags.unsupported)
                    );
                    return Err(evidence::private(original, stage));
                }
                check(fields == 1, "evidence-manifest-count")?;
                check(!flags.unsupported, "evidence-unsupported")?;
                check(
                    flags.unresolved || flags.denied || flags.malformed || flags.failed,
                    "evidence-empty",
                )?;
                result = Some(flags.output());
            }
            continue;
        }
        if !inside {
            check(
                line.is_empty() || line.bytes().all(|b| b == b'='),
                "evidence-framing",
            )?;
            continue;
        }
        if let Some(path) = line.strip_prefix("ManifestPath = ") {
            fields += 1;
            check(fields == 1, "evidence-manifest-count")?;
            selected = super::ordinal_path_equal(path, manifest)?;
        }
        flags.observe(line);
    }
    check(
        !inside && matches == 1 && result.is_some(),
        "evidence-final",
    )?;
    let output = format!(
        "WINDOWS_SXS_EVIDENCE phase=registry-authority manifest=rust-consumer blocks={matches} {} original_call_attributed=False cause_claimed=False target_admitted=False",
        result.unwrap()
    );
    check(output.len() <= 4096, "evidence-output")?;
    Ok(output)
}
pub fn success_evidence(bytes: &[u8], manifest: &str, control: &str) -> Result<String> {
    check(
        !manifest.is_empty()
            && !control.is_empty()
            && !super::ordinal_path_equal(manifest, control)?,
        "collector-identity",
    )?;
    let lines = decode_lines(bytes)?;
    let (mut inside, mut selected_control, mut selected_consumer) = (false, false, false);
    let (mut error, mut reference, mut unknown, mut succeeded) = (false, false, false, false);
    let (mut blocks, mut controls, mut consumers, mut fields, mut terminal) = (0, 0, 0, 0, 0);
    for raw in &lines {
        let line = raw.trim_matches([' ', '\t']);
        if line == BEGIN {
            blocks += 1;
            check(!inside && blocks <= 64, "collector-begin")?;
            inside = true;
            selected_control = false;
            selected_consumer = false;
            error = false;
            reference = false;
            unknown = false;
            succeeded = false;
            fields = 0;
            terminal = 0;
            continue;
        }
        if line == END {
            check(inside, "collector-end")?;
            inside = false;
            if selected_control {
                controls += 1;
                check(
                    controls == 1
                        && fields == 1
                        && terminal == 1
                        && error
                        && !reference
                        && !succeeded,
                    "collector-positive",
                )?;
            }
            if selected_consumer {
                check(fields == 1 && !error && !unknown, "collector-consumer")?;
                consumers += 1;
            }
            continue;
        }
        if !inside {
            check(
                line.is_empty() || line.bytes().all(|b| b == b'='),
                "collector-framing",
            )?;
            continue;
        }
        if let Some(path) = line.strip_prefix("ManifestPath = ") {
            fields += 1;
            check(fields == 1, "collector-manifest")?;
            selected_control = super::ordinal_path_equal(path, control)?;
            selected_consumer = super::ordinal_path_equal(path, manifest)?;
        }
        reference |= line.starts_with(UNRESOLVED) || line.starts_with("INFO: Reference: ");
        if let Some(identity) = line.strip_prefix("INFO: Reference: ") {
            unknown |= !known_dependency(identity);
        }
        succeeded |= line.contains("Activation Context generation succeeded.");
        error |= line.starts_with("ERROR:");
        if line == "ERROR: Activation Context generation failed." {
            terminal += 1;
        }
    }
    check(!inside && controls == 1, "collector-final")?;
    let output = format!(
        "WINDOWS_SXS_EVIDENCE phase=registry-authority collector_recording_verified=True consumer_qualified=True consumer_blocks={consumers} child_visibility_claimed=False original_call_attributed=False cause_claimed=False target_admitted=False"
    );
    ensure!(output.len() <= 4096, "SxS evidence output exceeds bound");
    Ok(output)
}

/// Original SxsTraceSuccess.CheckValidation assertions, executable from the ordered bootstrap.
/// The result validates parser contracts; it does not prove that a collector recorded an event.
pub fn check_success_validation() -> Result<()> {
    use anyhow::ensure;
    const CONTROL: &str = "F:\\private-control-sentinel\\collector.manifest";
    const CONSUMER: &str = "F:\\private-python-sentinel\\DLLs\\_ctypes.pyd";
    const BEGIN: &str = "Begin Activation Context Generation.\n";
    const END: &str = "End Activation Context Generation.\n";
    let positive = format!(
        "{BEGIN}ManifestPath = {CONTROL}\nERROR: invalid namespace\nERROR: Activation Context generation failed.\n{END}"
    );
    let benign = format!(
        "{BEGIN}ManifestPath = {CONSUMER}\nINFO: Activation Context generation succeeded.\n{END}"
    );
    let utf8 = |text: &str| [b"\xef\xbb\xbf".as_slice(), text.as_bytes()].concat();
    let utf16 = |text: &str| {
        let mut bytes = vec![255, 254];
        for unit in text.encode_utf16() {
            bytes.extend(unit.to_le_bytes());
        }
        bytes
    };
    for count in 0..3 {
        let text = benign.repeat(count) + &positive;
        let result = success_evidence(&utf8(&text), CONSUMER, CONTROL)?;
        ensure!(result == success_evidence(&utf16(&text), CONSUMER, CONTROL)?
            && result.contains(&format!("collector_recording_verified=True consumer_qualified=True consumer_blocks={count}"))
            && result.contains("child_visibility_claimed=False") && !result.contains("private-"),
            "collector successful-consumer parser fixture differs");
    }
    for invalid in [
        String::new(),
        benign.clone(),
        positive.clone() + &positive,
        positive.replace(CONTROL, "wrong.manifest"),
        positive.replace("ERROR: Activation Context generation failed.\n", ""),
        positive.replace(
            "ERROR: Activation Context generation failed.",
            "INFO: Activation Context generation succeeded.",
        ),
        positive.replace(
            END,
            &format!("ERROR: Activation Context generation failed.\n{END}"),
        ),
        positive.replace(
            "ERROR: invalid namespace",
            "ERROR: Cannot resolve reference unknown",
        ),
        positive.replace("ERROR: invalid namespace", "INFO: Reference: unknown"),
        positive.replace(
            "ERROR: invalid namespace",
            "ERROR: Activation Context generation succeeded.",
        ),
        positive.replace(
            "ManifestPath = ",
            &format!("ManifestPath = {CONTROL}\nManifestPath = "),
        ),
        positive.clone() + BEGIN,
        positive.clone() + &benign.replace(END, ""),
        BEGIN.to_owned() + &positive,
        positive.clone() + END,
        positive.clone() + "private-outside-sentinel\n",
        positive.clone() + "\0",
        positive.clone() + "\r",
        positive.clone() + &"x".repeat(2049),
        positive.clone() + &"\n".repeat(4096),
        benign.repeat(64) + &positive,
        positive.clone()
            + &benign.replace(
                "INFO: Activation Context generation succeeded.",
                "ERROR: Access is denied.",
            ),
        positive.clone()
            + &benign.replace(
                "INFO: Activation Context generation succeeded.",
                "INFO: Reference: unknown",
            ),
        positive.clone()
            + &benign.replace(
                "ManifestPath = ",
                &format!("ManifestPath = {CONSUMER}\nManifestPath = "),
            ),
    ] {
        let error = success_evidence(&utf8(&invalid), CONSUMER, CONTROL)
            .err()
            .ok_or_else(|| anyhow::anyhow!("collector malformed text accepted"))?;
        ensure!(
            !format!("{:?}", super::safe(error, "collector-evidence")).contains("private-"),
            "collector parser disclosed private payload"
        );
    }
    for invalid in [
        vec![],
        vec![239, 187, 191],
        vec![239, 187, 191, 255],
        vec![255, 254, 0],
        vec![254, 255, 0, 0],
        positive.as_bytes().to_vec(),
        vec![0; 1_048_577],
    ] {
        ensure!(
            success_evidence(&invalid, CONSUMER, CONTROL).is_err(),
            "collector malformed bytes accepted"
        );
    }
    ensure!(
        success_evidence(&utf8(&positive), CONTROL, CONTROL).is_err(),
        "collector aliased consumer accepted"
    );
    ensure!(
        failure_evidence(&utf8(&positive), CONSUMER).is_err(),
        "collector substituted for failed consumer"
    );
    Ok(())
}
