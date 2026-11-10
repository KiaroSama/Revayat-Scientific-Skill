//! Strict standard-tool text decoding and separate failed-consumer/collector-positive contracts.
use super::{PrivateFailure, safe};
use anyhow::{Result, ensure};
use regex::Regex;

const BEGIN: &str = "Begin Activation Context Generation.";
const END: &str = "End Activation Context Generation.";
const UNRESOLVED: &str = "ERROR: Cannot resolve reference ";
fn check(value: bool, stage: &'static str) -> Result<()> {
    if !value {
        return Err(PrivateFailure {
            stage,
            original: anyhow::anyhow!("fixed SxS evidence predicate rejected"),
        }
        .into());
    }
    Ok(())
}
pub fn decode_lines(bytes: &[u8]) -> Result<Vec<String>> {
    check(
        (2..=1048576).contains(&bytes.len()),
        "evidence-length-input-shape",
    )?;
    let text = if bytes.starts_with(&[255, 254]) {
        check(bytes.len().is_multiple_of(2), "evidence-length-utf16-shape")?;
        let mut units = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        let decoded = String::from_utf16(&units).map_err(|e| safe(e.into(), "evidence-utf16"));
        units.fill(0);
        decoded?
    } else if bytes.starts_with(&[239, 187, 191]) {
        std::str::from_utf8(&bytes[3..])
            .map_err(|e| safe(e.into(), "evidence-utf8"))?
            .to_owned()
    } else {
        check(false, "evidence-bom")?;
        unreachable!()
    };
    check(!text.contains('\0'), "evidence-nul")?;
    let normalized = text.replace("\r\n", "\n");
    let lines = normalized
        .split('\n')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    check(lines.len() <= 4096, "evidence-line-count")?;
    for line in &lines {
        check(line.encode_utf16().count() <= 2048, "evidence-line-width")?;
        check(!line.contains('\r'), "evidence-cr")?;
    }
    Ok(lines)
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
    let lines = decode_lines(bytes)?;
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
                check(matches == 1, "evidence-selected-count")?;
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
