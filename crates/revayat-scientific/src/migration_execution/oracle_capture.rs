//! Owned per-harness row journal. Only the outer runtime can finalize cleanup evidence.
#[cfg(test)]
#[path = "oracle_capture_tests.rs"]
mod tests;
use super::*;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

const TARGET: &str = "tests/security/windows/registry-authority/lib/registry_authority";
const CASE: &str = "protocol::tests::source_generated_oracle";
const OWNER: &str = "tests/security/windows/registry-authority/lib/registry_authority::protocol::tests::source_generated_oracle";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOracle {
    schema: u8,
    population: String,
    owner_case_id: String,
    events: Vec<events::OperationEvent>,
}

pub(super) struct OracleCapture(tempfile::TempDir);
impl OracleCapture {
    pub(super) fn create(artifact: &Artifact, tier: &str) -> Result<Option<Self>> {
        if artifact.target != TARGET || tier != "portable" {
            return Ok(None);
        }
        Ok(Some(Self(
            tempfile::Builder::new()
                .prefix("revayat-oracle-events-")
                .tempdir()?,
        )))
    }
    pub(super) fn retain(self) {
        let _owned_recovery_path = self.0.keep();
    }
    pub(super) fn configure(&self, spec: &mut CommandSpec) -> Result<()> {
        spec.env.insert(
            "REVAYAT_ORACLE_EVENT_DIR".into(),
            self.0.path().canonicalize()?.into_os_string(),
        );
        Ok(())
    }
    /// Called only after run_supervised returned, including its owned tree/container finalization.
    pub(super) fn finish(
        self,
        root: &Path,
        identity: &CollectedExecution,
        binary: &BinaryExecution,
    ) -> Result<events::OperationReport> {
        let result = (|| {
            ensure!(
                binary.target == TARGET
                    && binary.exit == Some(0)
                    && binary.error.is_none()
                    && binary.cleanup_complete
                    && binary.cases.get(CASE) == Some(&CaseOutcome::Passed),
                "oracle carrier execution or cleanup incomplete"
            );
            let path = self.0.path().join("oracle-observations.json");
            ensure!(
                !crate::identity::is_link(&path)?,
                "oracle journal must be a plain file"
            );
            let bytes = bounded(&path)?;
            let mut raw: RawOracle = serde_json::from_slice(&bytes)
                .map_err(|_| anyhow::anyhow!("invalid oracle row journal"))?;
            ensure!(
                raw.schema == 1
                    && raw.population == "oracle"
                    && raw.owner_case_id == OWNER
                    && raw.events.len() == 41,
                "oracle journal carrier or row inventory differs"
            );
            let mut seen = BTreeSet::new();
            for (index, event) in raw.events.iter_mut().enumerate() {
                ensure!(
                    !event.cleanup_complete
                        && event.parent_id == OWNER
                        && event.sequence == index + 1
                        && event.source == "execution"
                        && event.outcome == CaseOutcome::Passed
                        && event.exit == 0
                        && event.assertions_complete
                        && seen.insert(event.case_id.clone()),
                    "oracle row observation is incomplete or self-certified cleanup"
                );
                event.cleanup_complete = true; // Outer owned runtime completion, never a child certificate.
            }
            let census = bounded(&root.join("tests/oracle-census.json"))?;
            let value: serde_json::Value = serde_json::from_slice(&census)?;
            ensure!(value["schema"] == 1, "unsupported oracle census schema");
            let baseline = value["baseline_commit"]
                .as_str()
                .context("oracle baseline missing")?;
            let report = events::OperationReport {
                schema: 1,
                population: "oracle".into(),
                tested_sha: identity.tested_sha.clone(),
                run_id: identity.run_id.clone(),
                run_attempt: identity.run_attempt.clone(),
                repository: identity.repository.clone(),
                workflow_ref: identity.workflow_ref.clone(),
                scope: events::EventScope {
                    platform: identity.platform.clone(),
                    tier: identity.tier.clone(),
                    profile: identity.profile.clone(),
                    job: identity.job.clone(),
                },
                baseline_commit: baseline.into(),
                census_sha256: format!("{:x}", Sha256::digest(&census)),
                events: raw.events,
            };
            Ok(report)
        })();
        runtime::with_cleanup(
            result,
            self.0
                .close()
                .context("oracle journal directory cleanup failed"),
        )
    }
}
fn bounded(path: &Path) -> Result<Vec<u8>> {
    ensure!(
        !crate::identity::is_link(path)? && fs::metadata(path)?.is_file(),
        "operation input must be a plain file"
    );
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 16 * 1024 * 1024,
        "operation input exceeds bound"
    );
    Ok(bytes)
}
pub(super) fn publish(
    root: &Path,
    output: &Path,
    identity: &CollectedExecution,
    reports: &[events::OperationReport],
) -> Result<()> {
    ensure!(
        reports.len() == 1,
        "required actual oracle report missing or duplicated"
    );
    let report = &reports[0];
    let bytes = bounded(&root.join("tests/oracle-census.json"))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    ensure!(value["schema"] == 1, "unsupported oracle census schema");
    let mut contract: events::EventContract =
        serde_json::from_value(value["execution_contract"].clone())
            .map_err(|_| anyhow::anyhow!("oracle execution contract is not source-closed"))?;
    contract.scopes.retain(|scope| scope.scope == report.scope);
    let census = events::CensusContract {
        population: "oracle".into(),
        baseline_commit: value["baseline_commit"]
            .as_str()
            .context("oracle baseline missing")?
            .into(),
        census_sha256: format!("{:x}", Sha256::digest(&bytes)),
        ids: value["cases"]
            .as_array()
            .context("oracle census rows missing")?
            .iter()
            .map(|row| {
                row["id"]
                    .as_str()
                    .map(str::to_owned)
                    .context("oracle row identity missing")
            })
            .collect::<Result<_>>()?,
        contract: Some(contract),
    };
    events::validate_populations(
        &[census],
        reports,
        std::slice::from_ref(identity),
        (
            &identity.tested_sha,
            &identity.run_id,
            &identity.run_attempt,
            &identity.repository,
            &identity.workflow_ref,
        ),
    )?;
    let bytes = serde_json::to_vec_pretty(report)?;
    ensure!(
        bytes.len() <= 16 * 1024 * 1024,
        "operation report exceeds bound"
    );
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let path = parent.join(format!("oracle-{}.json", report.scope.profile));
    let mut stage = tempfile::NamedTempFile::new_in(parent)?;
    stage.write_all(&bytes)?;
    stage.as_file().sync_all()?;
    stage
        .persist_noclobber(path)
        .map_err(|_| anyhow::anyhow!("oracle operation report publication failed"))?;
    Ok(())
}
