//! Owned per-harness operation journals. Only the outer runtime finalizes cleanup.
#[cfg(test)]
#[path = "oracle_capture_tests.rs"]
mod tests;
use super::*;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

const TARGET: &str = "tests/security/windows/registry-authority/lib/registry_authority";
const CASE: &str = "protocol::tests::source_generated_oracle";
const OWNER: &str = "tests/security/windows/registry-authority/lib/registry_authority::protocol::tests::source_generated_oracle";

struct Config {
    population: &'static str,
    target: &'static str,
    case: &'static str,
    owner: &'static str,
    environment: &'static str,
    journal: &'static str,
    census: &'static str,
    key: &'static str,
    count: usize,
}
const ORACLE: Config = Config {
    population: "oracle",
    target: TARGET,
    case: CASE,
    owner: OWNER,
    environment: "REVAYAT_ORACLE_EVENT_DIR",
    journal: "oracle-observations.json",
    census: "tests/oracle-census.json",
    key: "cases",
    count: 41,
};
const ENGINE: Config = Config {
    population: "engine",
    target: "crates/revayat-scientific/test/runtime_build_integration",
    case: "test_explicit_engine_discovery_does_not_probe_other_backends",
    owner: "crates/revayat-scientific/test/runtime_build_integration::test_explicit_engine_discovery_does_not_probe_other_backends",
    environment: "REVAYAT_ENGINE_EVENT_DIR",
    journal: "engine-observations.json",
    census: "tests/engine-census.json",
    key: "cases",
    count: 6,
};
const PREPARATION: Config = Config {
    population: "runtime-preparation",
    target: "crates/revayat-scientific/test/windows_contract",
    case: "bootstrap::controller_markers_preserve_validation_order",
    owner: "crates/revayat-scientific/test/windows_contract::bootstrap::controller_markers_preserve_validation_order",
    environment: "REVAYAT_RUNTIME_PREPARATION_EVENT_DIR",
    journal: "runtime-preparation-observations.json",
    census: "tests/runtime-preparation-census.json",
    key: "sites",
    count: 19,
};
const CONFIGS: [&Config; 3] = [&ORACLE, &ENGINE, &PREPARATION];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawJournal {
    schema: u8,
    population: String,
    owner_case_id: String,
    events: Vec<events::OperationEvent>,
}

pub(super) struct Capture {
    directory: tempfile::TempDir,
    config: &'static Config,
}
impl Capture {
    pub(super) fn create(artifact: &Artifact, tier: &str) -> Result<Option<Self>> {
        if tier != "portable" {
            return Ok(None);
        }
        let Some(config) = CONFIGS
            .iter()
            .find(|config| config.target == artifact.target)
        else {
            return Ok(None);
        };
        Ok(Some(Self {
            directory: tempfile::Builder::new()
                .prefix(&format!("revayat-{}-events-", config.population))
                .tempdir()?,
            config,
        }))
    }
    pub(super) fn retain(self) {
        let _owned_recovery_path = self.directory.keep();
    }
    pub(super) fn configure(&self, spec: &mut CommandSpec) -> Result<()> {
        spec.env.insert(
            self.config.environment.into(),
            self.directory.path().canonicalize()?.into_os_string(),
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
        let config = self.config;
        let result = (|| {
            ensure!(
                binary.target == config.target
                    && binary.exit == Some(0)
                    && binary.error.is_none()
                    && binary.cleanup_complete
                    && binary.cases.get(config.case) == Some(&CaseOutcome::Passed),
                "operation carrier execution or cleanup incomplete"
            );
            let path = self.directory.path().join(config.journal);
            ensure!(
                !crate::identity::is_link(&path)?,
                "operation journal must be a plain file"
            );
            let bytes = bounded(&path)?;
            let mut raw: RawJournal = serde_json::from_slice(&bytes)
                .map_err(|_| anyhow::anyhow!("invalid operation journal"))?;
            ensure!(
                raw.schema == 1
                    && raw.population == config.population
                    && raw.owner_case_id == config.owner
                    && raw.events.len() == config.count,
                "operation journal carrier or entry inventory differs"
            );
            let mut seen = BTreeSet::new();
            for (index, event) in raw.events.iter_mut().enumerate() {
                ensure!(
                    !event.cleanup_complete
                        && event.parent_id == config.owner
                        && event.sequence == index + 1
                        && event.source == "execution"
                        && event.outcome == CaseOutcome::Passed
                        && event.exit == 0
                        && event.assertions_complete
                        && seen.insert(event.case_id.clone()),
                    "operation observation is incomplete or self-certified cleanup"
                );
                event.cleanup_complete = true; // Outer owned runtime completion, never a child certificate.
            }
            let census = bounded(&root.join(config.census))?;
            let value: serde_json::Value = serde_json::from_slice(&census)?;
            ensure!(value["schema"] == 1, "unsupported operation census schema");
            let baseline = value["baseline_commit"]
                .as_str()
                .context("operation baseline missing")?;
            let report = events::OperationReport {
                schema: 1,
                population: config.population.into(),
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
            self.directory
                .close()
                .context("operation journal directory cleanup failed"),
        )
    }
}

// Preserve the established synthetic boundary tests and their registrations.
#[cfg(test)]
struct OracleCapture(tempfile::TempDir);
#[cfg(test)]
impl OracleCapture {
    fn create(artifact: &Artifact, tier: &str) -> Result<Option<Self>> {
        if artifact.target != TARGET {
            return Ok(None);
        }
        Ok(Capture::create(artifact, tier)?.map(|capture| Self(capture.directory)))
    }
    fn configure(&self, spec: &mut CommandSpec) -> Result<()> {
        spec.env.insert(
            ORACLE.environment.into(),
            self.0.path().canonicalize()?.into_os_string(),
        );
        Ok(())
    }
    fn finish(
        self,
        root: &Path,
        identity: &CollectedExecution,
        binary: &BinaryExecution,
    ) -> Result<events::OperationReport> {
        Capture {
            directory: self.0,
            config: &ORACLE,
        }
        .finish(root, identity, binary)
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
#[cfg(test)]
fn publish(
    root: &Path,
    output: &Path,
    identity: &CollectedExecution,
    reports: &[events::OperationReport],
) -> Result<()> {
    publish_selected(root, output, identity, reports, &[&ORACLE])
}
pub(super) fn publish_all(
    root: &Path,
    output: &Path,
    identity: &CollectedExecution,
    reports: &[events::OperationReport],
) -> Result<()> {
    publish_selected(root, output, identity, reports, &CONFIGS)
}
fn load_census(
    root: &Path,
    config: &Config,
    scope: &events::EventScope,
) -> Result<events::CensusContract> {
    let bytes = bounded(&root.join(config.census))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    ensure!(value["schema"] == 1, "unsupported operation census schema");
    let mut contract: events::EventContract =
        serde_json::from_value(value["execution_contract"].clone())
            .map_err(|_| anyhow::anyhow!("operation execution contract is not source-closed"))?;
    contract.scopes.retain(|entry| entry.scope == *scope);
    Ok(events::CensusContract {
        population: config.population.into(),
        baseline_commit: value["baseline_commit"]
            .as_str()
            .context("operation baseline missing")?
            .into(),
        census_sha256: format!("{:x}", Sha256::digest(&bytes)),
        ids: value[config.key]
            .as_array()
            .context("operation census entries missing")?
            .iter()
            .map(|row| {
                row["id"]
                    .as_str()
                    .map(str::to_owned)
                    .context("operation identity missing")
            })
            .collect::<Result<_>>()?,
        contract: Some(contract),
    })
}
fn publish_selected(
    root: &Path,
    output: &Path,
    identity: &CollectedExecution,
    reports: &[events::OperationReport],
    configs: &[&Config],
) -> Result<()> {
    ensure!(
        reports.len() == configs.len(),
        "required actual operation report missing or duplicated"
    );
    let mut censuses = Vec::new();
    for config in configs {
        let matching: Vec<_> = reports
            .iter()
            .filter(|report| report.population == config.population)
            .collect();
        ensure!(
            matching.len() == 1,
            "required operation population missing or duplicated"
        );
        censuses.push(load_census(root, config, &matching[0].scope)?);
    }
    events::validate_populations(
        &censuses,
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
    // Validate the entire three-population batch before publishing any member.
    for report in reports {
        publish_report(output, report)?;
    }
    Ok(())
}
fn publish_report(output: &Path, report: &events::OperationReport) -> Result<()> {
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
    let path = parent.join(format!(
        "{}-{}.json",
        report.population, report.scope.profile
    ));
    let mut stage = tempfile::NamedTempFile::new_in(parent)?;
    stage.write_all(&bytes)?;
    stage.as_file().sync_all()?;
    stage
        .persist_noclobber(path)
        .map_err(|_| anyhow::anyhow!("operation report publication failed"))?;
    Ok(())
}
