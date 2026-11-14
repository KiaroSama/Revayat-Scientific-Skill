//! Linux coverage comes from its actual host owner and isolated worker receipts.
use super::*;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
#[path = "native_coverage_metadata.rs"]
mod metadata;

pub(super) const OWNER_TARGET: &str = "crates/revayat-scientific/test/runtime_build_integration";
pub(super) const OWNER_CASE: &str =
    "test_production_launch_enforces_isolation_and_cleans_owned_container";
const OWNER: &str = "crates/revayat-scientific/test/runtime_build_integration::test_production_launch_enforces_isolation_and_cleans_owned_container";
const ENVIRONMENT: &str = "REVAYAT_COVERAGE_EVENT_DIR";
const JOURNAL: &str = "linux-coverage-observations.json";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: u8,
    population: String,
    owner_case_id: String,
    production: serde_json::Value,
    helper: serde_json::Value,
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn qualify(journal: &Journal) -> Result<BTreeMap<String, CaseOutcome>> {
    use serde_json::json;
    ensure!(
        journal.schema == 1 && journal.population == "coverage" && journal.owner_case_id == OWNER,
        "native coverage journal owner differs"
    );
    let production = &journal.production;
    let production_run = production["run_id"]
        .as_str()
        .context("production run missing")?;
    ensure!(
        crate::tex_supervisor::valid_token(production_run),
        "invalid production run"
    );
    ensure!(
        production
            == &json!({
                "verified":true,"checks":29,"run_id":production_run,"container_cleanup":"verified",
                "production_output_aggregate_quota":"verified","output_mount":"tmpfs",
                "output_bytes":268435456,"per_file_bytes":268435456,"per_file_efbig":true,
                "aggregate_enospc":true,"tex_openout_files":2,"ordinary_pdf":true
            }),
        "effective production mount, quota, producer or cleanup observation incomplete"
    );
    let helper = &journal.helper;
    ensure!(
        helper.as_object().is_some_and(|fields| fields.len() == 7
            && fields.keys().all(|key| [
                "preflight",
                "scenarios",
                "cases",
                "run_id",
                "worker_sha256",
                "container_cleanup",
                "execution"
            ]
            .contains(&key.as_str()))),
        "unknown helper receipt field"
    );
    let helper_run = helper["run_id"].as_str().context("helper run missing")?;
    ensure!(
        crate::tex_supervisor::valid_token(helper_run) && helper_run != production_run,
        "helper and production require distinct owned runs"
    );
    ensure!(
        helper["container_cleanup"] == "verified"
            && helper["worker_sha256"].as_str().is_some_and(digest),
        "checked worker identity or cleanup missing"
    );
    ensure!(
        helper["preflight"]
            == json!({
                "phase":"helper-preflight","status":"passed","checks":39,"environment_names":7,
                "scratch_bytes":134217728,"file_bytes":67108864,"wall_seconds":90,
                "kill_after_seconds":2,"wall_configuration_verified":true
            }),
        "effective helper prerequisites differ"
    );
    let elapsed = helper["execution"]["elapsed_millis"]
        .as_u64()
        .context("actual helper duration missing")?;
    ensure!(
        elapsed <= 110000
            && helper["execution"]
                == json!({"exit":0,"host_wall_seconds":110,"elapsed_millis":elapsed}),
        "helper wall execution or exit incomplete"
    );
    ensure!(
        helper["scenarios"]
            == json!({"phase":"security-scenarios","status":"passed","admission_checks":30,"tex_output_checks":6,"production_output_aggregate_quota":"unresolved"}),
        "helper summary cannot certify production quota"
    );
    super::linux_cases(helper)
}

/// The existing host test calls this after its portable proof-integrity checks.
/// No journal is emitted until both actual native boundaries and all 36 leaves
/// have returned with verified owned cleanup.
pub fn observe_linux_coverage() -> Result<serde_json::Value> {
    ensure!(cfg!(target_os = "linux"), "Linux coverage requires Linux");
    let journal = Journal {
        schema: 1,
        population: "coverage".into(),
        owner_case_id: OWNER.into(),
        production: crate::sandbox::probe()?,
        helper: crate::sandbox::security()?,
    };
    qualify(&journal)?;
    if let Some(directory) = std::env::var_os(ENVIRONMENT) {
        let path = Path::new(&directory);
        ensure!(
            path.is_dir() && !crate::identity::is_link(path)? && path.canonicalize()? == path,
            "native coverage destination must be an owned plain directory"
        );
        let bytes = serde_json::to_vec(&journal)?;
        ensure!(
            bytes.len() <= 65536,
            "native coverage journal exceeds bound"
        );
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path.join(JOURNAL))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    Ok(serde_json::json!({"production":journal.production,"helper":journal.helper}))
}

fn leaf(id: &str) -> Result<String> {
    let name = crate::security_cases::CASE_NAMES
        .iter()
        .find(|(candidate, _)| *candidate == id)
        .context("coverage source names an unknown worker leaf")?
        .1;
    Ok(format!("{}::{name}", super::LINUX_TARGET))
}
fn check(id: &str, ids: &[&str], owner: bool) -> Result<events::CheckOutcome> {
    let mut witnesses = ids.iter().map(|id| leaf(id)).collect::<Result<Vec<_>>>()?;
    if owner {
        witnesses.insert(0, OWNER.into());
    }
    ensure!(
        !witnesses.is_empty(),
        "native coverage check has no actual witness"
    );
    Ok(events::CheckOutcome {
        check_id: id.into(),
        witness_ids: witnesses,
        outcome: CaseOutcome::Passed,
    })
}
fn worker_checks() -> Result<Vec<events::OperationEvent>> {
    let controls = [
        "readonly-target-tools-root",
        "scratch-only-writes",
        "empty-allowlisted-environment",
        "network-namespace",
        "nonroot-capabilities",
        "cpu-memory-pid-file-disk-wall",
        "owned-cleanup",
    ]
    .iter()
    .map(|id| check(id, &[], true))
    .collect::<Result<Vec<_>>>()?;
    let depth = [
        "html/depth/parser",
        "html/depth/source",
        "html/depth/guard",
        "html/depth/assets",
        "html/depth/text-order",
        "html/depth/resource-policy",
        "html/depth/render-entry",
        "html/depth/lint",
    ];
    let nodes = [
        "html/nodes/parser",
        "html/nodes/source",
        "html/nodes/guard",
        "html/nodes/assets",
        "html/nodes/text-order",
        "html/nodes/resource-policy",
        "html/nodes/render-entry",
        "html/nodes/lint",
    ];
    let html = vec![
        check("depth-boundary", &depth, false)?,
        check("element-count-boundary", &nodes, false)?,
        check(
            "parser",
            &[depth[0], nodes[0], "html/ordinary-nesting"],
            false,
        )?,
        check(
            "source",
            &[depth[1], nodes[1], "html/ordinary-nesting"],
            false,
        )?,
        check("lint", &[depth[7], nodes[7], "html/ordinary-lint"], false)?,
        check("guard", &[depth[2], nodes[2], "html/ordinary-guard"], false)?,
        check(
            "assets",
            &[depth[3], nodes[3], "html/ordinary-assets"],
            false,
        )?,
        check(
            "text-order",
            &[depth[4], nodes[4], "html/ordinary-nesting"],
            false,
        )?,
        check(
            "resource-policy",
            &[depth[5], nodes[5], "html/ordinary-nesting"],
            false,
        )?,
        check(
            "render-entry-admission-ordering",
            &[depth[6], nodes[6], "html/ordinary-render-entry-ordering"],
            false,
        )?,
        check(
            "ordinary-nesting",
            &[
                "html/ordinary-nesting",
                "html/ordinary-lint",
                "html/ordinary-guard",
                "html/ordinary-assets",
                "html/ordinary-render-entry-ordering",
            ],
            false,
        )?,
    ];
    let tex = vec![
        check(
            "effective-production-mount",
            &[
                "tex-output/production-run-arguments-evaluated",
                "tex-output/production-rw-output-bind",
            ],
            true,
        )?,
        check(
            "per-file-versus-aggregate",
            &["tex-output/production-per-file-not-aggregate"],
            true,
        )?,
        check("finite-multi-file-quota", &[], true)?,
        check(
            "harmless-tex-openout-policy",
            &[
                "tex-output/real-xelatex-no-shell",
                "tex-output/two-permitted-output-files",
            ],
            true,
        )?,
        check("normal-output", &["tex-output/ordinary-pdf"], true)?,
    ];
    Ok([
        (1, "coverage::linux-controls", controls),
        (5, "coverage::html-work-admission", html),
        (6, "coverage::tex-output-budget", tex),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (ordinal, id, checks))| events::OperationEvent {
        case_id: id.into(),
        parent_id: OWNER.into(),
        sequence: index + 1,
        invokes_ids: vec![],
        obligation_ids: metadata::obligation_ids(ordinal, checks.len()),
        source: "execution".into(),
        outcome: CaseOutcome::Passed,
        exit: 0,
        cleanup_complete: true,
        assertions_complete: true,
        variants: vec![],
        check_results: checks,
    })
    .collect())
}

pub(super) struct Capture(tempfile::TempDir);
impl Capture {
    pub(super) fn create() -> Result<Self> {
        Ok(Self(
            tempfile::Builder::new()
                .prefix("revayat-linux-coverage-")
                .tempdir()?,
        ))
    }
    pub(super) fn configure(&self, spec: &mut CommandSpec) -> Result<()> {
        spec.env.insert(
            ENVIRONMENT.into(),
            self.0.path().canonicalize()?.into_os_string(),
        );
        Ok(())
    }
    pub(super) fn retain(self) {
        let _ = self.0.keep();
    }
    pub(super) fn finish(
        self,
        root: &Path,
        identity: &CollectedExecution,
        owner: &BinaryExecution,
    ) -> Result<(BinaryExecution, events::OperationReport)> {
        let result = (|| {
            ensure!(
                owner.target == OWNER_TARGET
                    && owner.exit == Some(0)
                    && owner.error.is_none()
                    && owner.cleanup_complete
                    && owner.cases.get(OWNER_CASE) == Some(&CaseOutcome::Passed),
                "actual native coverage owner or outer cleanup incomplete"
            );
            let path = self.0.path().join(JOURNAL);
            ensure!(
                !crate::identity::is_link(&path)? && fs::metadata(&path)?.is_file(),
                "native coverage journal must be plain"
            );
            let mut bytes = Vec::new();
            fs::File::open(path)?.take(65537).read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() <= 65536,
                "native coverage journal exceeds bound"
            );
            let journal: Journal = serde_json::from_slice(&bytes)?;
            let cases = qualify(&journal)?;
            ensure!(
                identity.platform == "linux"
                    && identity.tier == "native"
                    && identity.profile == "debug",
                "native coverage execution scope differs"
            );
            let census_path = root.join("tests/coverage-census.json");
            let census_bytes = crate::resource::bounded_read(&census_path, 16 * 1024 * 1024)?;
            let census: serde_json::Value = serde_json::from_slice(&census_bytes)?;
            let baseline = census["baseline_commit"]
                .as_str()
                .context("coverage baseline missing")?;
            ensure!(
                census["schema"] == 1 && exact_sha(baseline),
                "coverage census binding differs"
            );
            let events = worker_checks()?;
            let contract = metadata::load(root, &census_bytes, &events)?;
            for event in &events {
                ensure!(
                    event
                        .check_results
                        .iter()
                        .flat_map(|check| &check.witness_ids)
                        .all(|id| id == OWNER
                            || cases
                                .keys()
                                .any(|case| id == &format!("{}::{case}", super::LINUX_TARGET))),
                    "coverage witness was not an actual same-run worker leaf"
                );
            }
            let worker = BinaryExecution {
                target: super::LINUX_TARGET.into(),
                mapping_target: Some("standalone_security".into()),
                exit: Some(0),
                cleanup_complete: true,
                cases,
                error: None,
            };
            let report = events::OperationReport {
                schema: 1,
                population: "coverage".into(),
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
                census_sha256: format!("{:x}", Sha256::digest(&census_bytes)),
                events,
            };
            metadata::validate_execution(&contract, &report, identity, owner, &worker)?;
            Ok((worker, report))
        })();
        runtime::with_cleanup(
            result,
            self.0
                .close()
                .context("native coverage journal cleanup failed"),
        )
    }
}

pub(super) fn publish(output: &Path, report: &events::OperationReport) -> Result<()> {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let bytes = serde_json::to_vec_pretty(report)?;
    ensure!(bytes.len() <= 65536, "native coverage report exceeds bound");
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(parent.join(format!("coverage-{}.json", report.scope.profile)))
        .map_err(|_| anyhow::anyhow!("native coverage report already exists or cannot publish"))?;
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub(crate) fn native_receipts_require_every_control_and_exact_witness() {
        let production = serde_json::json!({"verified":true,"checks":29,"run_id":"a".repeat(32),"container_cleanup":"verified","production_output_aggregate_quota":"verified","output_mount":"tmpfs","output_bytes":268435456,"per_file_bytes":268435456,"per_file_efbig":true,"aggregate_enospc":true,"tex_openout_files":2,"ordinary_pdf":true});
        let helper = serde_json::json!({"preflight":{"phase":"helper-preflight","status":"passed","checks":39,"environment_names":7,"scratch_bytes":134217728,"file_bytes":67108864,"wall_seconds":90,"kill_after_seconds":2,"wall_configuration_verified":true},"scenarios":{"phase":"security-scenarios","status":"passed","admission_checks":30,"tex_output_checks":6,"production_output_aggregate_quota":"unresolved"},"cases":crate::security_cases::IDS.iter().map(|id|serde_json::json!({"phase":"security-case","id":id,"status":"passed"})).collect::<Vec<_>>(),"run_id":"b".repeat(32),"worker_sha256":"c".repeat(64),"container_cleanup":"verified","execution":{"exit":0,"host_wall_seconds":110,"elapsed_millis":1}});
        let valid = serde_json::json!({"schema":1,"population":"coverage","owner_case_id":OWNER,"production":production,"helper":helper});
        let journal: Journal = serde_json::from_value(valid.clone()).unwrap();
        assert_eq!(qualify(&journal).unwrap().len(), 36);
        for (path, value) in [
            ("/production/output_mount", serde_json::json!("bind")),
            ("/production/output_bytes", serde_json::json!(268435457u64)),
            ("/production/per_file_efbig", serde_json::json!(false)),
            ("/production/aggregate_enospc", serde_json::json!(false)),
            ("/production/tex_openout_files", serde_json::json!(1)),
            ("/production/ordinary_pdf", serde_json::json!(false)),
            (
                "/production/container_cleanup",
                serde_json::json!("unknown"),
            ),
            ("/helper/preflight/checks", serde_json::json!(38)),
            (
                "/helper/preflight/wall_configuration_verified",
                serde_json::json!(false),
            ),
            ("/helper/preflight/wall_seconds", serde_json::json!(91)),
            (
                "/helper/execution/elapsed_millis",
                serde_json::json!(110001),
            ),
            ("/helper/execution/exit", serde_json::json!(1)),
            ("/helper/container_cleanup", serde_json::json!("unknown")),
            (
                "/helper/scenarios/production_output_aggregate_quota",
                serde_json::json!("verified"),
            ),
            (
                "/helper/worker_sha256",
                serde_json::json!("not-an-identity"),
            ),
            ("/helper/run_id", serde_json::json!("a".repeat(32))),
        ] {
            let mut changed = valid.clone();
            *changed.pointer_mut(path).unwrap() = value;
            assert!(
                qualify(&serde_json::from_value(changed).unwrap()).is_err(),
                "{path}"
            );
        }
        let mut changed = valid.clone();
        changed["helper"]["cases"].as_array_mut().unwrap().pop();
        assert!(qualify(&serde_json::from_value(changed).unwrap()).is_err());
        let events = worker_checks().unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(
            events
                .iter()
                .map(|event| event.check_results.len())
                .collect::<Vec<_>>(),
            [7, 11, 5]
        );
        let actual = qualify(&journal).unwrap();
        for event in events {
            assert_eq!(event.parent_id, OWNER);
            assert!(
                !event.case_id.contains("windows")
                    && !event.case_id.contains("docx")
                    && !event.case_id.contains("static-output")
            );
            assert!(
                event
                    .check_results
                    .iter()
                    .flat_map(|check| &check.witness_ids)
                    .all(|id| id == OWNER
                        || actual
                            .keys()
                            .any(|case| id == &format!("{}::{case}", super::super::LINUX_TARGET)))
            );
        }
        metadata::test_source_contract_and_global_refusal(&actual);
    }
}
