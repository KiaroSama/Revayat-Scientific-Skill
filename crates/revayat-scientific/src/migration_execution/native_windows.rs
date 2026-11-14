//! Same-run Windows receipts join actual bootstrap/kernel and libtest witnesses.
use super::*;
use events::{CheckOutcome, OperationEvent, OperationReport, VariantOutcome};
use sha2::{Digest, Sha256};
use std::io::Write;

const OWNER: &str = "crates/revayat-scientific/test/windows_native::actual_lpac_primary_and_descendant_attest_registry_and_token_controls";
const STANDALONE: &str = "crates/revayat-scientific/test/windows_standalone";
const CASES: [&str; 5] = [
    "native_opc_consumer_recognizes_case_variant_relationship_part",
    "junction_destination_admission_preserves_owned_controls",
    "junction_publication_refuses_and_preserves_stage_and_sentinels",
    "ordinary_publication_commits_exact_bytes",
    "public_build_junction_refusal_precedes_lint_and_renderer",
];
const RECEIPT: &str = "windows-security-receipt.json";
const COVERAGE: &[u8] = include_bytes!("../../../../tests/coverage-census.json");
const STAGES: &[u8] = include_bytes!("../../../../tests/native-stage-census.json");

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: u8,
    tested_sha: String,
    run_id: String,
    run_attempt: String,
    repository: String,
    workflow_ref: String,
    job: String,
    stage_ids: Vec<String>,
}

fn stage_ids() -> Vec<String> {
    let mut ids = (1..=53)
        .map(|i: usize| {
            let index = i.to_string();
            format!("bootstrap::managed/{index:0>2}")
        })
        .collect::<Vec<_>>();
    ids.extend(
        [
            "runtime-preparation::PythonStartupFixture.CheckValidation",
            "post-bootstrap::RegistryLoaderFixture.CheckValidation",
            "post-bootstrap::SxsTraceCapture.CheckValidation",
            "post-bootstrap::StartupActivationAccess.CheckTraceControlValidation",
        ]
        .map(str::to_owned),
    );
    ids
}

fn verify_output(stdout: &[u8], stderr: &[u8]) -> Result<Vec<String>> {
    let stderr = std::str::from_utf8(stderr).context("Windows bootstrap stderr is not UTF-8")?;
    let expected = (1..=53_i32)
        .flat_map(|i| {
            ["before", "after"].map(|state| {
                let state = state.to_owned();
                let index = i.to_string();
                format!("WINDOWS_BOOTSTRAP phase=managed state={state} index={index}")
            })
        })
        .chain((0..=3_i32).flat_map(|i| {
            ["before", "after"].map(|state| {
                let state = state.to_owned();
                let index = i.to_string();
                format!("WINDOWS_BOOTSTRAP_DIRECT state={state} index={index}")
            })
        }))
        .collect::<Vec<_>>();
    ensure!(
        stderr.ends_with('\n'),
        "Windows bootstrap marker stream is truncated"
    );
    let observed = stderr
        .lines()
        .filter(|line| {
            line.starts_with("WINDOWS_BOOTSTRAP phase=managed")
                || line.starts_with("WINDOWS_BOOTSTRAP_DIRECT")
        })
        .collect::<Vec<_>>();
    ensure!(
        observed == expected,
        "Windows bootstrap markers missing, duplicated or out of order"
    );
    let stdout = std::str::from_utf8(stdout).context("Windows kernel stdout is not UTF-8")?;
    let primary = stdout
        .lines()
        .filter(|line| line.starts_with("WINDOWS_KERNEL_CONTROL role=primary "))
        .collect::<Vec<_>>();
    let session = stdout.lines().filter(|line| line.starts_with("WINDOWS_KERNEL_SESSION original_access_denied=True restored_access_denied=True host_surface_restored=True volume_policy_restored=True wall_tree_terminated=True "))
        .collect::<Vec<_>>();
    let primary_ok = primary.len() == 1
        && ["status=passed", "network=True", "quota=True"]
            .iter()
            .all(|field| {
                primary[0]
                    .split_ascii_whitespace()
                    .filter(|part| part == field)
                    .count()
                    == 1
            });
    let session_ok = session.len() == 1
        && session[0]
            .split_ascii_whitespace()
            .filter(|part| *part == "target_admitted=False")
            .count()
            == 1;
    ensure!(
        primary_ok && session_ok,
        "Windows kernel controls or restored session receipt incomplete"
    );
    Ok(stage_ids())
}

/// Called only after successful outer ownership recovery and both requested native gates.
pub fn record_windows_security_receipt(stdout: &[u8], stderr: &[u8]) -> Result<()> {
    let stages = verify_output(stdout, stderr)?;
    let root = std::env::current_dir()?;
    let (tested_sha, run_id, run_attempt, job) = checked_identity(&root)?;
    ensure!(
        job == "windows-security",
        "Windows receipt requires windows-security job"
    );
    let receipt = Receipt {
        schema: 1,
        tested_sha,
        run_id,
        run_attempt,
        job,
        repository: hosted_label("GITHUB_REPOSITORY")?,
        workflow_ref: hosted_label("GITHUB_WORKFLOW_REF")?,
        stage_ids: stages,
    };
    fs::create_dir_all(root.join("execution"))?;
    write_json(&root.join("execution").join(RECEIPT), &receipt)
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().context("Windows event report lacks parent")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(&serde_json::to_vec_pretty(value)?)?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(path).map_err(|e| e.error)?;
    Ok(())
}

fn verify_receipt(receipt: &Receipt, report: &CollectedExecution) -> Result<()> {
    let matches = receipt.schema == 1
        && receipt.tested_sha == report.tested_sha
        && receipt.run_id == report.run_id
        && receipt.run_attempt == report.run_attempt
        && receipt.repository == report.repository
        && receipt.workflow_ref == report.workflow_ref
        && receipt.job == report.job
        && receipt.job == "windows-security"
        && receipt.stage_ids == stage_ids();
    ensure!(
        matches,
        "Windows receipt binding or verified stage inventory differs"
    );
    let clean = report.error.is_none()
        && report.discovery_exit.is_none()
        && !report.final_parity_verified
        && report.schema == 1
        && report.ignored_only
        && report.platform == "windows"
        && report.tier == "native"
        && report.profile == "debug"
        && report.binaries.iter().all(|binary| {
            binary.exit == Some(0) && binary.cleanup_complete && binary.error.is_none()
        });
    ensure!(clean, "Windows owner harness or cleanup incomplete");
    let passed = events::passed_cases(report);
    ensure!(
        passed.contains(OWNER)
            && CASES.iter().all(|case| {
                let case = case.to_string();
                passed.contains(&format!("{STANDALONE}::{case}"))
            }),
        "Windows owner or standalone witness did not pass"
    );
    Ok(())
}

pub(super) fn publish_windows_native_events(
    root: &Path,
    output: &Path,
    report: &CollectedExecution,
) -> Result<()> {
    let parent = output.parent().context("Windows report lacks parent")?;
    let path = parent.join(RECEIPT);
    let read = (|| {
        ensure!(
            !crate::identity::is_link(&path)?,
            "Windows receipt must be plain"
        );
        crate::resource::bounded_read(&path, 65536)
    })();
    // Consume even an invalid receipt so it cannot be replayed or uploaded as a report.
    let bytes = runtime::with_cleanup(read, fs::remove_file(&path).map_err(Into::into))?;
    let receipt: Receipt =
        serde_json::from_slice(&bytes).context("invalid Windows security receipt")?;
    verify_receipt(&receipt, report)?;
    let passed = events::passed_cases(report);
    let mut reports = Vec::new();
    for (population, name, compiled, filename) in [
        (
            "coverage",
            "coverage-census.json",
            COVERAGE,
            "coverage-debug.json",
        ),
        (
            "native-stage",
            "native-stage-census.json",
            STAGES,
            "native-stage-debug.json",
        ),
    ] {
        let bytes = crate::resource::bounded_read(&root.join("tests").join(name), 1024 * 1024)?;
        ensure!(
            bytes == compiled,
            "Windows census differs from compiled source"
        );
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        let contract: events::EventContract =
            serde_json::from_value(value["execution_contract"].clone())?;
        let scope = contract
            .scopes
            .iter()
            .find(|s| s.scope.job == "windows-security")
            .context("Windows census scope missing")?;
        let expected_ids = if population == "native-stage" {
            receipt.stage_ids.clone()
        } else {
            [
                "coverage::windows-controls",
                "coverage::docx-case-relationships",
                "coverage::static-output-links",
            ]
            .map(str::to_owned)
            .to_vec()
        };
        ensure!(
            scope.entry_ids == expected_ids && scope.owner_case_id == OWNER,
            "Windows census inventory differs"
        );
        let mut events = Vec::new();
        for (index, id) in expected_ids.iter().enumerate() {
            let entry = contract
                .entries
                .iter()
                .find(|entry| &entry.id == id)
                .context("Windows event metadata missing")?;
            ensure!(
                entry
                    .checks
                    .iter()
                    .flat_map(|check| &check.witness_ids)
                    .all(|id| passed.contains(id)),
                "Windows check witness did not execute"
            );
            events.push(OperationEvent {
                case_id: id.clone(),
                parent_id: entry.parent_id.clone(),
                sequence: index + 1,
                invokes_ids: entry.invokes_ids.clone(),
                obligation_ids: entry.obligation_ids.clone(),
                source: "execution".into(),
                outcome: CaseOutcome::Passed,
                exit: 0,
                cleanup_complete: true,
                assertions_complete: true,
                variants: entry
                    .variant_ids
                    .iter()
                    .map(|id| VariantOutcome {
                        id: id.clone(),
                        outcome: CaseOutcome::Passed,
                    })
                    .collect(),
                check_results: entry
                    .checks
                    .iter()
                    .map(|check| CheckOutcome {
                        check_id: check.id.clone(),
                        witness_ids: check.witness_ids.clone(),
                        outcome: CaseOutcome::Passed,
                    })
                    .collect(),
            });
        }
        reports.push((
            parent.join(filename),
            OperationReport {
                schema: 1,
                population: population.into(),
                tested_sha: report.tested_sha.clone(),
                run_id: report.run_id.clone(),
                run_attempt: report.run_attempt.clone(),
                repository: report.repository.clone(),
                workflow_ref: report.workflow_ref.clone(),
                scope: scope.scope.clone(),
                baseline_commit: value["baseline_commit"]
                    .as_str()
                    .context("Windows census baseline missing")?
                    .into(),
                census_sha256: format!("{:x}", Sha256::digest(&bytes)),
                events,
            },
        ));
    }
    let censuses = events::load_censuses(root)?
        .into_iter()
        .filter(|c| c.population == "coverage" || c.population == "native-stage")
        .map(|mut c| {
            if let Some(contract) = &mut c.contract {
                contract
                    .scopes
                    .retain(|scope| scope.scope.job == "windows-security");
                contract.entries.retain(|entry| {
                    contract
                        .scopes
                        .iter()
                        .any(|scope| scope.entry_ids.contains(&entry.id))
                });
                c.ids = contract
                    .entries
                    .iter()
                    .map(|entry| entry.id.clone())
                    .collect();
            }
            c
        })
        .collect::<Vec<_>>();
    let operations = reports
        .iter()
        .map(|(_, report)| report.clone())
        .collect::<Vec<_>>();
    events::validate_populations(
        &censuses,
        &operations,
        std::slice::from_ref(report),
        (
            &report.tested_sha,
            &report.run_id,
            &report.run_attempt,
            &report.repository,
            &report.workflow_ref,
        ),
    )?;
    for (path, report) in reports {
        write_json(&path, &report)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn markers() -> String {
        (1..=53_i32)
            .flat_map(|i| {
                ["before", "after"].map(|state| {
                    let state = state.to_owned();
                    let index = i.to_string();
                    format!("WINDOWS_BOOTSTRAP phase=managed state={state} index={index}\r\n")
                })
            })
            .chain((0..=3_i32).flat_map(|i| {
                ["before", "after"].map(|state| {
                    let state = state.to_owned();
                    let index = i.to_string();
                    format!("WINDOWS_BOOTSTRAP_DIRECT state={state} index={index}\n")
                })
            }))
            .collect()
    }
    #[test]
    fn receipt_binding_and_all_standalone_cleanup_are_required() {
        let mut report = CollectedExecution {
            schema: 1,
            tested_sha: "a".repeat(40),
            run_id: "1".into(),
            run_attempt: "1".into(),
            repository: "example/revayat".into(),
            workflow_ref: "example/revayat/.github/workflows/ci.yml@refs/heads/test".into(),
            job: "windows-security".into(),
            platform: "windows".into(),
            tier: "native".into(),
            profile: "debug".into(),
            ignored_only: true,
            binaries: vec![
                BinaryExecution {
                    target: OWNER.split_once("::").unwrap().0.into(),
                    mapping_target: Some("windows_native".into()),
                    exit: Some(0),
                    cleanup_complete: true,
                    cases: [(
                        OWNER.split_once("::").unwrap().1.into(),
                        CaseOutcome::Passed,
                    )]
                    .into(),
                    error: None,
                },
                BinaryExecution {
                    target: STANDALONE.into(),
                    mapping_target: Some("windows_standalone".into()),
                    exit: Some(0),
                    cleanup_complete: true,
                    cases: CASES.map(|case| (case.into(), CaseOutcome::Passed)).into(),
                    error: None,
                },
            ],
            error: None,
            discovery_exit: None,
            final_parity_verified: false,
        };
        let mut receipt = Receipt {
            schema: 1,
            tested_sha: report.tested_sha.clone(),
            run_id: report.run_id.clone(),
            run_attempt: report.run_attempt.clone(),
            repository: report.repository.clone(),
            workflow_ref: report.workflow_ref.clone(),
            job: report.job.clone(),
            stage_ids: stage_ids(),
        };
        verify_receipt(&receipt, &report).unwrap();
        receipt.run_attempt = "2".into();
        assert!(verify_receipt(&receipt, &report).is_err());
        receipt.run_attempt = "1".into();
        report.binaries[1].cleanup_complete = false;
        assert!(verify_receipt(&receipt, &report).is_err());
        report.binaries[1].cleanup_complete = true;
        for case in CASES {
            report.binaries[1]
                .cases
                .insert(case.into(), CaseOutcome::Failed);
            assert!(verify_receipt(&receipt, &report).is_err());
            report.binaries[1]
                .cases
                .insert(case.into(), CaseOutcome::Passed);
        }
    }
    #[test]
    fn ordered_receipt_refuses_missing_duplicate_reordered_or_incomplete_controls() {
        let out = b"WINDOWS_KERNEL_CONTROL role=primary run=test status=passed network=True quota=True\nWINDOWS_KERNEL_SESSION original_access_denied=True restored_access_denied=True host_surface_restored=True volume_policy_restored=True wall_tree_terminated=True wall_actual_exit=1 target_admitted=False\n";
        let complete = markers();
        assert_eq!(verify_output(out, complete.as_bytes()).unwrap().len(), 57);
        for bad in [
            complete.replacen("state=after index=53", "state=before index=53", 1),
            complete.replacen("WINDOWS_BOOTSTRAP_DIRECT state=after index=3\n", "", 1),
            format!("{complete}WINDOWS_BOOTSTRAP_DIRECT state=after index=3\n"),
            complete.replacen("index=1\r\n", "index=2\r\n", 1),
        ] {
            assert!(verify_output(out, bad.as_bytes()).is_err());
        }
        for field in [
            "quota=True",
            "network=True",
            "target_admitted=False",
            "host_surface_restored=True",
        ] {
            let bad = std::str::from_utf8(out)
                .unwrap()
                .replace(field, "invalid=False");
            assert!(verify_output(bad.as_bytes(), complete.as_bytes()).is_err());
        }
    }
}
