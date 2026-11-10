//! Actual native execution. Flat outcomes never manufacture bootstrap/census events.
use super::*;

pub(super) const LINUX_TARGET: &str = "crates/revayat-scientific/bin/revayat-security-worker";
const WINDOWS_TARGETS: &[&str] = &["windows_native", "windows_standalone"];

pub(super) fn validate_targets(artifacts: &[Artifact]) -> Result<()> {
    ensure!(
        WINDOWS_TARGETS.iter().all(|required| artifacts
            .iter()
            .any(|artifact| artifact.mapping_target.as_deref() == Some(*required))),
        "required native Windows harness missing"
    );
    Ok(())
}

pub(super) fn select(
    target: Option<&str>,
    all: &BTreeSet<String>,
    ignored: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    if !target.is_some_and(|target| WINDOWS_TARGETS.contains(&target)) {
        return Ok(BTreeSet::new());
    }
    ensure!(
        !all.is_empty() && ignored.is_empty(),
        "native Windows harness must execute every case"
    );
    Ok(all.clone())
}

pub(super) fn linux(timeout: Duration) -> BinaryExecution {
    let mut binary = BinaryExecution {
        target: LINUX_TARGET.into(),
        mapping_target: Some("standalone_security".into()),
        exit: None,
        cleanup_complete: false,
        cases: BTreeMap::new(),
        error: None,
    };
    let result = (|| -> Result<BTreeMap<String, CaseOutcome>> {
        ensure!(
            timeout >= Duration::from_secs(150),
            "native collection deadline is too short for the fixed containment gates"
        );
        // These return only after actual control observations and owned container cleanup.
        // Neither a host-side parser test nor libtest registration qualifies this worker.
        crate::sandbox::probe()?;
        let helper = crate::sandbox::security()?;
        linux_cases(&helper)
    })();
    match result {
        Ok(cases) => {
            binary.cases = cases;
            binary.exit = Some(0);
            binary.cleanup_complete = true;
        }
        Err(_) => {
            binary.error =
                Some("native containment, isolated worker or owned cleanup incomplete".into())
        }
    }
    binary
}

fn linux_cases(helper: &serde_json::Value) -> Result<BTreeMap<String, CaseOutcome>> {
    let names = crate::security_cases::CASE_NAMES
        .iter()
        .copied()
        .collect::<BTreeMap<_, _>>();
    ensure!(
        names.len() == 36
            && names.keys().copied().collect::<BTreeSet<_>>()
                == crate::security_cases::IDS.iter().copied().collect(),
        "native worker counterpart inventory differs"
    );
    ensure!(
        helper["container_cleanup"] == "verified" && helper["preflight"]["status"] == "passed",
        "isolated worker qualification missing"
    );
    let rows = helper["cases"]
        .as_array()
        .context("actual isolated case outcomes missing")?;
    let mut cases = BTreeMap::new();
    for row in rows {
        let id = row["id"]
            .as_str()
            .context("isolated case identity missing")?;
        let name = *names.get(id).context("unknown isolated case")?;
        ensure!(
            row == &serde_json::json!({"phase":"security-case","id":id,"status":"passed"})
                && cases.insert(name.to_owned(), CaseOutcome::Passed).is_none(),
            "isolated case failed or duplicated"
        );
    }
    ensure!(
        cases.len() == names.len(),
        "isolated case execution incomplete"
    );
    Ok(cases)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_selection_requires_actual_nonignored_harnesses() {
        let all = BTreeSet::from(["one".into(), "two".into()]);
        assert_eq!(
            select(Some("windows_native"), &all, &BTreeSet::new()).unwrap(),
            all
        );
        assert!(select(Some("windows_native"), &all, &all).is_err());
        assert!(
            select(
                Some("windows_standalone"),
                &BTreeSet::new(),
                &BTreeSet::new()
            )
            .is_err()
        );
        assert!(
            select(Some("portable_model"), &all, &BTreeSet::new())
                .unwrap()
                .is_empty()
        );
        assert!(validate_targets(&[]).is_err());
    }
    #[test]
    fn worker_outcomes_require_real_qualification_and_each_exact_case() {
        let mut helper = serde_json::json!({"container_cleanup":"verified", "preflight":{"status":"passed"},
            "cases":crate::security_cases::IDS.iter().map(|id|
                serde_json::json!({"phase":"security-case","id":id,"status":"passed"})).collect::<Vec<_>>()});
        assert_eq!(linux_cases(&helper).unwrap().len(), 36);
        helper["container_cleanup"] = serde_json::json!("unknown");
        assert!(linux_cases(&helper).is_err());
        helper["container_cleanup"] = serde_json::json!("verified");
        helper["cases"].as_array_mut().unwrap().pop();
        assert!(linux_cases(&helper).is_err());
        let duplicate = helper["cases"][0].clone();
        helper["cases"].as_array_mut().unwrap().push(duplicate);
        assert!(linux_cases(&helper).is_err());
    }
}
