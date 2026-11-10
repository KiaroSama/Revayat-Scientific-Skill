//! A separate bounded helper boundary, preserving the pre-Rust security tier.
use crate::{
    identity::{file_identity, is_link},
    tex_container as tex, tex_supervisor,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{fs, path::PathBuf};

fn worker() -> Result<PathBuf> {
    let executable = std::env::current_exe()?;
    let parent = executable
        .parent()
        .context("native executable has no parent")?;
    let parent = if parent.file_name().is_some_and(|name| name == "deps") {
        parent
            .parent()
            .context("test binary has no release parent")?
    } else {
        parent
    };
    let path = parent.join("revayat-security-worker");
    for ancestor in path.ancestors() {
        ensure!(
            !is_link(ancestor)?,
            "native helper executable path contains a link"
        );
    }
    ensure!(
        path.is_file(),
        "native security worker sibling is missing; build revayat-security-worker beside the CLI"
    );
    Ok(path)
}

pub fn security() -> Result<Value> {
    ensure!(
        cfg!(target_os = "linux"),
        "helper containment gate requires native Linux"
    );
    let config = tex::runtime_config()?;
    ensure!(
        config.kind == "docker",
        "native helper gate requires Docker"
    );
    let executable = worker()?;
    let companion = executable
        .parent()
        .context("worker has no parent")?
        .join("revayat-process-owner");
    for ancestor in companion.ancestors() {
        ensure!(
            !is_link(ancestor)?,
            "native helper companion path contains a link"
        );
    }
    let original = file_identity(&executable, Some(64 * 1024 * 1024))?;
    let companion_original = file_identity(&companion, Some(64 * 1024 * 1024))?;
    let stage = tempfile::Builder::new()
        .prefix(".revayat-tex-helper-")
        .tempdir()?;
    let public = stage.path().join("public");
    let empty = stage.path().join("empty-dev");
    fs::create_dir(&public)?;
    fs::create_dir(&empty)?;
    let pinned = public.join("security-worker");
    let pinned_companion = public.join("revayat-process-owner");
    fs::copy(&executable, &pinned)?;
    fs::copy(&companion, &pinned_companion)?;
    ensure!(
        file_identity(&executable, Some(64 * 1024 * 1024))? == original
            && file_identity(&pinned, Some(64 * 1024 * 1024))?.same_bytes(&original),
        "native worker changed while preparing checked public view"
    );
    ensure!(
        file_identity(&companion, Some(64 * 1024 * 1024))? == companion_original
            && file_identity(&pinned_companion, Some(64 * 1024 * 1024))?
                .same_bytes(&companion_original),
        "native companion changed while preparing checked public view"
    );
    let coverage = include_bytes!("../../../tests/security/coverage.json");
    let _: Value = serde_json::from_slice(coverage)?;
    fs::write(public.join("coverage.json"), coverage)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&public, &empty] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
        }
        fs::set_permissions(&pinned, fs::Permissions::from_mode(0o555))?;
        fs::set_permissions(&pinned_companion, fs::Permissions::from_mode(0o555))?;
        fs::set_permissions(
            public.join("coverage.json"),
            fs::Permissions::from_mode(0o444),
        )?;
    }
    let run = tex_supervisor::new_token();
    let mut args = config.base.clone();
    args.extend([
        "run".into(),
        "--rm".into(),
        "--pull=never".into(),
        "--name".into(),
        format!("revayat-tex-{run}"),
        "--label".into(),
        format!("{}={run}", tex::RUN_LABEL),
        "--cidfile".into(),
        stage
            .path()
            .join("container.cid")
            .to_str()
            .context("helper staging is not UTF-8")?
            .into(),
        "--network=none".into(),
        "--read-only".into(),
        "--cap-drop=ALL".into(),
        "--security-opt=no-new-privileges".into(),
        "--pids-limit=64".into(),
        "--memory=1g".into(),
        "--memory-swap=1g".into(),
        "--cpus=2".into(),
        "--ulimit".into(),
        "fsize=67108864:67108864".into(),
        "--ulimit".into(),
        "nofile=128:128".into(),
        "--log-driver=none".into(),
        "--tmpfs".into(),
        "/scratch:rw,noexec,nosuid,nodev,size=134217728".into(),
        "--workdir=/".into(),
        "--mount".into(),
        tex::mount_argument(&public, "/target", true)?,
        "--mount".into(),
        tex::mount_argument(&empty, "/dev/shm", true)?,
        "--mount".into(),
        tex::mount_argument(&empty, "/dev/mqueue", true)?,
        "--user".into(),
        "65532:65532".into(),
        "--entrypoint=/usr/bin/timeout".into(),
        config.image.clone(),
        "--signal=TERM".into(),
        "--kill-after=2s".into(),
        "90s".into(),
        "/usr/local/bin/revayat-sandbox-probe".into(),
        "--helper-entry".into(),
    ]);
    let (stage, text) = super::run_owned(
        &config,
        stage,
        &run,
        &args,
        110,
        &[("REVAYAT_HOST_ONLY_CANARY", &run)],
    )?;
    ensure!(
        file_identity(&executable, Some(64 * 1024 * 1024))? == original
            && file_identity(
                &stage.path().join("public/security-worker"),
                Some(64 * 1024 * 1024)
            )?
            .same_bytes(&original),
        "native checked worker changed during containment"
    );
    ensure!(
        file_identity(&companion, Some(64 * 1024 * 1024))? == companion_original
            && file_identity(
                &stage.path().join("public/revayat-process-owner"),
                Some(64 * 1024 * 1024)
            )?
            .same_bytes(&companion_original),
        "native checked companion changed during containment"
    );
    let records = text
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("native helper emitted an invalid structured result")?;
    let proofs = records
        .iter()
        .filter(|item| item["phase"] == "helper-preflight")
        .collect::<Vec<_>>();
    ensure!(
        proofs.len() == 1
            && records
                .first()
                .is_some_and(|item| item["phase"] == "helper-preflight")
            && proofs[0]["status"] == "passed"
            && proofs[0]["checks"] == 39
            && proofs[0]["environment_names"] == 7
            && proofs[0]["scratch_bytes"] == 134_217_728
            && proofs[0]["file_bytes"] == 67_108_864,
        "trusted native helper preflight did not verify its boundary"
    );
    let summaries = records
        .iter()
        .filter(|item| item["phase"] == "security-scenarios")
        .collect::<Vec<_>>();
    let expected = json!({"phase":"security-scenarios","status":"passed","admission_checks":30,"tex_output_checks":6,"production_output_aggregate_quota":"unresolved"});
    ensure!(
        summaries.len() == 1 && *summaries[0] == expected && records.last() == Some(&expected),
        "native helper scenarios failed, missing or incomplete"
    );
    let cases = verified_cases(&records)?;
    Ok(
        json!({"preflight":proofs[0],"scenarios":summaries[0],"cases":cases,"run_id":run,"worker_sha256":original.sha256,"container_cleanup":"verified"}),
    )
}

/// A summary cannot substitute for each actual isolated worker outcome.
fn verified_cases(records: &[Value]) -> Result<Vec<Value>> {
    use std::collections::BTreeSet;
    let cases = records
        .iter()
        .filter(|row| row["phase"] == "security-case")
        .cloned()
        .collect::<Vec<_>>();
    let expected = crate::security_cases::IDS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    ensure!(
        records.len() == cases.len() + 2,
        "unexpected isolated worker record"
    );
    for (index, row) in cases.iter().enumerate() {
        let id = row["id"].as_str().context("security case ID missing")?;
        ensure!(
            row == &json!({"phase":"security-case","id":id,"status":"passed"})
                && actual.insert(id)
                && expected.contains(id)
                && crate::security_cases::IDS.get(index) == Some(&id),
            "invalid or duplicate isolated security case outcome"
        );
    }
    ensure!(
        actual == expected,
        "isolated security case outcomes incomplete"
    );
    Ok(cases)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_summary_never_replaces_complete_unique_case_outcomes() {
        assert_eq!(
            super::super::failure_category(
                "sandbox enforcement failed: probe-control-08: PRIVATE_CANARY"
            ),
            "control=08"
        );
        for text in [
            "PRIVATE_CANARY",
            "sandbox enforcement failed: probe-control-PRIVATE: secret",
            "sandbox enforcement failed: probe-control-99: secret",
        ] {
            assert_eq!(
                super::super::failure_category(text),
                "diagnostic=unclassified"
            );
        }
        let rows = crate::security_cases::IDS
            .iter()
            .map(|id| json!({"phase":"security-case","id":id,"status":"passed"}))
            .collect::<Vec<_>>();
        let qualified = |rows: &[Value]| {
            let mut qualified = vec![json!({"phase":"helper-preflight"})];
            qualified.extend_from_slice(rows);
            qualified.push(json!({"phase":"security-scenarios"}));
            qualified
        };
        assert_eq!(verified_cases(&qualified(&rows)).unwrap(), rows);
        for altered in [
            rows[..35].to_vec(),
            vec![rows[0].clone(); 36],
            vec![json!({"phase":"security-scenarios","status":"passed"})],
        ] {
            assert!(verified_cases(&qualified(&altered)).is_err());
        }
        let mut failed = rows;
        failed[0]["status"] = json!("failed");
        assert!(verified_cases(&qualified(&failed)).is_err());
    }
}
