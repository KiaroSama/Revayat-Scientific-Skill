//! Verify effective Linux controls using the production container launch path.
use crate::{tex_container as tex, tex_supervisor};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::fs;
#[path = "sandbox_helper.rs"]
mod helper;
pub use helper::security;
#[cfg(test)]
pub(crate) use helper::tests::worker_summary_never_replaces_complete_unique_case_outcomes;

fn run_owned(
    config: &tex::RuntimeConfig,
    stage: tempfile::TempDir,
    run: &str,
    args: &[String],
    timeout: u64,
    environment: &[(&str, &str)],
) -> Result<(tempfile::TempDir, String, u64)> {
    let directory = stage.path();
    let receipt = tex_supervisor::register(config, directory, run)?;
    let started = std::time::Instant::now();
    let outcome =
        tex::call_with_environment(args, timeout, environment).and_then(|(code, text)| {
            ensure!(
                code == 0,
                "native sandbox failed (exit {code}; {})",
                failure_category(&text)
            );
            let elapsed = started.elapsed();
            ensure!(
                elapsed <= std::time::Duration::from_secs(timeout),
                "native sandbox exceeded its configured host wall budget"
            );
            Ok((text, u64::try_from(elapsed.as_millis())?))
        });
    let cleanup = tex::cleanup(config, directory, run, false);
    let (stage, (text, elapsed)) = tex::finalize::finish_stage(
        stage,
        run,
        outcome,
        cleanup,
        || tex_supervisor::acknowledge(receipt.as_deref()),
        tex::finalize::recovery,
    )?;
    Ok((stage, text, elapsed))
}

/// Fixed probe/control and authored case identities only; never echo child text.
fn failure_category(text: &str) -> String {
    for line in text.lines() {
        if let Some((code, _)) = line
            .strip_prefix("sandbox enforcement failed: probe-control-")
            .and_then(|value| value.split_once(':'))
            && code.len() == 2
            && code.bytes().all(|value| value.is_ascii_digit())
            && code
                .parse::<u8>()
                .is_ok_and(|value| (1..=39).contains(&value))
        {
            return format!("control={code}");
        }
    }
    let mut failed = std::collections::BTreeSet::new();
    for line in text.lines() {
        if let Ok(row) = serde_json::from_str::<Value>(line)
            && row["phase"] == "security-case"
            && row["status"] == "failed"
            && let Some(id) = row["id"].as_str()
            && crate::security_cases::IDS.contains(&id)
        {
            failed.insert(id.to_owned());
        }
    }
    if failed.is_empty() {
        "diagnostic=unclassified".into()
    } else {
        format!("cases={}", failed.into_iter().collect::<Vec<_>>().join(","))
    }
}

pub fn probe() -> Result<Value> {
    let config = tex::runtime_config()?;
    ensure!(
        config.kind == "docker",
        "native Linux enforcement gate requires Docker"
    );
    let stage = tempfile::Builder::new()
        .prefix(".revayat-tex-probe-")
        .tempdir()?;
    let directory = stage.path();
    fs::create_dir(directory.join("input"))?;
    fs::create_dir(directory.join("output"))?;
    fs::write(
        directory.join("input/sentinel.txt"),
        b"public sandbox fixture",
    )?;
    fs::write(
        directory.join("input").join(tex::STAGED_MAIN),
        r"\documentclass{article}
\newwrite\probe
\begin{document}
\immediate\openout\probe=public-one.txt
\immediate\write\probe{public harmless first}
\immediate\closeout\probe
\immediate\openout\probe=public-two.txt
\immediate\write\probe{public harmless second}
\immediate\closeout\probe
Ordinary scientific document.
\end{document}",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.join("output"), fs::Permissions::from_mode(0o777))?;
    }
    fs::write(
        directory.join("host-private-sentinel"),
        b"public enforcement fixture outside the input mount",
    )?;
    let run = tex_supervisor::new_token();
    let arguments = tex::run_arguments(&config, directory, "probe.tex", &run)?;
    let receipt = tex_supervisor::register(&config, directory, &run)?;
    let outcome = (|| {
        let (code, _) =
            tex::call_with_environment(&arguments, 15, &[("REVAYAT_HOST_ONLY_CANARY", &run)])?;
        ensure!(code == 0, "native sandbox launch failed");
        let identifier = tex::verified_container_with(&config, directory, &run, &mut tex::call)?;
        let mut arguments = config.base.clone();
        arguments.extend([
            "exec".into(),
            identifier,
            "/usr/bin/timeout".into(),
            "--signal=TERM".into(),
            "--kill-after=5s".into(),
            "60s".into(),
            "/usr/local/bin/revayat-sandbox-probe".into(),
        ]);
        let (code, text) =
            tex::call_with_environment(&arguments, 75, &[("REVAYAT_HOST_ONLY_CANARY", &run)])?;
        ensure!(
            code == 0,
            "native sandbox failed (exit {code}; {})",
            failure_category(&text)
        );
        tex::copy_outputs_with(
            &config,
            directory,
            &run,
            &[
                "sandbox-verified.json",
                "probe.txt",
                "document.pdf",
                "public-one.txt",
                "public-two.txt",
            ],
            &mut tex::call,
        )
    })();
    let cleanup = tex::cleanup(&config, directory, &run, false);
    let (stage, _) = tex::finalize::finish_stage(
        stage,
        &run,
        outcome,
        cleanup,
        || tex_supervisor::acknowledge(receipt.as_deref()),
        tex::finalize::recovery,
    )?;
    verify_probe_output(stage.path())?;
    Ok(
        json!({"verified":true,"checks":29,"run_id":run,"container_cleanup":"verified","production_output_aggregate_quota":"verified","output_mount":"tmpfs","output_bytes":tex::MAX_OUTPUT_BYTES,"per_file_bytes":tex::MAX_OUTPUT_BYTES,"per_file_efbig":true,"aggregate_enospc":true,"tex_openout_files":2,"ordinary_pdf":true}),
    )
}

/// Verify actual mounted input/output bytes as well as the native control report.
pub fn verify_probe_output(directory: &std::path::Path) -> Result<()> {
    let read = |name: &str, limit: u64| -> Result<Vec<u8>> {
        use std::io::Read;
        let path = directory.join(name);
        ensure!(
            !crate::identity::is_link(&path)?
                && fs::metadata(&path)?.is_file()
                && fs::metadata(&path)?.len() <= limit,
            "invalid bounded sandbox evidence"
        );
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(limit + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= limit,
            "sandbox evidence grew beyond bound"
        );
        Ok(bytes)
    };
    let proof: Value = serde_json::from_slice(&read("output/sandbox-verified.json", 4096)?)?;
    ensure!(
        proof
            == json!({"verified":true,"checks":29,"output_mount":"tmpfs","output_bytes":268435456,"per_file_bytes":268435456,"per_file_efbig":true,"aggregate_enospc":true,"tex_openout_files":2,"ordinary_pdf":true}),
        "native probe did not verify every effective control"
    );
    ensure!(
        read("input/sentinel.txt", 64)? == b"public sandbox fixture",
        "sandbox changed approved input bytes"
    );
    ensure!(
        read("output/probe.txt", 64)? == b"allowed output\n",
        "sandbox did not preserve exact allowed output"
    );
    for (name, expected) in [
        ("public-one.txt", b"public harmless first\n".as_slice()),
        ("public-two.txt", b"public harmless second\n".as_slice()),
    ] {
        ensure!(
            read(&format!("output/{name}"), 1024)? == expected,
            "sandbox did not preserve harmless TeX openout output"
        );
    }
    crate::pdf::validate_pdf(&directory.join("output/document.pdf"))?;
    Ok(())
}

pub fn cli(args: &[String]) -> Result<i32> {
    ensure!(
        args.is_empty(),
        "security-linux takes no arguments; it runs the mandatory production isolation probe"
    );
    ensure!(
        cfg!(target_os = "linux"),
        "native Linux enforcement gate must run on Linux"
    );
    let production = probe()?;
    let helper = security()?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({"production":production,"helper":helper}))?
    );
    Ok(0)
}
