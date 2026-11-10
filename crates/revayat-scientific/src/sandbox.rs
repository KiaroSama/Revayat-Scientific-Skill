//! Verify effective Linux controls using the production container launch path.
use crate::{tex_container as tex, tex_supervisor};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::fs;
#[path = "sandbox_helper.rs"]
mod helper;
pub use helper::security;

fn run_owned(
    config: &tex::RuntimeConfig,
    stage: tempfile::TempDir,
    run: &str,
    args: &[String],
    timeout: u64,
    environment: &[(&str, &str)],
) -> Result<(tempfile::TempDir, String)> {
    let directory = stage.path();
    let receipt = tex_supervisor::register(config, directory, run)?;
    let outcome =
        tex::call_with_environment(args, timeout, environment).and_then(|(code, text)| {
            ensure!(code == 0, "native sandbox failed (exit {code})");
            Ok(text)
        });
    let cleanup = tex::cleanup(config, directory, run, false);
    tex::finalize::finish_stage(
        stage,
        run,
        outcome,
        cleanup,
        || tex_supervisor::acknowledge(receipt.as_deref()),
        tex::finalize::recovery,
    )
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
    let mut arguments = tex::run_arguments(&config, directory, "probe.tex", &run)?;
    let image = arguments
        .iter()
        .position(|arg| arg == &config.image)
        .context("production launch omitted immutable image")?;
    arguments.truncate(image + 1);
    arguments.extend([
        "--signal=TERM".into(),
        "--kill-after=5s".into(),
        "20s".into(),
        "/usr/local/bin/revayat-sandbox-probe".into(),
    ]);
    let (stage, _) = run_owned(
        &config,
        stage,
        &run,
        &arguments,
        35,
        &[("REVAYAT_HOST_ONLY_CANARY", &run)],
    )?;
    verify_probe_output(stage.path())?;
    Ok(
        json!({"verified":true,"checks":29,"run_id":run,"container_cleanup":"verified","production_output_aggregate_quota":"unresolved"}),
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
        proof == json!({"verified":true,"checks":29}),
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
