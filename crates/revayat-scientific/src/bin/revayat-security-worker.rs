//! Fixed native admission worker, launched only after the trusted image probe.
use anyhow::{Result, ensure};
use revayat_scientific::{
    images, lint,
    security_cases::{Cases, IDS},
};
use serde_json::json;
use std::{collections::BTreeSet, path::Path};
fn run() -> Result<i32> {
    ensure!(
        cfg!(target_os = "linux"),
        "native security worker requires Linux"
    );
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().map(String::as_str) == Some("--lint-admission") {
        ensure!(
            args.len() == 2,
            "fixed lint admission requires one authored fixture"
        );
        let path = Path::new(&args[1]);
        images::plain_path(path)?;
        ensure!(
            path.is_file()
                && path.canonicalize()?.starts_with("/scratch/tmp")
                && matches!(
                    path.file_name().and_then(|s| s.to_str()),
                    Some("good.html" | "depth.html" | "nodes.html")
                ),
            "lint child requires a fixed authored scratch fixture"
        );
        return lint::cli_lint(&[args[1].clone()]);
    }
    ensure!(args.is_empty(), "security worker accepts no arguments");
    let expected = BTreeSet::from([
        "PATH",
        "HOME",
        "TMPDIR",
        "XDG_CACHE_HOME",
        "LANG",
        "LC_ALL",
        "REVAYAT_SECURITY_TIER",
    ]);
    ensure!(
        std::env::vars()
            .map(|(name, _)| name)
            .collect::<BTreeSet<_>>()
            == expected.into_iter().map(str::to_owned).collect(),
        "security worker environment differs from trusted helper allowlist"
    );
    ensure!(
        std::env::var("TMPDIR")? == "/scratch/tmp"
            && std::env::var("HOME")? == "/scratch/home"
            && std::env::var("REVAYAT_SECURITY_TIER")? == "linux"
            && std::env::current_dir()? == Path::new("/scratch/work"),
        "security worker is outside its fixed scratch boundary"
    );
    let temp = tempfile::Builder::new()
        .prefix("security-admissions-")
        .tempdir_in("/scratch/tmp")?;
    let mut cases = Cases::new(temp.path(), &std::env::current_exe()?, true)?;
    let mut log = revayat_scientific::runtime::OperationLog::create(
        "security-worker",
        Path::new("/scratch/home/logs"),
        Some("INFO"),
    )?;
    ensure!(
        log.path().is_some(),
        "security worker requires its private UTF-8 operation log"
    );
    log.info("started isolated_target_phase=true");
    ensure!(
        IDS.len() == 36 && IDS.iter().collect::<BTreeSet<_>>().len() == 36,
        "security case inventory changed"
    );
    let mut passed = Vec::new();
    let mut failed = Vec::new();
    for id in IDS {
        log.info(&format!("scenario_started id={id}"));
        match cases.run(id) {
            Ok(()) => {
                passed.push(*id);
                log.info(&format!("scenario_completed id={id}"));
                println!(
                    "{}",
                    json!({"phase":"security-case","id":id,"status":"passed"})
                );
            }
            Err(error) => {
                failed.push(*id);
                log.write("ERROR", &format!("scenario_failed id={id}"));
                println!(
                    "{}",
                    json!({"phase":"security-case","id":id,"status":"failed","reason":format!("{error:#}").chars().take(512).collect::<String>()})
                );
            }
        }
    }
    ensure!(
        failed.is_empty(),
        "fixed security admissions failed: {}",
        failed.join(", ")
    );
    ensure!(passed.len() == 36, "security case inventory changed");
    println!(
        "{}",
        json!({"phase":"security-scenarios","status":"passed","admission_checks":30,"tex_output_checks":6,"production_output_aggregate_quota":"unresolved"})
    );
    Ok(0)
}
fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("security-worker: {error:#}");
            2
        }
    };
    std::process::exit(code);
}
