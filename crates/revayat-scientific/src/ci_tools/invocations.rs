//! Invocation-only workflow and container command contracts.
use anyhow::{Context, Result, ensure};
use serde_json::Value;

const PROGRAMS: &[&str] = &[
    "cargo",
    "brew",
    "sudo",
    "docker",
    "zizmor",
    "actionlint",
    "git",
    "rustc",
    "target/debug/revayat-scientific",
    "/usr/bin/test",
    "/usr/bin/fc-cache",
    "/usr/bin/apt-get",
    "/usr/bin/rm",
    "/usr/bin/timeout",
    "/usr/local/bin/revayat-tex-entry",
];

fn program(argv: &[&str]) -> Result<()> {
    let first = argv.first().context("empty executable invocation")?;
    ensure!(
        PROGRAMS.contains(first),
        "workflow executable is not allowlisted"
    );
    ensure!(
        !argv
            .iter()
            .any(|arg| matches!(*arg, "-c" | "-Command" | "-EncodedCommand" | "--no-sandbox")),
        "embedded interpreter programs are forbidden"
    );
    if *first == "cargo" {
        ensure!(
            !argv
                .iter()
                .any(|arg| *arg == "--config" || arg.starts_with("--config=")),
            "workflow Cargo configuration must not override executable runners"
        );
    }
    if *first == "brew" {
        ensure!(
            argv == ["brew", "install", "poppler"],
            "brew is limited to hosted Poppler setup"
        );
    }
    if *first == "sudo" {
        ensure!(
            argv.get(1) == Some(&"apt-get"),
            "sudo is limited to the required package manager"
        );
    }
    Ok(())
}

fn command(source: &str) -> Result<()> {
    // PowerShell reports the final native exit code, so each step owns one invocation.
    ensure!(
        source
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count()
            == 1,
        "workflow steps require one executable invocation for portable exit reporting"
    );
    for line in source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        ensure!(
            !line.contains([';', '|', '&', '`', '<', '>', '\\', '#', '$', '\'', '"'])
                && !line.contains("$(")
                && !line.contains("${{"),
            "workflow run steps must contain only direct executable invocations"
        );
        program(&line.split_whitespace().collect::<Vec<_>>())?;
    }
    ensure!(!source.trim().is_empty(), "empty workflow command");
    Ok(())
}

fn required(node: &Value) -> Result<()> {
    if let Some(shell) = node["defaults"]["run"].get("shell") {
        ensure!(
            shell
                .as_str()
                .is_some_and(|s| ["bash", "pwsh", "sh"].contains(&s)),
            "workflow default shell cannot be an interpreter program"
        );
    }
    if let Some(value) = node.get("continue-on-error") {
        ensure!(
            value == &Value::Bool(false),
            "required workflow failures cannot be ignored"
        );
    }
    Ok(())
}

pub(super) fn workflow(filename: &str, value: &Value) -> Result<()> {
    required(value)?;
    if matches!(
        filename,
        ".github/workflows/ci.yml"
            | ".github/workflows/security-ci.yml"
            | ".github/workflows/codeql.yml"
            | ".github/workflows/dependency-review.yml"
    ) {
        let triggers: &[&str] = if filename == ".github/workflows/ci.yml" {
            &["push", "pull_request", "workflow_dispatch"]
        } else {
            &["workflow_call"]
        };
        let events = value["on"]
            .as_object()
            .context("workflow trigger mapping missing")?;
        ensure!(
            events.len() == triggers.len()
                && triggers.iter().all(|trigger| events.contains_key(*trigger)),
            "CI root must run on pushes, pull requests and manual dispatch; children must be reusable only"
        );
    }
    for job in value["jobs"]
        .as_object()
        .context("workflow jobs mapping missing")?
        .values()
    {
        required(job)?;
        if let Some(steps) = job["steps"].as_array() {
            for step in steps {
                required(step)?;
                if let Some(shell) = step.get("shell") {
                    ensure!(
                        shell
                            .as_str()
                            .is_some_and(|s| ["bash", "pwsh", "sh"].contains(&s)),
                        "workflow shell cannot be an interpreter program"
                    );
                }
                if let Some(run) = step.get("run") {
                    command(run.as_str().context("workflow command must be text")?)?;
                }
            }
        }
    }
    Ok(())
}

pub fn docker(source: &str) -> Result<()> {
    let mut commands = 0;
    for line in source.lines().map(str::trim) {
        let Some((instruction, json)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        if ["RUN", "ENTRYPOINT", "CMD"].contains(&instruction.to_ascii_uppercase().as_str()) {
            let argv: Vec<String> =
                serde_json::from_str(json).context("Docker commands must use exec form")?;
            program(&argv.iter().map(String::as_str).collect::<Vec<_>>())?;
            commands += 1;
        }
    }
    ensure!(commands > 0, "Dockerfile has no executable commands");
    Ok(())
}
