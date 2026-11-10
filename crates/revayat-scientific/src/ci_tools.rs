//! Native workflow and exact stored commit identity checks.
use crate::runtime::{CommandSpec, run};
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
mod automation;
mod invocations;
mod poppler;
mod source_audit;
pub use invocations::docker as validate_docker_invocations;
pub use source_audit::classify_source;

pub const APPROVED_EMAIL: &str = "Kiaro.Sama.Dev@gmail.com";
pub const DEPENDABOT_EMAIL: &str = "49699333+dependabot[bot]@users.noreply.github.com";
fn git(repository: &Path, args: &[&str]) -> Result<String> {
    let mut spec = CommandSpec::new("git")
        .args(std::iter::once("--no-replace-objects").chain(args.iter().copied()));
    spec.cwd = Some(repository.to_owned());
    spec.timeout = Duration::from_secs(30);
    let output = run(&spec)?;
    ensure!(
        output.success(),
        "Git identity inspection failed; check repository and revisions"
    );
    Ok(String::from_utf8(output.stdout)?)
}
fn resolve(repository: &Path, revision: &str) -> Result<String> {
    let value = git(
        repository,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{revision}^{{commit}}"),
        ],
    )?;
    let value = value.trim();
    ensure!(
        [40, 64].contains(&value.len())
            && value
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "revision did not resolve to one commit"
    );
    Ok(value.to_owned())
}
pub type IdentityReport = (usize, Vec<(String, Vec<String>)>);
pub fn inspect_identities(
    repository: &Path,
    head: &str,
    base: Option<&str>,
) -> Result<IdentityReport> {
    if let Some(grafts) = std::env::var_os("GIT_GRAFT_FILE") {
        let path = PathBuf::from(grafts);
        ensure!(
            !path.exists() || fs::metadata(path)?.len() == 0,
            "environment-selected grafts can hide ancestry"
        );
    }
    ensure!(
        git(repository, &["rev-parse", "--is-shallow-repository"])?.trim() == "false",
        "shallow repository cannot establish complete commit identities"
    );
    let grafts =
        PathBuf::from(git(repository, &["rev-parse", "--git-path", "info/grafts"])?.trim());
    let grafts = if grafts.is_absolute() {
        grafts
    } else {
        repository.join(grafts)
    };
    ensure!(
        !grafts.exists() || fs::metadata(grafts)?.len() == 0,
        "legacy grafts can hide ancestry"
    );
    let head = resolve(repository, head)?;
    let revision = if let Some(base) = base {
        format!("{}..{head}", resolve(repository, base)?)
    } else {
        head
    };
    let raw = git(
        repository,
        &["log", "--format=%H%x00%ae%x00%ce", &revision, "--"],
    )?;
    let mut failures = Vec::new();
    let mut count = 0;
    for row in raw.lines() {
        count += 1;
        let fields: Vec<_> = row.split('\0').collect();
        ensure!(
            fields.len() == 3
                && [40, 64].contains(&fields[0].len())
                && fields[0].bytes().all(|c| c.is_ascii_hexdigit()),
            "malformed raw commit identity record"
        );
        let mut roles = Vec::new();
        for (role, email) in [("author", fields[1]), ("committer", fields[2])] {
            if email != APPROVED_EMAIL
                && email != DEPENDABOT_EMAIL
                && !(role == "committer" && email == "noreply@github.com")
            {
                roles.push(role.to_owned());
            }
        }
        if !roles.is_empty() {
            failures.push((fields[0].to_owned(), roles));
        }
    }
    Ok((count, failures))
}
pub fn cli_commit_identity(args: &[String]) -> Result<i32> {
    use clap::Parser;
    #[derive(Parser)]
    struct Options {
        #[arg(long, default_value = "HEAD")]
        head: String,
        #[arg(long, conflicts_with = "ci_base")]
        base: Option<String>,
        #[arg(long)]
        ci_base: bool,
    }
    let opts = Options::try_parse_from(
        std::iter::once("check-commit-identity".into()).chain(args.iter().cloned()),
    )?;
    let root = crate::distribution::repository_root()?;
    let selected = if opts.ci_base {
        Some(automation::base_from_environment(&root)?)
    } else {
        opts.base
    };
    let head = if opts.ci_base {
        std::env::var("HEAD_REF").context("CI head commit is required")?
    } else {
        opts.head
    };
    let (count, failures) = inspect_identities(&root, &head, selected.as_deref())?;
    if selected.is_some() {
        eprintln!("Introduced-commit check excludes earlier history.");
    }
    for (sha, roles) in &failures {
        eprintln!("Unapproved commit identity: {sha} ({})", roles.join(", "));
    }
    println!(
        "Identity check: {count} commits, {} mismatches; required owner email={APPROVED_EMAIL}; exact service roles permitted",
        failures.len()
    );
    Ok(i32::from(!failures.is_empty()))
}
/// Translate GitHub's dedicated self-repository syntax for actionlint 1.7.12.
/// Only the three reviewed calls change in memory; all diagnostics stay active.
pub fn actionlint_source(filename: &str, source: &str) -> Result<String> {
    if !source.contains("$/") {
        return Ok(source.to_owned());
    }
    ensure!(
        filename == ".github/workflows/ci.yml",
        "self-reference compatibility is limited to reviewed CI jobs"
    );
    let calls = [
        ("security", "security-ci"),
        ("codeql", "codeql"),
        ("dependency-review", "dependency-review"),
    ];
    let mut seen = std::collections::HashSet::new();
    let mut job = String::new();
    let mut jobs = false;
    let mut result = String::new();
    for line in source.split_inclusive('\n') {
        let plain = line.trim_end_matches(['\r', '\n']);
        if plain == "jobs:" {
            jobs = true;
        }
        if jobs && plain.starts_with("  ") && !plain.starts_with("   ") && plain.ends_with(':') {
            job = plain[2..plain.len() - 1].to_owned();
        }
        if line.contains("$/") {
            let target = calls
                .iter()
                .find(|c| c.0 == job)
                .context("unsupported self-repository workflow reference")?;
            ensure!(
                plain == format!("    uses: $/.github/workflows/{}.yml", target.1)
                    && seen.insert(target.0),
                "unsupported or duplicate self-repository workflow reference"
            );
            result.push_str(&line.replacen("$/", "./", 1));
        } else {
            result.push_str(line);
        }
    }
    ensure!(
        seen.len() == calls.len(),
        "self-reference compatibility requires all three reviewed calls"
    );
    Ok(result)
}
pub fn validate_workflow_contract(root: &Path, filename: &str, source: &str) -> Result<()> {
    let source = actionlint_source(filename, source)?;
    let value: serde_json::Value = serde_saphyr::from_str(&source)?;
    let jobs = value["jobs"]
        .as_object()
        .context("workflow jobs mapping missing")?;
    invocations::workflow(filename, &value)?;
    for job in jobs.values() {
        if let Some(reference) = job["uses"].as_str() {
            if let Some(local) = reference.strip_prefix("./") {
                ensure!(
                    local.starts_with(".github/workflows/")
                        && !local.contains("..")
                        && !local.contains('@'),
                    "unsupported local workflow reference"
                );
                let callee: serde_json::Value =
                    serde_saphyr::from_str(&fs::read_to_string(root.join(local))?)?;
                if let Some(inputs) = callee["on"]["workflow_call"]["inputs"].as_object() {
                    for (name, input) in inputs {
                        if input["required"].as_bool() == Some(true) {
                            ensure!(
                                job["with"].get(name).is_some(),
                                "input {} is required by {local} in {filename}",
                                name
                            );
                        }
                    }
                }
            } else {
                ensure!(
                    reference
                        .rsplit_once('@')
                        .is_some_and(|(_, sha)| sha.len() == 40
                            && sha.bytes().all(|b| b.is_ascii_hexdigit())),
                    "reusable workflows must be pinned to an immutable commit"
                );
            }
        }
    }
    Ok(())
}
pub fn cli_workflow(args: &[String]) -> Result<i32> {
    if args == ["source-audit"] {
        source_audit::run()?;
        return Ok(0);
    }
    if let Some(code) = automation::cli(args)? {
        return Ok(code);
    }
    let root = crate::distribution::repository_root()?;
    let mut files = fs::read_dir(root.join(".github/workflows"))?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    files.retain(|p| p.extension().is_some_and(|e| e == "yml" || e == "yaml"));
    files.sort();
    ensure!(!files.is_empty(), "no workflows found");
    let dockerfile = root.join("skills/revayat-scientific/assets/Dockerfile.tex");
    if dockerfile.try_exists()? {
        ensure!(
            !crate::identity::is_link(&dockerfile)?
                && fs::metadata(&dockerfile)?.len() <= 1024 * 1024,
            "Dockerfile must be a plain file of at most 1 MiB"
        );
        validate_docker_invocations(&fs::read_to_string(dockerfile)?)?;
    }
    let mut failed = false;
    for path in files {
        ensure!(
            !crate::identity::is_link(&path)? && fs::metadata(&path)?.len() <= 1024 * 1024,
            "workflow must be a plain file of at most 1 MiB"
        );
        let filename = path
            .strip_prefix(&root)?
            .to_string_lossy()
            .replace('\\', "/");
        let source = actionlint_source(&filename, &fs::read_to_string(&path)?)?;
        validate_workflow_contract(&root, &filename, &source)?;
        let output = lint_one(&root, &filename, &source)?;
        print!("{}", output.stdout_text());
        eprint!("{}", output.stderr_text());
        failed |= !output.success();
    }
    Ok(i32::from(failed))
}
pub fn lint_spec(root: &Path, filename: &str) -> CommandSpec {
    let mut spec = CommandSpec::new("actionlint").args(["-stdin-filename", filename, "-"]);
    spec.cwd = Some(root.to_owned());
    spec.timeout = Duration::from_secs(30);
    spec
}

pub fn lint_one(
    root: &Path,
    filename: &str,
    source: &str,
) -> Result<crate::runtime::CommandOutput> {
    lint_one_with(root, filename, source, crate::runtime::run_with_input)
}

pub fn lint_one_with(
    root: &Path,
    filename: &str,
    source: &str,
    runner: impl FnOnce(&CommandSpec, &[u8]) -> Result<crate::runtime::CommandOutput>,
) -> Result<crate::runtime::CommandOutput> {
    let translated = actionlint_source(filename, source)?;
    runner(&lint_spec(root, filename), translated.as_bytes())
}

pub fn cli_sha(args: &[String]) -> Result<i32> {
    if args == ["--ci-base"] {
        let root = crate::distribution::repository_root()?;
        let base = automation::base_from_environment(&root)?;
        automation::github_output(&base)?;
        return Ok(0);
    }
    ensure!(args.len() == 1, "check-sha requires one full commit SHA");
    require_sha(&args[0])?;
    Ok(0)
}

fn require_sha(value: &str) -> Result<()> {
    ensure!(
        value.len() == 40
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "dependency review requires a full base commit SHA"
    );
    Ok(())
}
