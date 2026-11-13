use revayat_scientific::{
    ci_tools as c,
    runtime::{self, CommandSpec},
};
use std::{fs, path::Path, time::Duration};

fn bounded(mut spec: CommandSpec) -> runtime::CommandOutput {
    spec.timeout = Duration::from_secs(30);
    spec.max_output = 1024 * 1024;
    runtime::run(&spec).unwrap()
}

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
}

#[test]
fn workflows_reject_shell_programs_and_ignored_required_failures() {
    gitleaks_contract_and_actual_git_child();
    let filename = ".github/workflows/gitleaks.yml";
    let gitleaks = fs::read_to_string(root().join(filename)).unwrap();
    c::validate_workflow_contract(root(), filename, &gitleaks).unwrap();
    assert!(!gitleaks.contains("python"));
    assert!(gitleaks.contains("runner.debug == '1'"));
    assert!(gitleaks.contains("/usr/bin/test 1 = 0"));
    assert!(gitleaks.contains("check-workflows gitleaks"));
    assert!(gitleaks.contains("fetch-depth: 0"));
    assert!(gitleaks.contains("persist-credentials: false"));
    for program in [
        "echo ignored || true",
        "cargo test && echo done",
        "sh -c 'cargo test'",
        "pwsh -Command cargo",
        "python -c pass",
        "curl https://example.com | sh",
        "cargo test; echo done",
        "cargo test $(echo injected)",
        "cargo test `echo injected`",
        "echo test > result",
        "echo done # ignored failure",
        "cargo --config target.x.runner=python test",
        "cargo test --config=runner",
        "cargo test $SHELL",
        // The default Windows shell appends only the final native LASTEXITCODE.
        "cargo test\ncargo fmt",
    ] {
        let source = format!(
            "name: invalid\non: workflow_dispatch\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: {program:?}\n"
        );
        assert!(c::validate_workflow_contract(root(), "broken.yml", &source).is_err());
    }
    for property in [
        "continue-on-error: true",
        "continue-on-error: '${{ true }}'",
        "shell: python {0}",
    ] {
        let source = format!(
            "name: invalid\non: workflow_dispatch\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - {property}\n        run: cargo test\n"
        );
        assert!(c::validate_workflow_contract(root(), "broken.yml", &source).is_err());
    }
}

fn gitleaks_contract_and_actual_git_child() {
    use sha2::{Digest, Sha256};
    let event = serde_json::json!({"pull_request":{"base":{"sha":"a".repeat(40)},"head":{"sha":"b".repeat(40)}}});
    let (options, scope, revisions) =
        c::gitleaks_log_options("pull_request", Some(&event)).unwrap();
    assert!(options.ends_with(&format!(" {}..{}", "a".repeat(40), "b".repeat(40))));
    assert!(!options.contains("--all"));
    assert_eq!(revisions.len(), 2);
    for event in ["push", "schedule", "workflow_dispatch"] {
        let (options, _, revisions) = c::gitleaks_log_options(event, None).unwrap();
        assert!(
            options.ends_with(" --all")
                && options.contains("--no-ext-diff --no-textconv --ignore-submodules=all -m")
        );
        assert!(revisions.is_empty());
    }
    assert!(c::gitleaks_log_options("pull_request", None).is_err());
    assert!(c::gitleaks_log_options("workflow_run", None).is_err());
    let report = serde_json::to_vec(&serde_json::json!([{"RuleID":"generic-api-key","File":"a|<b>\nfile.txt","StartLine":2,"Commit":"a".repeat(40),"Secret":"PRIVATE_SCAN_CANARY","Match":"PRIVATE_SCAN_CANARY","Message":"PRIVATE_SCAN_CANARY"}])).unwrap();
    let locations = c::gitleaks_locations(2, b"", b"", &report).unwrap();
    let summary = c::gitleaks_summary(&locations, scope).unwrap();
    assert!(summary.contains("a&#124;&lt;b&gt; file.txt"));
    assert!(!summary.contains("PRIVATE_SCAN_CANARY"));
    assert!(
        summary.contains(
            "full history describes revision coverage"
                .replacen('f', "F", 1)
                .as_str()
        )
    );
    assert!(
        c::gitleaks_locations(0, b"", b"", b"[]")
            .unwrap()
            .is_empty()
    );
    for (code, stdout, stderr, bytes) in [
        (0, b"".as_slice(), b"".as_slice(), report.as_slice()),
        (2, b"".as_slice(), b"".as_slice(), b"[]".as_slice()),
        (1, b"".as_slice(), b"".as_slice(), b"[]".as_slice()),
        (
            0,
            b"PRIVATE_SCAN_CANARY".as_slice(),
            b"".as_slice(),
            b"[]".as_slice(),
        ),
        (
            0,
            b"".as_slice(),
            b"PRIVATE_SCAN_CANARY".as_slice(),
            b"[]".as_slice(),
        ),
        (
            0,
            b"".as_slice(),
            b"".as_slice(),
            b"PRIVATE_SCAN_CANARY".as_slice(),
        ),
        (0, b"".as_slice(), b"".as_slice(), b"null".as_slice()),
    ] {
        let error = c::gitleaks_locations(code, stdout, stderr, bytes).unwrap_err();
        assert!(!format!("{error:#}").contains("PRIVATE_SCAN_CANARY"));
    }
    let root = tempfile::tempdir().unwrap();
    let repository = root.path().join("repository");
    fs::create_dir(&repository).unwrap();
    let git = runtime::executable("git").unwrap();
    let mut init = CommandSpec::new(git.as_os_str()).args(["init", "--quiet"]);
    init.cwd = Some(repository.clone());
    assert!(bounded(init).success());
    let mut commit = CommandSpec::new(git.as_os_str()).args([
        "-c",
        "user.name=Native fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "--allow-empty",
        "--no-gpg-sign",
        "--quiet",
        "-m",
        "Public native receipt fixture",
    ]);
    commit.cwd = Some(repository.clone());
    assert!(bounded(commit).success());
    let nonce = "a".repeat(32);
    for failure in [false, true] {
        let directory = root
            .path()
            .join(if failure { "failure" } else { "success" });
        fs::create_dir(&directory).unwrap();
        let wrapper = directory.join(format!("git{}", std::env::consts::EXE_SUFFIX));
        fs::copy(env!("CARGO_BIN_EXE_revayat-gitleaks-git"), &wrapper).unwrap();
        let args = vec![
            "-C".to_owned(),
            repository.to_str().unwrap().to_owned(),
            "log".into(),
            if failure {
                "--PRIVATE_GIT_OPTION_CANARY"
            } else {
                "--format=%H"
            }
            .into(),
        ];
        let mut hash = Sha256::new();
        for argument in &args {
            hash.update((argument.len() as u64).to_be_bytes());
            hash.update(argument.as_bytes());
        }
        let digest = format!("{:x}", hash.finalize());
        fs::write(directory.join("git-binding.json"), serde_json::to_vec(&serde_json::json!({"schema":1,"nonce":nonce,"real_git":git,"real_git_sha256":revayat_scientific::build::file_hash(&git).unwrap(),"history_sha256":digest})).unwrap()).unwrap();
        let output = bounded(CommandSpec::new(wrapper.as_os_str()).args(&args));
        assert_eq!(output.success(), !failure);
        assert_eq!(
            c::verify_gitleaks_history(&directory, &nonce, &digest).is_ok(),
            !failure
        );
        let receipt = fs::read_dir(&directory)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("git-history-")
            })
            .unwrap();
        let record: serde_json::Value =
            serde_json::from_slice(&fs::read(&receipt).unwrap()).unwrap();
        assert_eq!(record["completed"], true);
        assert_eq!(record["exit_code"].as_i64(), Some(i64::from(output.code)));
        assert!(c::verify_gitleaks_history(&directory, &"b".repeat(32), &digest).is_err());
        assert!(c::verify_gitleaks_history(&directory, &nonce, &"c".repeat(64)).is_err());
        fs::copy(&receipt, directory.join("git-history-contradictory.json")).unwrap();
        assert!(c::verify_gitleaks_history(&directory, &nonce, &digest).is_err());
        fs::remove_file(receipt).unwrap();
        fs::remove_file(directory.join("git-history-contradictory.json")).unwrap();
        assert!(c::verify_gitleaks_history(&directory, &nonce, &digest).is_err());
    }
}

#[test]
fn root_is_manual_only_and_children_are_reusable_only() {
    for name in ["ci", "security-ci", "codeql", "dependency-review"] {
        let filename = format!(".github/workflows/{name}.yml");
        let source = fs::read_to_string(root().join(&filename)).unwrap();
        c::validate_workflow_contract(root(), &filename, &source).unwrap();
        let expected: &[&str] = if name == "ci" {
            &["push", "pull_request", "workflow_dispatch"]
        } else {
            &["workflow_call"]
        };
        for forbidden in [
            "push",
            "pull_request",
            "schedule",
            "workflow_run",
            "pull_request_target",
        ] {
            if expected.contains(&forbidden) {
                continue;
            }
            let changed = source.replacen("on:\n", &format!("on:\n  {forbidden}:\n"), 1);
            assert_ne!(changed, source);
            assert!(c::validate_workflow_contract(root(), &filename, &changed).is_err());
        }
        for trigger in expected {
            assert!(source.contains(&format!("  {trigger}:")));
        }
    }
}

#[test]
fn ci_preserves_release_after_failure_and_requires_explicit_browser() {
    let source = fs::read_to_string(root().join(".github/workflows/ci.yml")).unwrap();
    let workflow: serde_json::Value = serde_saphyr::from_str(&source).unwrap();
    let steps = workflow["jobs"]["portable"]["steps"].as_array().unwrap();
    let release = steps
        .iter()
        .find(|step| {
            step["run"]
                .as_str()
                .is_some_and(|run| run.contains("--release --workspace --bins"))
        })
        .unwrap();
    assert_eq!(release["if"], "${{ always() && !cancelled() }}");
    assert!(
        steps
            .iter()
            .any(|step| step["run"].as_str().is_some_and(|run| {
                run.contains("--tier portable --profile release")
                    && run.contains("--output execution/portable-release.json")
            }))
    );
    assert_eq!(
        workflow["jobs"]["scientific"]["env"]["REVAYAT_BROWSER"],
        "/usr/bin/google-chrome"
    );
    assert!(source.contains("check-workflows browser-preflight"));
    for job in ["scientific", "quality"] {
        let steps = workflow["jobs"][job]["steps"].as_array().unwrap();
        let cleanup = steps
            .iter()
            .find(|step| {
                step["run"]
                    .as_str()
                    .is_some_and(|run| run.ends_with("check-workflows cleanup-actionlint"))
            })
            .unwrap();
        assert_eq!(cleanup["if"], "${{ always() }}");
    }
    assert!(!source.contains("--include-ignored"));
    assert!(source.contains("--tier scientific --profile debug --ignored"));
    assert!(!source.contains("--no-sandbox"));
}

#[test]
fn equipped_poppler_and_all_profile_reports_are_explicit_required_inputs() {
    let source = fs::read_to_string(root().join(".github/workflows/ci.yml")).unwrap();
    let workflow: serde_json::Value = serde_saphyr::from_str(&source).unwrap();
    let steps = workflow["jobs"]["portable"]["steps"].as_array().unwrap();
    for command in [
        "brew install poppler",
        "check-workflows prepare-poppler",
        "check-workflows poppler-preflight",
        "check-workflows cleanup-poppler",
    ] {
        assert!(steps.iter().any(|step| {
            step["run"]
                .as_str()
                .is_some_and(|run| run.ends_with(command))
        }));
    }
    let position = |suffix: &str| {
        steps
            .iter()
            .position(|step| {
                step["run"]
                    .as_str()
                    .is_some_and(|run| run.ends_with(suffix))
            })
            .unwrap()
    };
    let setup = position("check-workflows prepare-poppler");
    let preflight = position("check-workflows poppler-preflight");
    let cleanup = position("check-workflows cleanup-poppler");
    let windows_cases = steps
        .iter()
        .position(|step| step["name"] == "Collect Windows crop and actual rendering preservation")
        .unwrap();
    assert!(setup < preflight && preflight < windows_cases && windows_cases < cleanup);
    assert_eq!(steps[setup]["if"], "runner.os == 'Windows'");
    assert_eq!(
        steps[cleanup]["if"],
        "${{ always() && runner.os == 'Windows' }}"
    );
    for job in ["scientific", "quality"] {
        let owned = workflow["jobs"][job]["steps"].as_array().unwrap();
        let acquire = owned
            .iter()
            .position(|step| {
                step["run"]
                    .as_str()
                    .is_some_and(|run| run.ends_with("check-workflows prepare-actionlint"))
            })
            .unwrap();
        let reclaim = owned
            .iter()
            .position(|step| {
                step["run"]
                    .as_str()
                    .is_some_and(|run| run.ends_with("check-workflows cleanup-actionlint"))
            })
            .unwrap();
        assert!(acquire < reclaim);
        assert_eq!(owned[reclaim]["if"], "${{ always() }}");
    }
    let collect = steps
        .iter()
        .filter_map(|step| step["run"].as_str())
        .filter(|run| run.contains("revayat-test-runner"))
        .collect::<Vec<_>>();
    assert_eq!(collect.len(), 4); // portable debug/release plus Mac/Windows equipped conditions.
    let aggregate = workflow["jobs"]["behavior-aggregate"]["steps"]
        .as_array()
        .unwrap();
    let joined = aggregate
        .iter()
        .filter_map(|step| step["run"].as_str())
        .find(|run| run.contains("--aggregate"))
        .unwrap();
    assert_eq!(joined.matches("--report ").count(), 11);
    assert_eq!(joined.matches("--ledger ").count(), 8);
    assert_eq!(joined.matches("--event-report ").count(), 19);
    assert!(
        joined
            .contains("--event-report execution-input/execution-native-linux/coverage-debug.json")
    );
    for platform in ["ubuntu", "macos", "windows"] {
        for profile in ["debug", "release"] {
            for population in ["oracle", "engine", "runtime-preparation"] {
                assert!(joined.contains(&format!(
                    "--event-report execution-input/execution-{platform}-latest/{population}-{profile}.json"
                )));
            }
        }
    }
    assert!(joined.contains("execution-macos-latest/scientific-debug.json"));
    for census in ["upstream", "verifier", "security"] {
        let step = aggregate
            .iter()
            .find(|step| {
                step["run"]
                    .as_str()
                    .is_some_and(|run| run.contains(&format!("--census {census}")))
            })
            .unwrap();
        let run = step["run"].as_str().unwrap();
        assert_eq!(step["if"], "${{ always() }}");
        assert!(run.contains(&format!("--ledger tests/behavior/{census}.json")));
        assert_eq!(run.matches("--report ").count(), 11);
        assert!(!run.contains("--tier")); // Reuse actual reports, never execute another pass.
    }
    assert!(revayat_scientific::ci::REQUIRED_JOBS.contains(&"behavior-aggregate"));
    assert!(
        workflow["jobs"]["status-final"]["needs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|job| job == "behavior-aggregate")
    );
    let security = fs::read_to_string(root().join(".github/workflows/security-ci.yml")).unwrap();
    assert_eq!(
        security
            .matches("--tier native --profile debug --ignored")
            .count(),
        2
    );
    assert!(!security.contains("--include-ignored"));
}

#[test]
fn artifact_preparation_is_opt_in_and_never_substitutes_for_validation() {
    let source = fs::read_to_string(root().join(".github/workflows/ci.yml")).unwrap();
    let workflow: serde_json::Value = serde_saphyr::from_str(&source).unwrap();
    let input = &workflow["on"]["workflow_dispatch"]["inputs"]["prepare_artifacts"];
    // Retain this regression identity while removing the obsolete bypass mode.
    assert!(input.is_null());
    let jobs = workflow["jobs"].as_object().unwrap();
    assert!(!jobs.contains_key("prepare-artifacts"));
    for (name, job) in jobs {
        assert_eq!(
            job["if"].as_str(),
            match name.as_str() {
                "behavior-aggregate" | "status-final" => Some("${{ always() && !cancelled() }}"),
                _ => None,
            },
            "{name}"
        );
    }
    assert_eq!(workflow["permissions"]["contents"], "read");
    for required in [
        "portable",
        "scientific",
        "security",
        "codeql",
        "dependency-review",
        "quality",
    ] {
        assert!(jobs.contains_key(required));
    }
    assert!(
        jobs["quality"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step["with"]["components"] == "rust-docs")
    );
}

#[test]
fn runtime_consumers_build_the_unix_companion_before_first_use() {
    for (filename, job) in [
        ("ci", "quality"),
        ("ci", "status-pending"),
        ("ci", "status-final"),
        ("dependency-review", "review"),
    ] {
        let source =
            fs::read_to_string(root().join(format!(".github/workflows/{filename}.yml"))).unwrap();
        let workflow: serde_json::Value = serde_saphyr::from_str(&source).unwrap();
        let commands = workflow["jobs"][job]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|step| step["run"].as_str())
            .collect::<Vec<_>>();
        let build = commands
            .iter()
            .position(|run| {
                run.starts_with("cargo build --locked")
                    && (run.contains("--workspace --bins")
                        || run.contains("--bin revayat-process-owner"))
            })
            .unwrap();
        let first_consumer = commands
            .iter()
            .position(|run| run.starts_with("target/debug/"))
            .unwrap();
        assert!(build < first_consumer, "{filename}/{job}");
    }
    let source = fs::read_to_string(root().join(".github/workflows/ci.yml")).unwrap();
    let workflow: serde_json::Value = serde_saphyr::from_str(&source).unwrap();
    let steps = workflow["jobs"]["portable"]["steps"].as_array().unwrap();
    assert!(
        steps.iter().any(
            |step| step["with"]["path"].as_str().is_some_and(|paths| paths
                .lines()
                .any(|path| path == "target/release/revayat-process-owner"))
        )
    );
}

#[test]
fn source_audit_rejects_unclassified_programs_and_over_limit_rust() {
    assert_eq!(
        c::classify_source("src/tool.rs", b"fn main() {}\n").unwrap(),
        "rust"
    );
    assert_eq!(
        c::classify_source("assets/template.html", b"<p>content</p>").unwrap(),
        "document"
    );
    assert!(c::classify_source("helper.py", b"print(1)").is_err());
    assert!(c::classify_source("helper", b"#!/bin/sh\necho forbidden").is_err());
    assert!(c::classify_source("unknown.extension", b"opaque").is_err());
    assert!(c::classify_source("src/oversize.rs", "\n".repeat(800).as_bytes()).is_err());
    assert!(c::classify_source("src/invalid.rs", &[255]).is_err());
}

#[test]
fn ci_base_resolution_preserves_spaces_and_rejects_untrusted_revisions() {
    let temp = tempfile::tempdir().unwrap();
    let repository = temp.path().join("repository with spaces فارسی");
    fs::create_dir(&repository).unwrap();
    let hooks = temp.path().join("empty hooks");
    fs::create_dir(&hooks).unwrap();
    let git = |args: &[&str]| {
        let mut spec = CommandSpec::new("git")
            .args(["-c", &format!("core.hooksPath={}", hooks.display())])
            .args(args.iter().copied());
        spec.cwd = Some(repository.clone());
        for (key, value) in [
            ("GIT_CONFIG_NOSYSTEM", "1"),
            (
                "GIT_CONFIG_GLOBAL",
                if cfg!(windows) { "NUL" } else { "/dev/null" },
            ),
            ("GIT_CONFIG_COUNT", "0"),
            ("GIT_AUTHOR_NAME", "Synthetic Fixture"),
            ("GIT_COMMITTER_NAME", "Synthetic Fixture"),
            ("GIT_AUTHOR_EMAIL", c::APPROVED_EMAIL),
            ("GIT_COMMITTER_EMAIL", c::APPROVED_EMAIL),
        ] {
            spec.env.insert(key.into(), value.into());
        }
        let output = bounded(spec);
        assert!(output.success());
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    };
    git(&["init", "--quiet"]);
    git(&[
        "commit",
        "--allow-empty",
        "--quiet",
        "-m",
        "Synthetic CI base fixture",
    ]);
    let head = git(&["rev-parse", "HEAD"]);
    git(&["update-ref", "refs/remotes/origin/main", &head]);
    let destination = temp.path().join("github output");
    let check = |base: &str| {
        fs::write(&destination, b"previous=value\n").unwrap();
        let mut spec = CommandSpec::new(env!("CARGO_BIN_EXE_revayat-scientific"))
            .args(["check-sha", "--ci-base"]);
        spec.cwd = Some(repository.clone());
        for (key, value) in [
            ("REVAYAT_REPOSITORY", repository.as_os_str()),
            ("BASE_REF", std::ffi::OsStr::new(base)),
            ("HEAD_REF", std::ffi::OsStr::new(&head)),
            ("DEFAULT_BRANCH", std::ffi::OsStr::new("main")),
            ("GITHUB_OUTPUT", destination.as_os_str()),
            ("GIT_CONFIG_NOSYSTEM", std::ffi::OsStr::new("1")),
            (
                "GIT_CONFIG_GLOBAL",
                std::ffi::OsStr::new(if cfg!(windows) { "NUL" } else { "/dev/null" }),
            ),
            ("GIT_CONFIG_COUNT", std::ffi::OsStr::new("0")),
        ] {
            spec.env.insert(key.into(), value.into());
        }
        bounded(spec)
    };
    for base in [head.as_str(), "0000000000000000000000000000000000000000"] {
        assert!(check(base).success());
        assert_eq!(
            fs::read_to_string(&destination).unwrap(),
            format!("previous=value\nsha={head}\n")
        );
    }
    for base in [
        "HEAD",
        "--help",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nsha=invalid",
    ] {
        assert!(!check(base).success());
        assert_eq!(
            fs::read_to_string(&destination).unwrap(),
            "previous=value\n"
        );
    }
}

#[test]
fn explicit_missing_browser_fails_without_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let mut spec = CommandSpec::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .args(["check-workflows", "browser-preflight"]);
    spec.env.insert(
        "REVAYAT_BROWSER".into(),
        temp.path().join("missing browser").into_os_string(),
    );
    spec.cwd = Some(temp.path().to_owned());
    assert!(!bounded(spec).success());
}

#[test]
fn tex_dockerfile_has_only_direct_exec_commands() {
    let source =
        fs::read_to_string(root().join("skills/revayat-scientific/assets/Dockerfile.tex")).unwrap();
    c::validate_docker_invocations(&source).unwrap();
    for changed in [
        source.replacen("RUN [", "RUN sh -c ", 1),
        source.replace("\"rustc\"", "\"sh\", \"-c\", \"rustc\""),
    ] {
        assert_ne!(changed, source);
        assert!(c::validate_docker_invocations(&changed).is_err());
    }
    for path in ["Vazirmatn-Regular.ttf", "Vazirmatn-Bold.ttf", "pzdr.tfm"] {
        assert!(source.contains(path));
    }
}
