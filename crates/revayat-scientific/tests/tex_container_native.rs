use anyhow::Result;
use revayat_scientific::{
    build::{BuildGuard, file_hash},
    tex_container::{self as tex, TexBoundary},
};
#[path = "support/tex_finalize_checks.rs"]
mod finalize_checks;
use serde_json::json;
use std::{collections::BTreeMap, fs, path::Path};
#[path = "support/tex_fixture.rs"]
mod fixture;
use fixture::{Backend, Fixture, compile, config};

#[test]
fn test_missing_tex_font_file_is_classified_without_exposing_log() -> Result<()> {
    let f = Fixture::new()?;
    fs::write(
        f.root.join("console-pass-1.log"),
        b"! I can't find file `pzdr'.\nl.9 PRIVATE_MANUSCRIPT_LINE",
    )?;
    assert_eq!(tex::failure_class(&f.root)?, "missing-resource-or-package");
    Ok(())
}
#[test]
fn test_remote_endpoint_is_rejected_before_document_access() -> Result<()> {
    for endpoint in [
        "tcp://example.com:2375",
        "ssh://user@example.com/run/podman.sock",
        "http://127.0.0.1:2375",
        "npipe:////remote/pipe/docker_engine",
    ] {
        assert!(tex::validate_endpoint(endpoint, "docker").is_err());
    }
    Ok(())
}
#[test]
fn test_surviving_owner_sweeps_receipts_after_child_timeout() -> Result<()> {
    let f = Fixture::new()?;
    let docker = f.root.join(if cfg!(windows) {
        "docker.exe"
    } else {
        "docker"
    });
    fs::copy(env!("CARGO_BIN_EXE_revayat-test-tool"), &docker)?;
    let mut command =
        revayat_scientific::runtime::CommandSpec::new(env!("CARGO_BIN_EXE_revayat-test-tool"))
            .args([
                "register-container".as_ref(),
                f.root.as_os_str(),
                docker.as_os_str(),
            ]);
    command.cwd = Some(f.root.clone());
    command.timeout = std::time::Duration::from_secs(2);
    let error = revayat_scientific::runtime::run_supervised(&command).unwrap_err();
    assert!(
        error
            .downcast_ref::<revayat_scientific::runtime::DeadlineExceeded>()
            .is_some()
    );
    assert!(f.root.join("registered").is_file());
    assert!(!f.root.join(".revayat-tex-fixture").exists());
    assert!(!f.root.join("docker-state/alive").exists());
    assert!(!fs::read_dir(&f.root)?.any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".revayat-tex-owner-")
    }));
    Ok(())
}
#[test]
fn test_endpoint_accepts_local_only_and_probe_never_pulls() -> Result<()> {
    tex::validate_endpoint("unix:///var/run/docker.sock", "docker")?;
    tex::validate_endpoint("npipe:////./pipe/docker_engine", "docker")?;
    tex::validate_endpoint("ssh://user@localhost/run/podman.sock", "podman")?;
    let f = Fixture::new()?;
    let arguments = tex::run_arguments(&config(), &f.root, "doc.tex", &"b".repeat(32))?;
    assert!(arguments.contains(&"--pull=never".into()));
    assert!(!arguments.iter().any(|a| a == "pull"));
    tex::validate_endpoint(
        "ssh://user@127.0.0.1:1234/run/user/1000/podman.sock",
        "podman",
    )?;
    let executable = f.root.join(if cfg!(windows) {
        "docker.exe"
    } else {
        "docker"
    });
    let remote = BTreeMap::from([("DOCKER_HOST".into(), "tcp://remote.example:2375".into())]);
    let mut queries = 0;
    assert!(
        tex::runtime_config_with(&executable, &remote, |_| {
            queries += 1;
            anyhow::bail!("remote endpoint must reject before query")
        })
        .is_err()
    );
    assert_eq!(queries, 0);
    let local = BTreeMap::from([
        ("DOCKER_HOST".into(), "unix:///var/run/docker.sock".into()),
        ("REVAYAT_TEX_IMAGE".into(), tex::DEFAULT_IMAGE.into()),
    ]);
    let mut commands = Vec::new();
    let resolved = tex::runtime_config_with(&executable, &local, |args| {
        commands.push(args.to_vec());
        if args.iter().any(|s| s == "info") {
            Ok(json!({"OSType":"linux","CgroupDriver":"systemd"}))
        } else {
            Ok(
                json!([{"Id":format!("sha256:{}","a".repeat(64)),"Config":{"Labels":{tex::IMAGE_LABEL:"1"}}}]),
            )
        }
    })?;
    assert_eq!(resolved.image, format!("sha256:{}", "a".repeat(64)));
    assert_eq!(commands.len(), 2);
    assert!(
        commands
            .iter()
            .all(|args| !args.iter().any(|a| a == "pull"))
    );
    Ok(())
}
#[test]
fn test_staging_selects_closure_graphics_fonts_and_refuses_outside_assets() -> Result<()> {
    let f = Fixture::new()?;
    fs::write(f.root.join("private.txt"), b"private")?;
    fs::write(f.root.join("unreferenced.png"), b"unapproved")?;
    fs::create_dir(f.root.join("chapters"))?;
    fs::create_dir(f.root.join("figures"))?;
    fs::rename(&f.child, f.root.join("chapters/one.tex"))?;
    fs::rename(&f.image, f.root.join("figures/plot.png"))?;
    fs::write(
        &f.source,
        b"\\input{chapters/one}\n\\includegraphics*[width=2cm]{figures/plot.png}",
    )?;
    let selected = tex::approved_files(&f.source)?;
    assert_eq!(
        selected
            .iter()
            .map(|(_, relative)| relative.clone())
            .collect::<std::collections::BTreeSet<_>>(),
        [
            "doc.tex",
            "chapters/one.tex",
            "figures/plot.png",
            "fonts/synthetic.ttf"
        ]
        .into_iter()
        .map(std::path::PathBuf::from)
        .collect()
    );
    let outside = tempfile::tempdir()?;
    fs::write(outside.path().join("outside.png"), b"outside sentinel")?;
    fs::write(
        &f.source,
        format!(
            "\\includegraphics{{{}}}",
            outside.path().join("outside.png").display()
        ),
    )?;
    assert!(tex::approved_files(&f.source).is_err());
    fs::write(&f.source, b"\\includegraphics{../outside.png}")?;
    assert!(tex::approved_files(&f.source).is_err());
    Ok(())
}
#[test]
fn test_mount_csv_and_resource_flags_keep_cid_host_private() -> Result<()> {
    let root = std::path::absolute(Path::new("job, Persian فارسی"))?;
    let args = tex::run_arguments(&config(), &root, "مقاله.tex", &"b".repeat(32))?;
    for flag in [
        "--pull=never",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=64",
        "--memory=1g",
        "--cpus=2",
    ] {
        assert!(args.contains(&flag.into()));
    }
    let mounts = args
        .windows(2)
        .filter(|p| p[0] == "--mount")
        .map(|p| p[1].clone())
        .collect::<Vec<_>>();
    assert_eq!(mounts.len(), 2);
    let fields = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(mounts[0].as_bytes())
        .records()
        .next()
        .unwrap()?;
    assert!(fields.iter().any(|s| s == "readonly"));
    assert!(
        fields
            .iter()
            .any(|s| s == format!("src={}", root.join("input").display()))
    );
    assert_eq!(
        args[args.iter().position(|a| a == "--cidfile").unwrap() + 1],
        root.join("container.cid").display().to_string()
    );
    assert!(args.contains(&"120s".into()));
    assert!(args.contains(&"--kill-after=5s".into()));
    assert!(!mounts.contains(&root.display().to_string()));
    let output_fields = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(mounts[1].as_bytes())
        .records()
        .next()
        .unwrap()?;
    assert!(output_fields.iter().any(|s| s == "dst=/output"));
    assert!(
        output_fields
            .iter()
            .any(|s| s == format!("src={}", root.join("output").display()))
    );
    assert!(!output_fields.iter().any(|s| s == "readonly"));
    Ok(())
}
#[test]
fn test_cleanup_removes_only_verified_run_and_detects_lost_label() -> Result<()> {
    let f = Fixture::new()?;
    fs::write(f.root.join("container.cid"), "a".repeat(64))?;
    let run = "b".repeat(32);
    let mut removed = false;
    let mut alive = true;
    tex::cleanup_with(&config(), &f.root, &run, false, &mut |args, _| {
        if args.iter().any(|s| s == "inspect") {
            return Ok((0,json!([{"Id":"a".repeat(64),"Name":format!("/revayat-tex-{run}"),"Config":{"Labels":{tex::RUN_LABEL:run}}}]).to_string()));
        }
        if args.iter().any(|s| s == "rm") {
            removed = true;
            alive = false;
        }
        Ok((0, if alive { "a".repeat(64) } else { String::new() }))
    })?;
    assert!(removed);
    let mut removed = false;
    let rejected = tex::cleanup_with(&config(), &f.root, &run, false, &mut |args, _| {
        if args.iter().any(|s| s == "rm") {
            removed = true;
        }
        if args.iter().any(|s| s == "inspect") {
            Ok((0,json!([{"Id":"a".repeat(64),"Name":format!("/revayat-tex-{run}"),"Config":{"Labels":{tex::RUN_LABEL:"another-job"}}}]).to_string()))
        } else {
            Ok((0, "a".repeat(64)))
        }
    });
    assert!(
        rejected
            .unwrap_err()
            .to_string()
            .contains("matching ownership")
    );
    assert!(!removed);
    let mut queries = 0;
    let mut removed = false;
    let lost = tex::cleanup_with(&config(), &f.root, &run, false, &mut |args, _| {
        removed |= args.iter().any(|s| s == "rm");
        queries += 1;
        Ok((
            0,
            if queries == 1 {
                String::new()
            } else {
                "a".repeat(64)
            },
        ))
    })
    .unwrap_err();
    assert!(lost.to_string().contains("ownership label"));
    assert_eq!(queries, 2);
    assert!(!removed);
    Ok(())
}
#[test]
fn test_failed_renderer_valid_pdf_timeout_and_cleanup_failure_never_publish() -> Result<()> {
    finalize_checks::primary_and_recovery()?;
    for outcome in ["nonzero", "timeout", "cleanup", "invalid"] {
        let f = Fixture::new()?;
        let mut backend = Backend::new();
        backend.code = if outcome == "nonzero" { 42 } else { 0 };
        backend.timeout = outcome == "timeout";
        backend.cleanup_fail = outcome == "cleanup";
        backend.invalid = outcome == "invalid";
        let error = compile(&f, &mut backend, None, |phase, _, directory| {
            if phase == TexBoundary::BeforeBackend {
                f.assert_copies(directory)?;
            }
            Ok(())
        })
        .unwrap_err();
        assert!(!error.to_string().contains("PRIVATE_MANUSCRIPT_LINE"));
        if outcome == "nonzero" {
            assert!(error.to_string().contains("undefined-control-sequence"));
        }
        if outcome == "timeout" {
            assert!(
                error
                    .downcast_ref::<revayat_scientific::runtime::DeadlineExceeded>()
                    .is_some()
            );
        }
        assert_eq!(backend.calls, 1);
        if outcome == "cleanup" {
            assert!(error.to_string().contains("retained evidence"));
            assert!(
                fs::read_dir(&f.root)?.any(|e| e.unwrap().path().join("recovery.json").exists())
            );
            let recovery = fs::read_dir(&f.root)?
                .filter_map(|e| e.ok())
                .map(|e| e.path().join("recovery.json"))
                .find(|p| p.is_file())
                .unwrap();
            let recovery: serde_json::Value = serde_json::from_slice(&fs::read(recovery)?)?;
            assert_eq!(recovery["status"], "cleanup_not_verified");
        } else {
            assert!(!backend.alive);
            assert_eq!(backend.cleanup_calls, 1);
            f.clean_staging()?;
        }
        f.unchanged()?;
    }
    Ok(())
}
#[test]
fn test_success_reopens_pdf_and_cleans_staging() -> Result<()> {
    let f = Fixture::new()?;
    let mut backend = Backend::new();
    let source = fs::read(&f.source)?;
    compile(&f, &mut backend, None, |phase, _, directory| {
        if phase == TexBoundary::BeforeBackend {
            f.assert_copies(directory)?;
        }
        Ok(())
    })?;
    assert!(!backend.alive);
    assert_eq!(backend.cleanup_calls, 1);
    assert_eq!(fs::read(&f.source)?, source);
    let doc = revayat_scientific::pdf::open_pdf(&f.output, false)?;
    assert_eq!(
        revayat_scientific::pdf::geometry(&doc)?[0].rect,
        [0.0, 0.0, 250.0, 360.0]
    );
    assert!(!fs::read_dir(&f.root)?.any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".revayat-tex-")
    }));
    Ok(())
}

#[test]
fn test_each_consumed_input_changed_during_render_preserves_the_previous_delivery() -> Result<()> {
    let f = Fixture::new()?;
    let mut cleanup_calls = 0;
    for path in f.originals() {
        let original = fs::read(&path)?;
        let changed = [original.clone(), b" concurrent edit".to_vec()].concat();
        let mut backend = Backend::new();
        let error = compile(&f, &mut backend, None, |phase, _, directory| {
            if phase == TexBoundary::BeforeBackend {
                f.assert_copies(directory)?;
            }
            if phase == TexBoundary::AfterBackend {
                fs::write(&path, &changed)?;
            }
            Ok(())
        })
        .unwrap_err();
        assert!(error.to_string().contains("changed"));
        assert_eq!(fs::read(&path)?, changed);
        assert!(!backend.alive);
        assert_eq!(backend.cleanup_calls, 1);
        cleanup_calls += backend.cleanup_calls;
        f.clean_staging()?;
        f.unchanged()?;
        fs::write(path, original)?;
    }
    assert_eq!(cleanup_calls, 4);
    Ok(())
}
#[test]
fn test_removed_input_after_staging_is_not_certified_as_the_current_source() -> Result<()> {
    let f = Fixture::new()?;
    let mut backend = Backend::new();
    assert!(
        compile(&f, &mut backend, None, |phase, _, _| {
            if phase == TexBoundary::AfterBackend {
                fs::remove_file(&f.child)?;
            }
            Ok(())
        })
        .is_err()
    );
    assert!(!f.child.exists());
    assert!(!backend.alive);
    assert_eq!(backend.cleanup_calls, 1);
    f.clean_staging()?;
    f.unchanged()
}
#[test]
fn test_copy_time_source_change_refuses_before_starting_the_backend() -> Result<()> {
    let f = Fixture::new()?;
    let mut backend = Backend::new();
    let error = compile(&f, &mut backend, None, |phase, original, _| {
        if phase == TexBoundary::AfterCopy && original == f.child {
            fs::write(original, b"new revision after copy")?;
        }
        Ok(())
    })
    .unwrap_err();
    assert!(error.to_string().contains("changed"));
    assert_eq!(backend.calls, 0);
    assert_eq!(backend.cleanup_calls, 0);
    assert_eq!(fs::read(&f.child)?, b"new revision after copy");
    f.clean_staging()?;
    f.unchanged()
}
#[test]
fn test_unchanged_source_and_all_copied_resources_publish_without_mutation() -> Result<()> {
    let f = Fixture::new()?;
    let before = f
        .originals()
        .into_iter()
        .map(|p| Ok((p.clone(), fs::read(&p)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut backend = Backend::new();
    compile(&f, &mut backend, None, |phase, _, directory| {
        if phase == TexBoundary::BeforeBackend {
            f.assert_copies(directory)?;
        }
        Ok(())
    })?;
    assert!(revayat_scientific::pdf::pdf_text(&f.output)?.contains("Staged revision"));
    assert_eq!(backend.cleanup_calls, 1);
    f.clean_staging()?;
    for (path, bytes) in before {
        assert_eq!(fs::read(path)?, bytes);
    }
    assert_eq!(backend.calls, 1);
    Ok(())
}
#[test]
fn test_guard_binds_sidecars_not_passed_to_the_tex_engine() -> Result<()> {
    let f = Fixture::new()?;
    let record = f.guard()?;
    let mut backend = Backend::new();
    let error = compile(&f, &mut backend, Some(&record), |phase, _, _| {
        if phase == TexBoundary::AfterBackend {
            fs::write(f.root.join("terms.tsv"), b"changed decisions")?;
        }
        Ok(())
    })
    .unwrap_err();
    assert!(error.to_string().contains("changed"));
    f.unchanged()?;
    assert!(!f.root.join("delivered.pdf").exists());
    assert_eq!(fs::read(f.root.join("terms.tsv"))?, b"changed decisions");
    assert_eq!(backend.cleanup_calls, 1);
    f.clean_staging()
}
#[test]
fn test_guard_admits_copied_font_and_seals_exact_pdf() -> Result<()> {
    let f = Fixture::new()?;
    let record = f.guard()?;
    let mut backend = Backend::new();
    compile(&f, &mut backend, Some(&record), |_, _, _| Ok(()))?;
    let guard = BuildGuard::check(&record, None)?;
    assert!(guard.inputs.contains_key(&f.font));
    assert_eq!(guard.rendered.get(&f.output), Some(&file_hash(&f.output)?));
    assert_eq!(guard.rendered.len(), 1);
    fs::write(&f.font, b"changedfont")?;
    assert!(BuildGuard::check(&record, None).is_err());
    Ok(())
}
#[test]
fn test_tex_original_revision_is_bound_before_copy_not_after() -> Result<()> {
    let f = Fixture::new()?;
    let mut backend = Backend::new();
    let changed = b"new revision copied as baseline";
    let mut injected = false;
    let error = compile(&f, &mut backend, None, |phase, original, _| {
        if phase == TexBoundary::BeforeCopy && original == f.child {
            fs::write(original, changed)?;
            injected = true;
        }
        Ok(())
    })
    .unwrap_err();
    assert!(
        injected,
        "the checked child's BeforeCopy boundary must execute"
    );
    assert!(error.to_string().contains("bounded checked copy"));
    assert_eq!(backend.calls, 0);
    assert_eq!(backend.cleanup_calls, 0);
    assert_eq!(fs::read(&f.child)?, changed);
    f.unchanged()?;
    f.clean_staging()
}
#[test]
fn test_tex_staged_revision_mutation_is_not_certified_after_backend() -> Result<()> {
    let f = Fixture::new()?;
    let original = fs::read(&f.child)?;
    let mut backend = Backend::new();
    let mut injected = false;
    let error = compile(&f, &mut backend, None, |phase, _, directory| {
        if phase == TexBoundary::AfterBackend {
            fs::write(
                directory.join("input/child.tex"),
                b"mutated staged revision",
            )?;
            injected = true;
        }
        Ok(())
    })
    .unwrap_err();
    assert!(injected, "the AfterBackend mutation boundary must execute");
    assert!(error.to_string().contains("changed"));
    assert_eq!(backend.calls, 1);
    assert_eq!(backend.cleanup_calls, 1);
    assert!(!backend.alive);
    assert_eq!(fs::read(&f.child)?, original);
    f.unchanged()?;
    f.clean_staging()
}

#[test]
fn constant_renderer_main_preserves_utf8_braces_and_spaces_in_source_filename() -> Result<()> {
    let mut f = Fixture::new()?;
    let source = f.root.join("مقاله {draft} 1.tex");
    fs::rename(&f.source, &source)?;
    f.source = source;
    let original = fs::read(&f.source)?;
    let mut backend = Backend::new();
    compile(&f, &mut backend, None, |phase, _, directory| {
        if phase == TexBoundary::BeforeBackend {
            assert_eq!(
                fs::read(directory.join("input").join(tex::STAGED_MAIN))?,
                original
            );
        }
        Ok(())
    })?;
    assert_eq!(fs::read(&f.source)?, original);
    assert_eq!(backend.calls, 1);
    Ok(())
}

#[test]
fn a_changed_constant_renderer_copy_cannot_publish() -> Result<()> {
    let f = Fixture::new()?;
    let mut backend = Backend::new();
    assert!(
        compile(&f, &mut backend, None, |phase, _, directory| {
            if phase == TexBoundary::AfterBackend {
                fs::write(
                    directory.join("input").join(tex::STAGED_MAIN),
                    b"changed driver main",
                )?;
            }
            Ok(())
        })
        .is_err()
    );
    f.unchanged()
}

#[test]
fn reserved_renderer_filename_cannot_replace_an_approved_include() -> Result<()> {
    let f = Fixture::new()?;
    fs::write(f.root.join(tex::STAGED_MAIN), b"included source")?;
    fs::write(&f.source, format!("\\input{{{}}}", tex::STAGED_MAIN))?;
    let mut backend = Backend::new();
    assert!(compile(&f, &mut backend, None, |_, _, _| Ok(())).is_err());
    assert_eq!(backend.calls, 0);
    f.unchanged()
}

#[test]
fn a_known_unenforced_daemon_is_refused_before_reading_or_staging_the_source() -> Result<()> {
    let f = Fixture::new()?;
    let state = f.root.join("daemon");
    fs::create_dir(&state)?;
    fs::write(
        state.join("info.json"),
        br#"{"OSType":"linux","CgroupDriver":"none"}"#,
    )?;
    let executable = f.root.join(if cfg!(windows) {
        "docker.exe"
    } else {
        "docker"
    });
    fs::copy(env!("CARGO_BIN_EXE_revayat-test-tool"), &executable)?;
    let mut command =
        revayat_scientific::runtime::CommandSpec::new(env!("CARGO_BIN_EXE_revayat-scientific"))
            .args([
                std::ffi::OsString::from("tex-container"),
                f.root.join("must-not-be-opened.tex").into_os_string(),
                f.output.clone().into_os_string(),
            ]);
    command.cwd = Some(f.root.clone());
    command.timeout = std::time::Duration::from_secs(20);
    command.env.extend([
        (
            "REVAYAT_CONTAINER_RUNTIME".into(),
            executable.into_os_string(),
        ),
        ("DOCKER_CONTEXT".into(), "".into()),
        (
            "DOCKER_HOST".into(),
            url::Url::from_file_path(&state)
                .unwrap()
                .to_string()
                .replacen("file:", "unix:", 1)
                .into(),
        ),
        (
            "REVAYAT_LOG_DIR".into(),
            f.root.join("logs").into_os_string(),
        ),
    ]);
    let output = revayat_scientific::runtime::run_supervised(&command)?;
    assert!(!output.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no supported cgroup driver"));
    f.unchanged()?;
    assert!(!fs::read_dir(&f.root)?.any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".revayat-tex-")
    }));
    for driver in ["none", ""] {
        assert!(
            tex::validate_runtime_information(
                &json!({"OSType":"linux","CgroupDriver":driver}),
                "docker"
            )
            .is_err()
        );
    }
    tex::validate_runtime_information(
        &json!({"OSType":"linux","CgroupDriver":"systemd"}),
        "docker",
    )?;
    assert!(tex::validate_runtime_information(&json!({"host":{"os":"linux","cgroupManager":"systemd","cgroupControllers":["cpu","pids"]}}),"podman").is_err());
    Ok(())
}
