use anyhow::{Result, bail};
use revayat_scientific::{
    build::{BuildGuard, document_inputs, file_hash},
    tex_container::{self as tex, RuntimeConfig, TexBoundary},
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
fn pdf(path: &Path) -> Result<()> {
    use lopdf::{Document, Object, Stream, dictionary};
    let mut d = Document::with_version("1.7");
    let pages = d.new_object_id();
    let stream = d.add_object(Stream::new(dictionary! {}, vec![]));
    let page=d.add_object(dictionary!{"Type"=>"Page","Parent"=>pages,"MediaBox"=>vec![Object::from(0),Object::from(0),Object::from(210),Object::from(300)],"Contents"=>stream,"Resources"=>dictionary!{}});
    d.objects.insert(
        pages,
        dictionary! {"Type"=>"Pages","Kids"=>vec![Object::Reference(page)],"Count"=>1}.into(),
    );
    let catalog = d.add_object(dictionary! {"Type"=>"Catalog","Pages"=>pages});
    d.trailer.set("Root", catalog);
    d.save(path)?;
    Ok(())
}
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    source: PathBuf,
    child: PathBuf,
    image: PathBuf,
    font: PathBuf,
    output: PathBuf,
}
impl Fixture {
    fn new() -> Result<Self> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().canonicalize()?;
        fs::create_dir(root.join("fonts"))?;
        let f = Self {
            _temp: temp,
            source: root.join("doc.tex"),
            child: root.join("child.tex"),
            image: root.join("image.png"),
            font: root.join("fonts/synthetic.ttf"),
            output: root.join("result.pdf"),
            root,
        };
        fs::write(&f.source,b"\\documentclass{article}\\begin{document}\\input{child}\\includegraphics{image.png}\\end{document}")?;
        fs::write(&f.child, b"original checked revision\n")?;
        fs::write(&f.image, b"synthetic image")?;
        fs::write(&f.font, b"synthetic font")?;
        fs::write(&f.output, b"previous approved output")?;
        Ok(f)
    }
    fn originals(&self) -> Vec<PathBuf> {
        vec![
            self.source.clone(),
            self.child.clone(),
            self.image.clone(),
            self.font.clone(),
        ]
    }
    fn unchanged(&self) -> Result<()> {
        assert_eq!(fs::read(&self.output)?, b"previous approved output");
        Ok(())
    }
    fn guard(&self) -> Result<PathBuf> {
        let terms = self.root.join("terms.tsv");
        let manifest = self.root.join("manifest.txt");
        fs::write(&terms, b"source\toutput\n")?;
        fs::write(&manifest, b"image.png\n")?;
        let path = self.root.join("build.json");
        BuildGuard::create(
            &path,
            &document_inputs(&self.source, &[terms, manifest], None)?,
            &[self.output.clone(), self.root.join("delivered.pdf")],
        )?;
        Ok(path)
    }
}
fn config() -> RuntimeConfig {
    RuntimeConfig {
        base: vec!["docker".into()],
        kind: "docker".into(),
        image: format!("sha256:{}", "a".repeat(64)),
    }
}
struct Backend {
    alive: bool,
    run: String,
    calls: usize,
    code: i32,
    invalid: bool,
    cleanup_fail: bool,
    timeout: bool,
}
impl Backend {
    fn new() -> Self {
        Self {
            alive: false,
            run: String::new(),
            calls: 0,
            code: 0,
            invalid: false,
            cleanup_fail: false,
            timeout: false,
        }
    }
    fn execute(&mut self, args: &[String], _: u64) -> Result<(i32, String)> {
        if args.iter().any(|s| s == "run") {
            self.calls += 1;
            self.alive = true;
            self.run = args[args.iter().position(|s| s == "--name").unwrap() + 1]
                .trim_start_matches("revayat-tex-")
                .into();
            let directory =
                Path::new(&args[args.iter().position(|s| s == "--cidfile").unwrap() + 1])
                    .parent()
                    .unwrap();
            fs::write(directory.join("container.cid"), "a".repeat(64))?;
            if self.timeout {
                bail!("injected renderer deadline");
            }
            let output = directory.join("output/document.pdf");
            if self.invalid {
                fs::write(output, b"%PDF-1.7\ntruncated")?;
            } else {
                pdf(&output)?;
            }
            if self.code != 0 {
                fs::write(
                    directory.join("output/console-pass-1.log"),
                    b"Undefined control sequence\nl.9 PRIVATE_MANUSCRIPT_LINE",
                )?;
            }
            return Ok((self.code, String::new()));
        }
        if args.iter().any(|s| s == "ps") {
            if self.cleanup_fail {
                bail!("daemon unavailable");
            }
            return Ok((
                0,
                if self.alive {
                    "a".repeat(64)
                } else {
                    String::new()
                },
            ));
        }
        if args.iter().any(|s| s == "inspect") {
            return Ok((0,json!([{"Id":"a".repeat(64),"Name":format!("/revayat-tex-{}",self.run),"Config":{"Labels":{tex::RUN_LABEL:self.run}}}]).to_string()));
        }
        if args.iter().any(|s| s == "rm") {
            self.alive = false;
            return Ok((0, String::new()));
        }
        bail!("unexpected fake runtime query")
    }
}
fn compile(
    f: &Fixture,
    backend: &mut Backend,
    guard: Option<&Path>,
    hook: impl FnMut(TexBoundary, &Path, &Path) -> Result<()>,
) -> Result<()> {
    tex::compile_document_observed(
        &f.source,
        &f.output,
        config(),
        guard,
        &mut |args, timeout| backend.execute(args, timeout),
        hook,
    )
}

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
    command.timeout = std::time::Duration::from_millis(250);
    assert!(revayat_scientific::runtime::run_supervised(&command).is_err());
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
    Ok(())
}
#[test]
fn test_staging_selects_closure_graphics_fonts_and_refuses_outside_assets() -> Result<()> {
    let f = Fixture::new()?;
    fs::write(f.root.join("private.txt"), b"private")?;
    fs::write(f.root.join("unreferenced.png"), b"unapproved")?;
    let selected = tex::approved_files(&f.source)?;
    assert_eq!(selected.len(), 4);
    for path in f.originals() {
        assert!(selected.iter().any(|(p, _)| p == &path));
    }
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
    assert!(args.contains(&root.join("container.cid").display().to_string()));
    assert!(args.contains(&"--kill-after=5s".into()));
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
    assert!(rejected.is_err());
    assert!(!removed);
    Ok(())
}
#[test]
fn test_failed_renderer_valid_pdf_timeout_and_cleanup_failure_never_publish() -> Result<()> {
    for outcome in ["nonzero", "timeout", "cleanup", "invalid"] {
        let f = Fixture::new()?;
        let mut backend = Backend::new();
        backend.code = if outcome == "nonzero" { 42 } else { 0 };
        backend.timeout = outcome == "timeout";
        backend.cleanup_fail = outcome == "cleanup";
        backend.invalid = outcome == "invalid";
        let error = compile(&f, &mut backend, None, |_, _, _| Ok(())).unwrap_err();
        assert!(!error.to_string().contains("PRIVATE_MANUSCRIPT_LINE"));
        if outcome == "cleanup" {
            assert!(error.to_string().contains("retained evidence"));
            assert!(
                fs::read_dir(&f.root)?.any(|e| e.unwrap().path().join("recovery.json").exists())
            );
        } else {
            assert!(!backend.alive);
        }
        f.unchanged()?;
    }
    Ok(())
}
#[test]
fn test_success_reopens_pdf_and_cleans_staging() -> Result<()> {
    let f = Fixture::new()?;
    let mut backend = Backend::new();
    compile(&f, &mut backend, None, |_, _, _| Ok(()))?;
    assert!(!backend.alive);
    let doc = revayat_scientific::pdf::open_pdf(&f.output, false)?;
    assert_eq!(
        revayat_scientific::pdf::geometry(&doc)?[0].rect,
        [0.0, 0.0, 210.0, 300.0]
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
    for path in f.originals() {
        let original = fs::read(&path)?;
        let changed = [original.clone(), b" concurrent edit".to_vec()].concat();
        let mut backend = Backend::new();
        assert!(
            compile(&f, &mut backend, None, |phase, _, _| {
                if phase == TexBoundary::AfterBackend {
                    fs::write(&path, &changed)?;
                }
                Ok(())
            })
            .is_err()
        );
        assert_eq!(fs::read(&path)?, changed);
        assert!(!backend.alive);
        f.unchanged()?;
        fs::write(path, original)?;
    }
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
    f.unchanged()
}
#[test]
fn test_copy_time_source_change_refuses_before_starting_the_backend() -> Result<()> {
    let f = Fixture::new()?;
    let mut backend = Backend::new();
    assert!(
        compile(&f, &mut backend, None, |phase, original, _| {
            if phase == TexBoundary::AfterCopy && original == f.child {
                fs::write(original, b"new revision after copy")?;
            }
            Ok(())
        })
        .is_err()
    );
    assert_eq!(backend.calls, 0);
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
    compile(&f, &mut backend, None, |_, _, _| Ok(()))?;
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
    assert!(
        compile(&f, &mut backend, Some(&record), |phase, _, _| {
            if phase == TexBoundary::AfterBackend {
                fs::write(f.root.join("terms.tsv"), b"changed decisions")?;
            }
            Ok(())
        })
        .is_err()
    );
    f.unchanged()?;
    assert!(!f.root.join("delivered.pdf").exists());
    Ok(())
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
    fs::write(&f.font, b"changedfont")?;
    assert!(BuildGuard::check(&record, None).is_err());
    Ok(())
}
#[test]
fn test_tex_original_revision_is_bound_before_copy_not_after() -> Result<()> {
    let f = Fixture::new()?;
    let mut backend = Backend::new();
    assert!(
        compile(&f, &mut backend, None, |phase, original, _| {
            if phase == TexBoundary::BeforeCopy && original == f.child {
                fs::write(original, b"new revision copied as baseline")?;
            }
            Ok(())
        })
        .is_err()
    );
    assert_eq!(backend.calls, 0);
    f.unchanged()
}
#[test]
fn test_tex_staged_revision_mutation_is_not_certified_after_backend() -> Result<()> {
    let f = Fixture::new()?;
    let mut backend = Backend::new();
    assert!(
        compile(&f, &mut backend, None, |phase, _, directory| {
            if phase == TexBoundary::AfterBackend {
                fs::write(
                    directory.join("input/child.tex"),
                    b"mutated staged revision",
                )?;
            }
            Ok(())
        })
        .is_err()
    );
    assert!(!backend.alive);
    f.unchanged()
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
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .arg("tex-container")
        .arg(f.root.join("must-not-be-opened.tex"))
        .arg(&f.output)
        .current_dir(&f.root)
        .env("REVAYAT_CONTAINER_RUNTIME", executable)
        .env("DOCKER_CONTEXT", "")
        .env(
            "DOCKER_HOST",
            url::Url::from_file_path(&state)
                .unwrap()
                .to_string()
                .replacen("file:", "unix:", 1),
        )
        .output()?;
    assert!(!output.status.success());
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
