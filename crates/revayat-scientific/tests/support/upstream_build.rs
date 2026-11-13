use super::{Work, fixture};
use anyhow::{Result, bail};
use revayat_scientific::{
    build::{self, Selection},
    tex_container as tex,
};
use std::{cell::Cell, fs, path::Path};
#[path = "tex_backend.rs"]
mod backend;
fn selected(source: &Path) -> Result<Selection> {
    Ok(Selection {
        source: source.canonicalize()?,
        engine: "tex".into(),
        browser: None,
        container: Some(tex::RuntimeConfig {
            base: vec!["docker".into()],
            kind: "docker".into(),
            image: format!("sha256:{}", "a".repeat(64)),
        }),
    })
}
pub(super) fn controller_mode(mode: &str) -> Result<()> {
    let work = Work::new();
    let old = b"%PDF-1.7 stale working output\n%%EOF\n";
    fs::write(&work.working, old)?;
    let invoked = Cell::new(false);
    let produced = Cell::new(false);
    let cleaned = Cell::new(0);
    let mut backend = backend::Backend::new();
    backend.invalid = mode == "truncated";
    backend.code = if mode == "failed-valid" { 42 } else { 0 };
    let marker = work.root.join("engine-invoked");
    let error = build::cli_build_with(
        &work.args()[1..],
        |source, _, _| selected(source),
        |selection, output, record| {
            tex::compile_document_with_lifecycle(
                &selection.source,
                output,
                selection.container.clone().unwrap(),
                Some(record),
                &mut |args, _| {
                    let launch = args.iter().any(|a| a == "run");
                    let compile = args.iter().any(|a| a == "exec")
                        && args
                            .last()
                            .is_some_and(|arg| arg == "/input/.revayat-main.tex");
                    if (launch && mode == "error") || compile {
                        invoked.set(true);
                        fs::write(&marker, b"compiler invoked")?;
                        if mode == "error" {
                            bail!("fixture container failed");
                        }
                        let result = backend.execute(args, 150)?;
                        if mode != "truncated" {
                            let staged = backend.directory.join("container-output/document.pdf");
                            revayat_scientific::render::validate_pdf(&staged)?;
                            produced.set(true);
                        }
                        return Ok(result);
                    }
                    if args.iter().any(|a| a == "ps") {
                        cleaned.set(cleaned.get() + 1);
                    }
                    backend.execute(args, 150)
                },
                |_, _, _| Ok(()),
                (
                    |_: &tex::RuntimeConfig, _: &Path, _: &str| Ok(None),
                    |_: Option<&Path>| Ok(()),
                    |_: &Path, _: &str| Ok(()),
                ),
            )
        },
        |_| {},
    )
    .unwrap_err();
    assert!(invoked.get());
    assert_eq!(fs::read(&marker)?, b"compiler invoked");
    assert_eq!(cleaned.get(), 2);
    let diagnostic = format!("{error:#}");
    let expected = match mode {
        "error" => "fixture container failed",
        "failed-valid" => "exit_code=42",
        "truncated" => "truncated PDF",
        _ => unreachable!(),
    };
    assert!(diagnostic.contains(expected), "{diagnostic}");
    assert_eq!(produced.get(), mode == "failed-valid");
    assert_eq!(fs::read(&work.working)?, old);
    work.unchanged();
    assert!(!fs::read_dir(&work.root)?.any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".revayat-")
    }));
    Ok(())
}
pub(super) fn tex_ledger_gate() -> Result<()> {
    let work = Work::new();
    fs::copy(fixture("nginx-calque.tex"), &work.source)?;
    let source = fs::read(&work.source)?;
    let terms = fixture("terms-nginx.tsv");
    let terms_before = fs::read(&terms)?;
    let mut args = work.args()[1..].to_vec();
    args.extend([
        "--terms".into(),
        terms.display().to_string(),
        "--manifest".into(),
        fixture("manifest-empty.txt").display().to_string(),
    ]);
    let mut findings = Vec::new();
    let invoked = Cell::new(false);
    let marker = work.root.join("tex-engine-invoked");
    let error = build::cli_build_with(
        &args,
        |source, _, _| selected(source),
        |_, _, _| {
            invoked.set(true);
            fs::write(&marker, b"compiler invoked")?;
            Ok(())
        },
        |finding| findings.push(finding.check.clone()),
    )
    .unwrap_err();
    assert!(error.to_string().contains("lint failed"));
    assert!(findings.iter().any(|check| check == "forbidden-fa"));
    assert!(!invoked.get());
    assert!(!marker.exists());
    assert_eq!(fs::read(&work.source)?, source);
    assert_eq!(fs::read(terms)?, terms_before);
    work.unchanged();
    Ok(())
}
