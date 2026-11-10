//! Five independently registered native counterparts of windows_probe.py.
//! The workflow proves LPAC containment before running this required target.
#![cfg(windows)]
use anyhow::{Context, Result, ensure};
use revayat_scientific::{
    identity::file_identity,
    publication,
    runtime::{self, CommandOutput, CommandSpec},
};
use std::{
    fs,
    io::Write,
    os::windows::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
    time::Duration,
};
use windows::{
    Win32::{
        Storage::{
            FileSystem::FILE_ATTRIBUTE_NORMAL,
            Packaging::Opc::{
                IOpcFactory, OPC_READ_DEFAULT, OPC_STREAM_IO_READ, OPC_URI_TARGET_MODE_INTERNAL,
                OpcFactory,
            },
        },
        System::Com::{
            CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
            CoTaskMemFree, CoUninitialize,
        },
    },
    core::{PCWSTR, PWSTR, w},
};
use zip::{ZipWriter, write::SimpleFileOptions};
#[path = "support/windows_junction.rs"]
mod windows_junction;

const STAGED: &[u8] = b"new staged output";
const TARGET: &[u8] = b"approved junction target";
const OUTSIDE: &[u8] = b"approved outside linked output";
const CHUNK: &[u8] = b"<html><body>bounded independent OPC control</body></html>";

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    target: PathBuf,
    outside: PathBuf,
    stage: PathBuf,
    link: PathBuf,
}
impl Fixture {
    fn new() -> Result<Self> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().canonicalize()?;
        let target = root.join("junction-target");
        fs::create_dir(&target)?;
        let outside = root.join("separate-sentinel");
        fs::create_dir(&outside)?;
        let stage = root.join("stage.pdf");
        fs::write(&stage, STAGED)?;
        fs::write(target.join("article.pdf"), TARGET)?;
        fs::write(outside.join("article.pdf"), OUTSIDE)?;
        let link = root.join("linked-output");
        windows_junction::create(&link, &target)?;
        ensure!(
            fs::symlink_metadata(&link)?.file_attributes() & 0x400 != 0
                && fs::read_link(&link)?.canonicalize()? == target.canonicalize()?,
            "native junction target identity differs"
        );
        Ok(Self {
            _temp: temp,
            root,
            target,
            outside,
            stage,
            link,
        })
    }
    fn destination(&self) -> PathBuf {
        self.link.join("article.pdf")
    }
    fn sentinels_unchanged(&self) -> Result<()> {
        ensure!(
            fs::read(self.target.join("article.pdf"))? == TARGET,
            "junction target bytes changed"
        );
        ensure!(
            fs::read(self.outside.join("article.pdf"))? == OUTSIDE,
            "separate outside sentinel changed"
        );
        Ok(())
    }
    fn candidate_unchanged(&self) -> Result<()> {
        ensure!(
            fs::read(&self.stage)? == STAGED,
            "stage disappeared or changed"
        );
        Ok(())
    }
}

fn authored_case_package(path: &Path) -> Result<()> {
    let mut archive = ZipWriter::new(fs::File::create(path)?);
    let members:[(&str,&[u8]);5]=[
        ("[Content_Types].xml",br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="html" ContentType="text/html"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/_rels/document.xml.RELS" ContentType="application/vnd.openxmlformats-package.relationships+xml"/></Types>"#),
        ("_rels/.rels",br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"#),
        ("word/document.xml",br#"<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body><w:p><w:r><w:t>original</w:t></w:r></w:p><w:altChunk r:id="rIdControlled"/></w:body></w:document>"#),
        ("word/_rels/document.xml.RELS",br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdControlled" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/aFChunk" Target="chunk.html"/></Relationships>"#),
        ("word/chunk.html",CHUNK),
    ];
    for (name, bytes) in members {
        archive.start_file(name, SimpleFileOptions::default())?;
        archive.write_all(bytes)?;
    }
    archive.finish()?.sync_all()?;
    Ok(())
}

const OPC_CASE: &str = "native_opc_consumer_recognizes_case_variant_relationship_part";
const OPC_CHILD: &str = "REVAYAT_TEST_OPC_CHILD_PACKAGE";
const OPC_HANG: &str = "REVAYAT_TEST_OPC_CHILD_HANG";

fn opc_command(path: &Path) -> Result<CommandSpec> {
    let mut command = CommandSpec::new(std::env::current_exe()?);
    command.args = ["--exact", OPC_CASE, "--nocapture", "--quiet"]
        .into_iter()
        .map(Into::into)
        .collect();
    command
        .env
        .insert(OPC_CHILD.into(), path.as_os_str().into());
    command.env_remove.push(OPC_HANG.into());
    command.timeout = Duration::from_secs(10);
    command.max_output = 65536;
    Ok(command)
}

#[test]
fn opc_consumer_deadline_terminates_and_reaps_owned_tree() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let pid_path = temp.path().join("owned-child.pid");
    let mut command = opc_command(&pid_path)?;
    assert_eq!(command.timeout, Duration::from_secs(10));
    assert_eq!(command.args[0], "--exact");
    assert_eq!(command.args[1], OPC_CASE);
    command.env.insert(OPC_HANG.into(), "1".into());
    command.timeout = Duration::from_secs(1);
    let error = runtime::run(&command).expect_err("nonreturning consumer must time out");
    ensure!(
        error.downcast_ref::<runtime::DeadlineExceeded>().is_some(),
        "consumer did not reach its owned deadline: {error:#}"
    );
    let pid = fs::read_to_string(pid_path)?.parse::<u32>()?;
    ensure!(
        revayat_scientific::windows_security::native::process_exited(pid)?,
        "timed-out consumer left its descendant running"
    );
    temp.close()?;
    Ok(())
}

#[test]
fn native_opc_consumer_recognizes_case_variant_relationship_part() -> Result<()> {
    if let Some(path) = std::env::var_os(OPC_CHILD) {
        if std::env::var_os(OPC_HANG).is_some() {
            use std::os::windows::process::CommandExt;
            use std::process::{Command, Stdio};
            let mut child = Command::new(env!("CARGO_BIN_EXE_revayat-test-tool"))
                .arg("silent")
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .creation_flags(0x08000000)
                .spawn()?;
            fs::write(&path, child.id().to_string())?;
            child.wait()?;
            anyhow::bail!("nonreturning OPC fixture unexpectedly exited");
        }
        consume_opc(Path::new(&path))?;
        // Suppress libtest's result trailer only after the real COM consumer
        // returned and dropped every apartment/interface/string owner.
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(b"OPC_CASE_RELATIONSHIP_RECOGNIZED\n")?;
        stdout.flush()?;
        std::process::exit(0);
    }
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("case-variant.docx");
    authored_case_package(&path)?;
    let before = file_identity(&path, None)?;
    let output = runtime::run(&opc_command(&path))?;
    ensure!(
        output.success()
            && output.stdout == b"OPC_CASE_RELATIONSHIP_RECOGNIZED\n"
            && output.stderr.is_empty(),
        "independent owned OPC consumer failed"
    );
    ensure!(
        file_identity(&path, None)? == before,
        "OPC read changed its authored package"
    );
    Ok(())
}

#[test]
fn junction_destination_admission_preserves_owned_controls() -> Result<()> {
    let f = Fixture::new()?;
    let error = publication::validate_destination(&f.destination(), &[])
        .expect_err("real junction must be refused");
    ensure!(
        error.to_string().contains("links or junctions"),
        "unexpected admission refusal: {error}"
    );
    f.sentinels_unchanged()?;
    f.candidate_unchanged()
}

#[test]
fn junction_publication_refuses_and_preserves_stage_and_sentinels() -> Result<()> {
    let f = Fixture::new()?;
    let error = publication::publish_files(&[(f.stage.clone(), f.destination())], &[], Some(1024))
        .expect_err("real junction must be refused");
    ensure!(
        error.to_string().contains("links or junctions"),
        "unexpected publication refusal: {error}"
    );
    f.sentinels_unchanged()?;
    f.candidate_unchanged()
}

#[test]
fn ordinary_publication_commits_exact_bytes() -> Result<()> {
    let f = Fixture::new()?;
    let ordinary = f.root.join("ordinary.pdf");
    publication::publish_files(&[(f.stage.clone(), ordinary.clone())], &[], Some(1024))?;
    ensure!(
        fs::read(ordinary)? == STAGED,
        "ordinary publication changed bytes"
    );
    ensure!(
        !f.stage.exists(),
        "successful publication did not consume stage"
    );
    f.sentinels_unchanged()
}

fn invoke(mut command: CommandSpec, root: &Path, marker: &Path) -> Result<CommandOutput> {
    command.cwd = Some(root.to_owned());
    command.timeout = Duration::from_secs(35);
    command.max_output = 65536;
    command.env.insert(
        "REVAYAT_TEST_BROWSER_MARKER".into(),
        marker.as_os_str().to_owned(),
    );
    runtime::run(&command).context("run bounded standalone fixture child")
}

fn build(source: &Path, output: &Path, marker: &Path) -> Result<CommandOutput> {
    let mut command = CommandSpec::new(env!("CARGO_BIN_EXE_revayat-scientific")).args([
        "--timeout",
        "10",
        "build",
    ]);
    command.args.extend([
        source.as_os_str().to_owned(),
        "article".into(),
        "--engine".into(),
        "chromium".into(),
        "--browser".into(),
        env!("CARGO_BIN_EXE_revayat-test-tool").into(),
        "--output-dir".into(),
        output.as_os_str().to_owned(),
    ]);
    invoke(command, source.parent().context("source parent")?, marker)
}

#[test]
fn public_build_junction_refusal_precedes_lint_and_renderer() -> Result<()> {
    let f = Fixture::new()?;
    let marker = f.root.join("renderer-started");
    let control = invoke(
        CommandSpec::new(env!("CARGO_BIN_EXE_revayat-test-tool")).args(["--headless"]),
        &f.root,
        &marker,
    )?;
    ensure!(
        control.code == 42 && marker.is_file(),
        "fake browser marker control did not execute"
    );
    fs::remove_file(&marker)?;
    let source = f.root.join("article.html");
    fs::write(
        &source,
        "<!doctype html><html lang=\"fa\" dir=\"rtl\"><head><style>pre{white-space:pre-wrap}</style></head><body><p>كتاب در دیوار آتش</p></body></html>",
    )?;
    fs::write(f.root.join("terms.tsv"), b"en\tfa\tnote\n")?;
    fs::write(f.root.join("manifest.txt"), b"")?;
    let ordinary = f.root.join("ordinary-output");
    fs::create_dir(&ordinary)?;
    let lint = build(&source, &ordinary, &marker)?;
    let diagnostic = String::from_utf8_lossy(&lint.stderr);
    ensure!(
        !lint.success() && diagnostic.contains("lint failed"),
        "authored fixture must actually fail source lint: {diagnostic}"
    );
    ensure!(
        !marker.exists(),
        "lint control unexpectedly launched renderer"
    );
    let refused = build(&source, &f.link, &marker)?;
    ensure!(
        refused.stdout.len() + refused.stderr.len() <= 65536,
        "public diagnostics exceeded bound"
    );
    let diagnostic = String::from_utf8_lossy(&refused.stderr);
    ensure!(
        !refused.success()
            && diagnostic.contains("output path must not contain links or junctions"),
        "public CLI did not reject lexical junction: {diagnostic}"
    );
    ensure!(
        !diagnostic.contains("lint failed"),
        "lint ran before destination admission"
    );
    ensure!(
        !marker.exists(),
        "public junction refusal launched renderer"
    );
    ensure!(
        !source.with_extension("pdf").exists(),
        "public refusal created working PDF"
    );
    f.sentinels_unchanged()?;
    f.candidate_unchanged()
}
