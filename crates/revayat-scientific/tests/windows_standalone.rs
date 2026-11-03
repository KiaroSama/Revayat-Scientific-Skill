//! Five independently registered native counterparts of windows_probe.py.
//! The workflow proves LPAC containment before running this required target.
#![cfg(windows)]
use anyhow::{Context, Result, ensure};
use revayat_scientific::{identity::file_identity, publication};
use std::{
    fs,
    io::Write,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::Command,
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

struct Apartment;
impl Apartment {
    fn initialize() -> Result<Self> {
        // SAFETY: this test thread owns the matching uninitialization below.
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.ok()?;
        Ok(Self)
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}
struct TaskString(PWSTR);
impl Drop for TaskString {
    fn drop(&mut self) {
        unsafe { CoTaskMemFree(Some(self.0.0.cast())) };
    }
}
fn allocated_text(value: PWSTR) -> Result<String> {
    let owned = TaskString(value);
    ensure!(!owned.0.is_null(), "OPC returned a null string");
    // SAFETY: OPC returns a terminated CoTaskMem string; ownership stays live.
    Ok(unsafe { owned.0.to_string() }?)
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

#[test]
fn native_opc_consumer_recognizes_case_variant_relationship_part() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("case-variant.docx");
    authored_case_package(&path)?;
    let before = file_identity(&path, None)?;
    let _apartment = Apartment::initialize()?;
    let name = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: official typed, in-process Windows OPC APIs; live UTF-16 filename
    // and an authored bounded package. No Revayat ZIP/XML reader is used here.
    unsafe {
        let factory: IOpcFactory = CoCreateInstance(&OpcFactory, None, CLSCTX_INPROC_SERVER)?;
        let stream = factory.CreateStreamOnFile(
            PCWSTR(name.as_ptr()),
            OPC_STREAM_IO_READ,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL.0,
        )?;
        let package = factory.ReadPackageFromStream(&stream, OPC_READ_DEFAULT)?;
        let parts = package.GetPartSet()?;
        let document_uri = factory.CreatePartUri(w!("/word/document.xml"))?;
        let document = parts.GetPart(&document_uri)?;
        let relationship = document
            .GetRelationshipSet()?
            .GetRelationship(w!("rIdControlled"))?;
        ensure!(
            allocated_text(relationship.GetId()?)? == "rIdControlled",
            "OPC relationship id differs"
        );
        ensure!(
            allocated_text(relationship.GetRelationshipType()?)?
                == "http://schemas.openxmlformats.org/officeDocument/2006/relationships/aFChunk",
            "OPC relationship type differs"
        );
        ensure!(
            relationship.GetTargetMode()? == OPC_URI_TARGET_MODE_INTERNAL,
            "OPC target is external"
        );
        let resolved = relationship
            .GetSourceUri()?
            .CombinePartUri(&relationship.GetTargetUri()?)?;
        ensure!(
            resolved.GetPath()? == "/word/chunk.html",
            "OPC resolved another target"
        );
        let chunk = parts.GetPart(&resolved)?.GetContentStream()?;
        let mut data = [0u8; 256];
        let mut count = 0;
        chunk
            .Read(
                data.as_mut_ptr().cast(),
                data.len() as u32,
                Some(&mut count),
            )
            .ok()?;
        ensure!(
            (count as usize) <= data.len(),
            "OPC content read exceeded supplied buffer"
        );
        ensure!(
            data[..count as usize] == *CHUNK,
            "independent OPC chunk bytes differ"
        );
        let mut eof = 1;
        chunk
            .Read(data.as_mut_ptr().cast(), 1, Some(&mut eof))
            .ok()?;
        ensure!(eof == 0, "OPC chunk had an unqualified tail");
    }
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

fn build(source: &Path, output: &Path, marker: &Path) -> Result<std::process::Output> {
    Command::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .args(["--timeout", "10", "build"])
        .arg(source)
        .arg("article")
        .args([
            "--engine",
            "chromium",
            "--browser",
            env!("CARGO_BIN_EXE_revayat-test-tool"),
            "--output-dir",
        ])
        .arg(output)
        .env("REVAYAT_TEST_BROWSER_MARKER", marker)
        .output()
        .context("launch real public build CLI")
}

#[test]
fn public_build_junction_refusal_precedes_lint_and_renderer() -> Result<()> {
    let f = Fixture::new()?;
    let marker = f.root.join("renderer-started");
    let control = Command::new(env!("CARGO_BIN_EXE_revayat-test-tool"))
        .arg("--headless")
        .env("REVAYAT_TEST_BROWSER_MARKER", &marker)
        .output()?;
    ensure!(
        control.status.code() == Some(42) && marker.is_file(),
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
        !lint.status.success() && diagnostic.contains("lint failed"),
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
        !refused.status.success()
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
