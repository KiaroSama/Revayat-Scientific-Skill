//! Finite authored security admissions shared by the isolated worker and tests.
use crate::{
    build, docx,
    html::ParsedHtml,
    identity, lint, publication, render,
    resource::ResourcePolicy,
    runtime::{self, CommandSpec},
    tex_container::{self, RuntimeConfig},
    text_order,
};
use anyhow::{Context, Result, bail, ensure};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
use zip::{ZipWriter, write::SimpleFileOptions};
#[path = "security_case_names.rs"]
mod names;
pub use names::CASE_NAMES;
pub const IDS: &[&str] = &[
    "docx/restricted-rels-_rels",
    "docx/restricted-RELS-_rels",
    "docx/restricted-rels-_RELS",
    "docx/restricted-ReLs-_ReLs",
    "docx/ordinary-external-False",
    "docx/ordinary-external-True",
    "html/ordinary-nesting",
    "html/ordinary-lint",
    "html/ordinary-guard",
    "html/ordinary-assets",
    "html/ordinary-render-entry-ordering",
    "html/depth/parser",
    "html/depth/source",
    "html/depth/guard",
    "html/depth/assets",
    "html/depth/text-order",
    "html/depth/resource-policy",
    "html/depth/render-entry",
    "html/depth/lint",
    "html/nodes/parser",
    "html/nodes/source",
    "html/nodes/guard",
    "html/nodes/assets",
    "html/nodes/text-order",
    "html/nodes/resource-policy",
    "html/nodes/render-entry",
    "html/nodes/lint",
    "publication/portable-reparse-metadata",
    "publication/ordinary-publication",
    "publication/protected-hardlink",
    "tex-output/production-run-arguments-evaluated",
    "tex-output/production-rw-output-bind",
    "tex-output/production-per-file-not-aggregate",
    "tex-output/real-xelatex-no-shell",
    "tex-output/two-permitted-output-files",
    "tex-output/ordinary-pdf",
];
pub struct Cases {
    root: PathBuf,
    lint_program: PathBuf,
    worker_lint: bool,
    tex_output: Option<PathBuf>,
}
impl Cases {
    pub fn new(root: &Path, lint_program: &Path, worker_lint: bool) -> Result<Self> {
        ensure!(
            root.is_dir() && lint_program.is_file(),
            "security fixtures and native lint executable are required"
        );
        Ok(Self {
            root: root.canonicalize()?,
            lint_program: lint_program.canonicalize()?,
            worker_lint,
            tex_output: None,
        })
    }
    pub fn run(&mut self, id: &str) -> Result<()> {
        ensure!(IDS.contains(&id), "unknown fixed security admission");
        if let Some(label) = id.strip_prefix("docx/") {
            self.docx(label)
        } else if let Some(label) = id.strip_prefix("html/") {
            self.html(label)
        } else if let Some(label) = id.strip_prefix("publication/") {
            self.publication(label)
        } else {
            self.tex_output(
                id.strip_prefix("tex-output/")
                    .context("invalid security case")?,
            )
        }
    }
    fn docx(&self, label: &str) -> Result<()> {
        let source = self.root.join(format!("{label}.docx"));
        let destination = self.root.join("previous.docx");
        let restricted = label.starts_with("restricted-");
        let (suffix, directory) = match label {
            "restricted-RELS-_rels" => ("RELS", "_rels"),
            "restricted-rels-_RELS" => ("rels", "_RELS"),
            "restricted-ReLs-_ReLs" => ("ReLs", "_ReLs"),
            _ => ("rels", "_rels"),
        };
        package(
            &source,
            suffix,
            directory,
            restricted,
            label.ends_with("True"),
        )?;
        let original = fs::read(&source)?;
        fs::write(&destination, b"previous valid sentinel")?;
        let patches =
            json!([{"part":"word/document.xml","index":0,"expected":"original","text":"changed"}]);
        let result = docx::edit_package(&source, &destination, &patches, &[]);
        if restricted {
            ensure!(
                result.is_err(),
                "restricted relationship identity was accepted"
            );
            ensure!(
                fs::read(&destination)? == b"previous valid sentinel",
                "restricted edit changed delivery"
            );
        } else {
            result?;
            let report = docx::inspect_package(&destination)?;
            ensure!(
                report["text_nodes"]
                    .as_array()
                    .context("missing text inventory")?
                    .iter()
                    .any(|node| node["part"] == "word/document.xml"
                        && node["index"] == 0
                        && node["text"] == "changed"),
                "ordinary relationship edit was not retained"
            );
        }
        ensure!(
            fs::read(source)? == original,
            "DOCX admission changed source"
        );
        Ok(())
    }
    fn html(&self, label: &str) -> Result<()> {
        let (kind, operation) = if let Some(operation) = label.strip_prefix("depth/") {
            ("depth", operation)
        } else if let Some(operation) = label.strip_prefix("nodes/") {
            ("nodes", operation)
        } else {
            ("good", label)
        };
        let body = match kind {
            "depth" => format!("{}متن علمی{}", "<span>".repeat(513), "</span>".repeat(513)),
            "nodes" => format!("{}متن علمی", "<br>".repeat(100001)),
            _ => format!("{}متن علمی{}", "<span>".repeat(32), "</span>".repeat(32)),
        };
        let text = format!(
            "<!doctype html><html lang=\"fa\" dir=\"rtl\"><head><meta charset=\"utf-8\"></head><body>{body}</body></html>"
        );
        let source = self.root.join(format!("{kind}.html"));
        fs::write(&source, &text)?;
        let result = match operation {
            "parser" => ParsedHtml::parse(&text).map(|_| ()),
            "source" => lint::Source::load(&source).map(|_| ()),
            "guard" | "ordinary-guard" => {
                build::document_inputs(&source, &[], None).and_then(|inputs| {
                    if kind == "good" {
                        ensure!(
                            inputs == [source.canonicalize()?],
                            "ordinary guard inputs changed"
                        );
                    }
                    Ok(())
                })
            }
            "assets" | "ordinary-assets" => assets(&source).and_then(|assets| {
                if kind == "good" {
                    ensure!(assets.is_empty(), "ordinary source manufactured assets");
                }
                Ok(())
            }),
            "text-order" => text_order::source_plain(&source).map(|_| ()),
            "resource-policy" => ResourcePolicy::new(&source).map(|_| ()),
            "render-entry" | "ordinary-render-entry-ordering" => {
                self.render_admission(&source, kind != "good")
            }
            "lint" | "ordinary-lint" => self.lint_admission(&source, kind != "good"),
            "ordinary-nesting" => {
                ensure!(
                    !ParsedHtml::parse(&text)?.text_content().is_empty(),
                    "ordinary parser lost prose"
                );
                let lint::Source::Html(model) = lint::Source::load(&source)? else {
                    bail!("wrong source model")
                };
                ensure!(
                    !model.html.text_content().is_empty(),
                    "ordinary source lost prose"
                );
                ensure!(
                    ResourcePolicy::new(&source)?.source_bytes == text.as_bytes(),
                    "resource source snapshot changed"
                );
                ensure!(
                    !text_order::source_plain(&source)?.is_empty(),
                    "ordinary source text lost"
                );
                Ok(())
            }
            _ => bail!("unknown HTML admission"),
        };
        ensure!(
            fs::read(&source)? == text.as_bytes(),
            "HTML admission changed source"
        );
        if kind == "good" || matches!(operation, "lint" | "render-entry") {
            result
        } else {
            refusal(result, "HTML work budget")
        }
    }
    fn lint_admission(&self, source: &Path, rejected: bool) -> Result<()> {
        let mut command = CommandSpec::new(&self.lint_program).args([if self.worker_lint {
            "--lint-admission"
        } else {
            "lint"
        }]);
        command.args.push(source.as_os_str().to_owned());
        command.cwd = Some(self.root.clone());
        command.timeout = Duration::from_secs(8);
        command.max_output = 65536;
        let output = runtime::run(&command)?;
        ensure!(
            output.stdout.len() + output.stderr.len() <= 65536,
            "lint diagnostic bound exceeded"
        );
        if rejected {
            ensure!(
                output.code == 2
                    && String::from_utf8_lossy(&output.stderr).contains("HTML work budget"),
                "missing public lint work-budget refusal"
            );
        } else {
            ensure!(output.code == 0, "ordinary public lint failed");
        }
        Ok(())
    }
    fn render_admission(&self, source: &Path, rejected: bool) -> Result<()> {
        let output = self.root.join("render.pdf");
        fs::write(&output, b"previous render sentinel")?;
        let original = fs::read(source)?;
        let sidecar = output.with_extension("resources.json");
        let mut called = 0;
        let result = render::render_html_with(source, &output, None, |_, _| {
            called += 1;
            bail!("accepted-admission-backend-reached")
        });
        ensure!(
            fs::read(source)? == original && fs::read(&output)? == b"previous render sentinel",
            "render admission changed protected bytes"
        );
        ensure!(
            !sidecar.exists(),
            "render admission published resource sidecar"
        );
        if rejected {
            ensure!(called == 0, "rejected source reached renderer");
            refusal(result, "HTML work budget")
        } else {
            ensure!(
                called == 1,
                "ordinary render entry did not reach backend exactly once"
            );
            refusal(result, "accepted-admission-backend-reached")
        }
    }
    fn publication(&self, label: &str) -> Result<()> {
        let destination = self.root.join("result.pdf");
        let candidate = self.root.join("candidate.pdf");
        fs::write(&candidate, b"valid candidate")?;
        match label {
            "portable-reparse-metadata" => {
                let target = self.root.join("reparse-target");
                fs::create_dir_all(&target)?;
                let link = self.root.join("reparse-link");
                #[cfg(unix)]
                std::os::unix::fs::symlink(&target, &link)?;
                ensure!(
                    identity::is_link(&link)?,
                    "native reparse ancestry fixture is unavailable"
                );
                ensure!(
                    publication::validate_destination(&link.join("result.pdf"), &[]).is_err(),
                    "linked ancestry admitted"
                );
                ensure!(
                    fs::read(candidate)? == b"valid candidate",
                    "reparse refusal changed candidate"
                );
                Ok(())
            }
            "ordinary-publication" => {
                publication::publish_files(&[(candidate, destination.clone())], &[], None)?;
                ensure!(
                    fs::read(destination)? == b"valid candidate",
                    "ordinary publication failed"
                );
                Ok(())
            }
            "protected-hardlink" => {
                fs::write(&destination, b"approved")?;
                let alias = self.root.join("alias.pdf");
                fs::hard_link(&destination, &alias)?;
                ensure!(
                    publication::validate_destination(&alias, std::slice::from_ref(&destination))
                        .is_err(),
                    "protected hardlink admitted"
                );
                ensure!(
                    fs::read(destination)? == b"approved",
                    "alias refusal changed source"
                );
                Ok(())
            }
            _ => bail!("unknown publication admission"),
        }
    }
    fn tex_output(&mut self, label: &str) -> Result<()> {
        if label.starts_with("production-") {
            return production_options(&self.root, label);
        }
        if self.tex_output.is_none() {
            self.tex_output = Some(produce_tex(&self.root)?);
        }
        let output = self.tex_output.as_ref().context("missing TeX output")?;
        match label {
            "real-xelatex-no-shell" => ensure!(
                output.join("document.pdf").metadata()?.len() > 0,
                "XeLaTeX produced no output"
            ),
            "two-permitted-output-files" => {
                for (name, expected) in [
                    ("public-one.txt", "public harmless first"),
                    ("public-two.txt", "public harmless second"),
                ] {
                    let path = output.join(name);
                    ensure!(
                        fs::read_to_string(&path)?.trim() == expected
                            && path.metadata()?.len() < 1024,
                        "harmless TeX openout control changed"
                    );
                }
            }
            "ordinary-pdf" => crate::pdf::validate_pdf(&output.join("document.pdf"))?,
            _ => bail!("unknown TeX output admission"),
        }
        let sum = fs::read_dir(output)?.try_fold(0u64, |sum, entry| -> Result<u64> {
            Ok(sum + entry?.metadata()?.len())
        })?;
        ensure!(
            sum < 1024 * 1024,
            "harmless producer exceeded small control budget"
        );
        Ok(())
    }
}
fn refusal(result: Result<()>, diagnostic: &str) -> Result<()> {
    let error = result.err().context("unsafe admission was accepted")?;
    ensure!(
        format!("{error:#}").contains(diagnostic),
        "admission refused for an unrelated reason"
    );
    Ok(())
}
fn assets(source: &Path) -> Result<Vec<PathBuf>> {
    lint::Source::load(source)?
        .image_references()
        .into_iter()
        .map(|(_, reference)| build::resolve_asset(source, &reference))
        .collect()
}
fn package(
    path: &Path,
    suffix: &str,
    directory: &str,
    restricted: bool,
    external: bool,
) -> Result<()> {
    const C: &str = "http://schemas.openxmlformats.org/package/2006/content-types";
    const P: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
    const W: &str = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
    const R: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
    let relation = format!("word/{directory}/document.xml.{suffix}");
    let kind = if restricted { "aFChunk" } else { "hyperlink" };
    let mode = if external {
        " TargetMode=\"External\""
    } else {
        ""
    };
    let target = if external {
        "https://example.invalid/public"
    } else {
        "fragment.html"
    };
    let members = [
        (
            "[Content_Types].xml".into(),
            format!(
                "<Types xmlns=\"{C}\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/><Override PartName=\"/{relation}\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Override PartName=\"/word/fragment.html\" ContentType=\"text/html\"/></Types>"
            ),
        ),
        (
            "_rels/.rels".into(),
            format!(
                "<Relationships xmlns=\"{P}\"><Relationship Id=\"rId1\" Type=\"{R}/officeDocument\" Target=\"word/document.xml\"/></Relationships>"
            ),
        ),
        (
            "word/document.xml".into(),
            format!(
                "<w:document xmlns:w=\"{W}\" xmlns:r=\"{R}\"><w:body><w:p><w:r><w:t>original</w:t></w:r></w:p>{}</w:body></w:document>",
                if restricted {
                    "<w:altChunk r:id=\"rId2\"/>"
                } else {
                    ""
                }
            ),
        ),
        (
            relation,
            format!(
                "<Relationships xmlns=\"{P}\"><Relationship Id=\"rId2\" Type=\"{R}/{kind}\" Target=\"{target}\"{mode}/></Relationships>"
            ),
        ),
        (
            "word/fragment.html".into(),
            "<html><body><p>public harmless alternate text</p></body></html>".into(),
        ),
    ];
    let mut archive = ZipWriter::new(File::create(path)?);
    for (name, text) in members {
        archive.start_file(name, SimpleFileOptions::default())?;
        archive.write_all(text.as_bytes())?;
    }
    archive.finish()?;
    Ok(())
}
fn production_options(root: &Path, label: &str) -> Result<()> {
    let config = RuntimeConfig {
        base: vec![
            "/usr/bin/docker".into(),
            "--host".into(),
            "unix:///var/run/docker.sock".into(),
        ],
        kind: "docker".into(),
        image: format!("sha256:{}", "0".repeat(64)),
    };
    let args = tex_container::run_arguments(
        &config,
        root,
        "probe.tex",
        "0123456789abcdef0123456789abcdef",
    )?;
    let values = |flag: &str| {
        args.windows(2)
            .filter(|pair| pair[0] == flag)
            .map(|pair| pair[1].clone())
            .collect::<Vec<_>>()
    };
    match label {
        "production-run-arguments-evaluated" => {
            ensure!(
                args.contains(&"--read-only".into()) && args.contains(&"--network=none".into()),
                "production isolation flags changed"
            );
            ensure!(
                values("--env").first() == Some(&"HOME=/tmp/tex-home".into())
                    && args.contains(&"TEXMFOUTPUT=/output".into()),
                "production environment arrangement changed"
            );
        }
        "production-rw-output-bind" => {
            let mounts = values("--mount")
                .into_iter()
                .map(|raw| -> Result<BTreeMap<String, String>> {
                    let fields = csv::ReaderBuilder::new()
                        .has_headers(false)
                        .from_reader(raw.as_bytes())
                        .records()
                        .next()
                        .context("missing mount")??;
                    Ok(fields
                        .iter()
                        .map(|field| {
                            let (k, v) = field.split_once('=').unwrap_or((field, ""));
                            (k.into(), v.into())
                        })
                        .collect())
                })
                .collect::<Result<Vec<_>>>()?;
            ensure!(
                mounts
                    == [
                        BTreeMap::from([
                            ("type".into(), "bind".into()),
                            ("src".into(), root.join("input").display().to_string()),
                            ("dst".into(), "/input".into()),
                            ("readonly".into(), "".into())
                        ]),
                        BTreeMap::from([
                            ("type".into(), "bind".into()),
                            ("src".into(), root.join("output").display().to_string()),
                            ("dst".into(), "/output".into())
                        ])
                    ],
                "production mount arrangement changed"
            );
        }
        "production-per-file-not-aggregate" => ensure!(
            values("--ulimit").contains(&"fsize=268435456:268435456".into())
                && values("--tmpfs") == ["/tmp:rw,noexec,nosuid,nodev,size=268435456"]
                && !args.contains(&"--storage-opt".into()),
            "production per-file versus aggregate quota arrangement changed"
        ),
        _ => bail!("unknown production option admission"),
    }
    Ok(())
}
fn produce_tex(root: &Path) -> Result<PathBuf> {
    let incoming = root.join("input");
    let outgoing = root.join("output");
    fs::create_dir_all(&incoming)?;
    fs::create_dir_all(&outgoing)?;
    let source = incoming.join("probe.tex");
    fs::write(
        &source,
        r"\documentclass{article}
\newwrite\probe
\begin{document}
\immediate\openout\probe=public-one.txt
\immediate\write\probe{public harmless first}
\immediate\closeout\probe
\immediate\openout\probe=public-two.txt
\immediate\write\probe{public harmless second}
\immediate\closeout\probe
Ordinary scientific document.
\end{document}",
    )?;
    let mut command = CommandSpec::new("xelatex").args([
        "-no-shell-escape",
        "-interaction=nonstopmode",
        "-halt-on-error",
        "-file-line-error",
        "-jobname=document",
    ]);
    command
        .args
        .push(format!("-output-directory={}", outgoing.display()).into());
    command.args.push(source.into_os_string());
    for name in ["home", "tmp", "cache"] {
        fs::create_dir_all(root.join(name))?;
    }
    for (name, path) in [
        ("HOME", "home"),
        ("TMPDIR", "tmp"),
        ("XDG_CACHE_HOME", "cache"),
    ] {
        command
            .env
            .insert(name.into(), root.join(path).into_os_string());
    }
    command.cwd = Some(incoming);
    command.timeout = Duration::from_secs(15);
    command.max_output = 65536;
    ensure!(
        runtime::run(&command)?.success(),
        "harmless XeLaTeX producer failed"
    );
    Ok(outgoing)
}
